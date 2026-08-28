// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inspection tools: look at the SHAPE of something before fetching it.
//!
//! Both tools here answer a question an agent otherwise has to answer by
//! guessing and paying for the guess. `get_call_tree` says how many legs a call
//! actually has and how each was linked, so the agent knows whether one
//! `get_dialog` is the whole story or a quarter of it. `validate_filter` says
//! whether a Filter DSL expression parses and how many dialogs it selects,
//! which is the difference between one cheap call and a page fetch that comes
//! back empty for a reason the agent cannot see.

use std::collections::{HashSet, VecDeque};

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::resolve_limit_with_cap;
use crate::output::model::DialogSummary;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `get_call_tree`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CallTreeParams {
    /// Call-ID of any leg of the call. The walk is symmetric, so naming the
    /// B-leg returns the same tree as naming the A-leg, rooted differently.
    pub call_id: String,
    /// Maximum legs to return, root included. Clamped to the server's row cap.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One leg of a call tree: a dialog, and how the walk reached it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CallTreeLeg {
    /// Call-ID of this leg.
    pub call_id: String,
    /// Hops from the root. Zero for the root itself.
    pub depth: u32,
    /// The leg this one was correlated FROM. `None` for the root.
    pub parent_call_id: Option<String>,
    /// Confidence of the edge from the parent, 0-100. `None` for the root.
    pub score: Option<u8>,
    /// Which correlation strategy matched this edge. `None` for the root.
    pub strategy: Option<String>,
    /// Whether the edge is an identifier comparison rather than a guess.
    ///
    /// `None` for the root, which was named by the caller rather than matched.
    pub identifier_match: Option<bool>,
    /// Whether the walk continued THROUGH this leg.
    ///
    /// False on a leg reached by `timing_heuristic`, and on any leg the row cap
    /// cut the walk short of. Reported rather than left implicit because the
    /// two produce the same shape — a leaf — for opposite reasons, and an agent
    /// deciding whether the tree is complete needs to tell them apart.
    pub followed: bool,
    /// The dialog itself, with its capture-derived free text fenced.
    pub dialog: DialogSummary,
}

/// Response of `get_call_tree`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CallTreeResponse {
    /// Schema version of this response shape.
    pub schema_version: u32,
    /// Call-ID the walk started from, echoed verbatim.
    pub root_call_id: String,
    /// Every leg found, ordered by depth then creation time.
    pub legs: Vec<CallTreeLeg>,
    /// Number of legs returned, root included.
    pub total_legs: usize,
    /// Deepest hop count reached.
    pub max_depth: u32,
    /// True when the row cap stopped the walk before it ran out of legs.
    pub truncated: bool,
    /// How many edges in the tree are `timing_heuristic` guesses.
    ///
    /// Zero means every link is an identifier both legs carried.
    pub heuristic_edges: usize,
    /// Total SIP messages across every leg — the size of the merged ladder the
    /// TUI's extended flow renders.
    pub total_messages: usize,
    /// Earliest leg creation time in the tree, RFC 3339.
    pub first_activity: Option<String>,
    /// Latest leg update time in the tree, RFC 3339.
    pub last_activity: Option<String>,
}

/// Parameters for `validate_filter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateFilterParams {
    /// The Filter DSL expression to compile and count, e.g.
    /// `state = Failed and rtp.mos < 3.5`. Diagnostic aliases such as
    /// `problems` expand the same way they do in `list_dialogs`.
    pub expr: String,
}

/// Response of `validate_filter`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateFilterResponse {
    /// Schema version of this response shape.
    pub schema_version: u32,
    /// The expression as submitted, echoed verbatim.
    pub expr: String,
    /// Whether the expression compiled.
    pub valid: bool,
    /// The parser's own message when it did not. `None` when it did.
    pub error: Option<String>,
    /// Dialogs the expression selects. `None` when the expression did not
    /// compile — a zero there would read as "parsed, matched nothing".
    pub total_matched: Option<usize>,
    /// Dialogs in the store the expression was run against.
    ///
    /// The denominator, and it is returned even on a parse failure: `0` matches
    /// out of `0` dialogs is an empty capture, `0` out of `4000` is an
    /// expression that selects nothing, and no single number distinguishes
    /// them.
    pub total_dialogs: usize,
}

#[tool_router(router = inspect_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Walk the whole call, not one leg of it.
    ///
    /// The TUI has had this since the `x` key: take a dialog, pull in the legs
    /// that correlate with it, and show them as one call. Nothing on the MCP
    /// surface reached it. `find_correlated` answers one hop from one Call-ID
    /// and returns bare identifiers; a carrier call crossing an SBC and a PBX
    /// is three or four dialogs deep, and reassembling it meant the agent
    /// calling `find_correlated` on each result and stitching the graph itself.
    ///
    /// # Why the walk stops at a timing guess
    ///
    /// [`CorrelationReason::strategy`] splits the seven strategies into
    /// identifier comparisons and one guess. The walk expands identifier edges
    /// transitively and treats a `timing_heuristic` match as a LEAF.
    ///
    /// Chaining guesses is not a smaller version of the same answer, it is a
    /// different answer: the timing heuristic links two INVITE dialogs that
    /// share an endpoint IP and started within the leg-correlation window, so
    /// on a proxy carrying ten calls a second every dialog is within a guess of
    /// every other. Expanded transitively that is not a call tree, it is the
    /// capture. Each such edge is still REPORTED, with `followed: false`, so an
    /// agent that wants the next hop can call `get_call_tree` again rooted
    /// there and see for itself what it is buying.
    ///
    /// [`CorrelationReason::strategy`]: crate::sip::dialog_store::CorrelationReason::strategy
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` names no dialog in the store.
    /// An unknown root is a different answer from a call with no other legs,
    /// and returning an empty tree for both would collapse them.
    #[tool(
        name = "get_call_tree",
        description = "Returns every leg of one call as a tree: the named \
                       dialog, the legs correlated to it, the legs correlated \
                       to those, each with its parent, depth, score and the \
                       strategy that matched the edge. Identifier matches are \
                       walked transitively; a timing_heuristic edge is reported \
                       with followed=false and not walked, because it is \
                       inferred from endpoint overlap and elapsed time rather \
                       than from a value both legs carry. Multi-leg is the \
                       normal case behind a B2BUA, SBC or PBX, where \
                       get_dialog returns one quarter of the call.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_call_tree(
        &self,
        Parameters(params): Parameters<CallTreeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);

        let payload = {
            let ds = self.dialog_store.read();
            let root = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;

            let mut legs = vec![CallTreeLeg {
                call_id: root.call_id.clone(),
                depth: 0,
                parent_call_id: None,
                score: None,
                strategy: None,
                identifier_match: None,
                // Overwritten below from `walked`; the root is always walked.
                followed: false,
                dialog: crate::mcp::shape::fenced_dialog_summary(root),
            }];
            let mut total_messages = root.messages.len();
            let mut first_activity = root.created_at;
            let mut last_activity = root.updated_at;

            // Seeded with the root so a leg correlating back to it — which most
            // strategies do, being symmetric — is not re-added as its own child.
            let mut seen: HashSet<String> = HashSet::from([root.call_id.clone()]);
            let mut walked: HashSet<String> = HashSet::new();
            let mut queue: VecDeque<(String, u32)> = VecDeque::from([(root.call_id.clone(), 0)]);
            let mut truncated = false;
            let mut heuristic_edges = 0usize;
            let mut max_depth = 0u32;

            while let Some((parent, depth)) = queue.pop_front() {
                walked.insert(parent.clone());
                let mut found = ds.find_correlated_scored(&parent);
                // `find_correlated_scored` sorts by score alone, so ties fall in
                // store order and two runs over the same capture can emit the
                // legs in different orders. A tree an agent diffs across polls
                // has to be stable, so the Call-ID breaks the tie.
                found.sort_by(|a, b| {
                    b.score
                        .cmp(&a.score)
                        .then_with(|| a.dialog.call_id.cmp(&b.dialog.call_id))
                });

                for r in found {
                    if !seen.insert(r.dialog.call_id.clone()) {
                        continue;
                    }
                    if legs.len() >= limit {
                        truncated = true;
                        break;
                    }
                    let (strategy, identifier_match) = r.reason.strategy();
                    if !identifier_match {
                        heuristic_edges += 1;
                    }
                    let child_depth = depth + 1;
                    max_depth = max_depth.max(child_depth);
                    total_messages += r.dialog.messages.len();
                    first_activity = first_activity.min(r.dialog.created_at);
                    last_activity = last_activity.max(r.dialog.updated_at);
                    legs.push(CallTreeLeg {
                        call_id: r.dialog.call_id.clone(),
                        depth: child_depth,
                        parent_call_id: Some(parent.clone()),
                        score: Some(r.score),
                        strategy: Some(strategy.to_string()),
                        identifier_match: Some(identifier_match),
                        followed: false,
                        dialog: crate::mcp::shape::fenced_dialog_summary(r.dialog),
                    });
                    if identifier_match {
                        queue.push_back((r.dialog.call_id.clone(), child_depth));
                    }
                }
                if truncated {
                    break;
                }
            }
            drop(ds);

            // Set from what the walk ACTUALLY visited, not from the decision to
            // enqueue: a leg still sitting in the queue when the row cap ended
            // the walk is a leaf in this answer whatever its strategy was, and
            // reporting it as followed would claim its subtree was searched.
            for leg in &mut legs {
                leg.followed = walked.contains(&leg.call_id);
            }
            legs.sort_by(|a, b| {
                a.depth
                    .cmp(&b.depth)
                    .then_with(|| a.dialog.created_at.cmp(&b.dialog.created_at))
                    .then_with(|| a.call_id.cmp(&b.call_id))
            });

            CallTreeResponse {
                schema_version: 1,
                root_call_id: params.call_id.clone(),
                total_legs: legs.len(),
                legs,
                max_depth,
                truncated,
                heuristic_edges,
                total_messages,
                first_activity: Some(first_activity.to_rfc3339()),
                last_activity: Some(last_activity.to_rfc3339()),
            }
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::json(payload)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Compile a Filter DSL expression and count what it selects, returning
    /// neither rows nor a tool failure.
    ///
    /// A malformed filter reaches every other tool as `invalid_params`, which
    /// is right there and wrong here: the whole point of this tool is to be
    /// told what is wrong with an expression, and an error response carries the
    /// message where a model is least likely to act on it. So a parse failure
    /// is a SUCCESSFUL call reporting `valid: false` with the parser's own
    /// text, and the only error this tool raises is one it did not expect.
    ///
    /// The count is the other half. `list_dialogs` already returns
    /// `total_matched`, but reaching it means paying for a page of fenced
    /// summaries; iterating on an expression — widen it, narrow it, try the
    /// other field name — costs one page per attempt, and the rows are thrown
    /// away every time.
    ///
    /// # Errors
    ///
    /// Nothing this tool raises. A `Result` is kept because the response
    /// serializer returns one.
    #[tool(
        name = "validate_filter",
        description = "Compiles a Filter DSL expression and reports whether it \
                       parsed, the parser's message when it did not, and how \
                       many dialogs it selects — with no rows returned. A \
                       malformed expression comes back as valid=false rather \
                       than as a tool error. total_dialogs is the denominator, \
                       so zero matches on an empty capture is distinguishable \
                       from zero matches on a full one.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn validate_filter(
        &self,
        Parameters(params): Parameters<ValidateFilterParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // The same compiler every other tool's `filter` goes through, alias
        // expansion included. A second parser here would validate an expression
        // that `list_dialogs` then rejects, which is worse than no tool.
        let compiled = self.compile_filter(Some(&params.expr));

        let payload = match compiled {
            Err(e) => ValidateFilterResponse {
                schema_version: 1,
                expr: params.expr.clone(),
                valid: false,
                error: Some(e.message.to_string()),
                total_matched: None,
                total_dialogs: self.dialog_store.read().len(),
            },
            Ok(expr) => {
                let (matched, total) = self.count_matching_dialogs(expr.as_ref());
                ValidateFilterResponse {
                    schema_version: 1,
                    expr: params.expr.clone(),
                    valid: true,
                    error: None,
                    total_matched: Some(matched),
                    total_dialogs: total,
                }
            }
        };

        // No untrusted-data note: this response carries the caller's own
        // expression and two integers, and nothing read off the wire.
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }
}

impl SipnabMcp {
    /// Count dialogs matching `expr`, and how many there were to match.
    ///
    /// Deliberately not `dialog_page`: that one exists to build a PAGE — it
    /// sorts, applies a cursor and projects every survivor into a fenced
    /// summary — and `validate_filter` throws all three away. What is shared is
    /// the part that has to agree, which is the predicate: the same
    /// [`FilterExpr::matches_dialog`], the same per-dialog stream slice, and
    /// the same two run-level facts (`CaptureMedia`, `MosDelay`) read once for
    /// the whole scan rather than per dialog.
    ///
    /// # Arguments
    ///
    /// * `expr` — the compiled expression, or `None` to count everything.
    ///
    /// # Returns
    ///
    /// `(matched, total)` over the whole store; no cursor, no truncation.
    ///
    /// [`FilterExpr::matches_dialog`]: crate::sip::dsl::FilterExpr::matches_dialog
    fn count_matching_dialogs(&self, expr: Option<&crate::sip::dsl::FilterExpr>) -> (usize, usize) {
        let ds = self.dialog_store.read();
        let ss = self.stream_store.read();
        let total = ds.len();
        let Some(expr) = expr else {
            return (total, total);
        };

        // Grouped once. `streams_for` walks the whole stream store per call, so
        // calling it inside a scan of every dialog is quadratic.
        let mut by_call: std::collections::HashMap<&str, Vec<&crate::rtp::stream::RtpStream>> =
            std::collections::HashMap::new();
        for s in ss.iter() {
            if let Some(id) = s.associated_dialog.as_deref() {
                by_call.entry(id).or_default().push(s);
            }
        }
        const NO_STREAMS: &[&crate::rtp::stream::RtpStream] = &[];
        let capture = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
        let delay = crate::rtp::quality::MosDelay::from_capture(&ss);

        let matched = ds
            .iter()
            .filter(|d| {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                expr.matches_dialog(d, streams, capture, delay)
            })
            .count();
        (matched, total)
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

    /// 127.0.0.1 as an `IpAddr`.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A fixed base timestamp, so every fixture is deterministic.
    fn base_ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Parse `raw` as SIP between localhost endpoints at `ts`.
    fn parse_at(raw: &[u8], ts: chrono::DateTime<chrono::Utc>) -> crate::sip::SipMessage {
        parse_sip(
            raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture parses")
    }

    /// An INVITE for `call_id` carrying one extra header, at `ts`.
    ///
    /// The Via branch is derived from the Call-ID so two fixtures never share
    /// one: a `via_branch` match would otherwise be what a `Session-ID` test is
    /// really observing.
    fn invite(
        call_id: &str,
        extra: &[&str],
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let mut headers = vec![
            format!("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{call_id}"),
            "From: Alice <sip:alice@example.com>;tag=t1".to_string(),
            "To: <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Content-Length: 0".to_string(),
        ];
        headers.extend(extra.iter().map(|h| (*h).to_string()));
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        parse_at(
            &build_sip("INVITE sip:bob@example.com SIP/2.0", &refs, b""),
            ts,
        )
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

    /// Three legs chained by `X-Call-ID`: a -> b -> c, where a and c share no
    /// header at all. One hop of `find_correlated` cannot see c from a.
    fn three_leg_chain() -> SipnabMcp {
        server_with(vec![
            invite("a@test", &[], base_ts()),
            invite(
                "b@test",
                &["X-Call-ID: a@test"],
                base_ts() + chrono::Duration::seconds(60),
            ),
            invite(
                "c@test",
                &["X-Call-ID: b@test"],
                base_ts() + chrono::Duration::seconds(120),
            ),
        ])
    }

    /// Two legs hanging off one root, an hour apart so nothing pairs them by
    /// timing. With the cap at two the walk has to abandon a leg it enqueued
    /// but never reached.
    fn one_root_two_children() -> SipnabMcp {
        server_with(vec![
            invite("root@test", &[], base_ts()),
            invite(
                "kid1@test",
                &["X-Call-ID: root@test"],
                base_ts() + chrono::Duration::seconds(60),
            ),
            invite(
                "kid2@test",
                &["X-Call-ID: root@test"],
                base_ts() + chrono::Duration::seconds(120),
            ),
        ])
    }

    // ── get_call_tree ─────────────────────────────────────────────────

    /// The whole point of the tool: the third leg is reachable only by
    /// following the second, so a one-hop answer misses it.
    #[tokio::test]
    async fn call_tree_reaches_a_leg_no_single_hop_can_see() {
        let srv = three_leg_chain();
        let v = json_of(
            &srv.get_call_tree(Parameters(CallTreeParams {
                call_id: "a@test".to_string(),
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        );

        let ids: Vec<&str> = v["legs"]
            .as_array()
            .expect("legs is an array")
            .iter()
            .filter_map(|l| l["call_id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["a@test", "b@test", "c@test"],
            "the walk must be transitive: c@test names b@test, never a@test, so \
             only a second hop reaches it: {v}"
        );
        assert_eq!(v["max_depth"], 2, "c@test sits two hops from the root: {v}");
        assert_eq!(
            v["legs"][2]["parent_call_id"], "b@test",
            "the tree has to say which leg c@test was reached FROM: {v}"
        );
        assert_eq!(
            v["legs"][2]["strategy"], "x_call_id",
            "and by which strategy: {v}"
        );
        assert_eq!(
            v["heuristic_edges"], 0,
            "every edge here is an identifier match: {v}"
        );
        assert_eq!(
            v["total_messages"], 3,
            "the merged ladder is three messages, one per leg: {v}"
        );
    }

    /// A timing-heuristic edge is REPORTED and not WALKED. Both halves matter:
    /// dropping it would hide a real link, walking it would let one busy second
    /// of traffic swallow the capture.
    #[tokio::test]
    async fn call_tree_reports_a_timing_edge_but_does_not_walk_through_it() {
        // Three INVITEs a few hundred ms apart between the same endpoints and
        // sharing nothing else — the timing heuristic's exact shape.
        let srv = server_with(vec![
            invite("t1@test", &[], base_ts()),
            invite(
                "t2@test",
                &[],
                base_ts() + chrono::Duration::milliseconds(200),
            ),
            invite(
                "t3@test",
                &[],
                base_ts() + chrono::Duration::milliseconds(400),
            ),
        ]);
        let v = json_of(
            &srv.get_call_tree(Parameters(CallTreeParams {
                call_id: "t1@test".to_string(),
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        );

        let legs = v["legs"].as_array().expect("legs is an array");
        let heuristic: Vec<&serde_json::Value> = legs
            .iter()
            .filter(|l| l["strategy"] == "timing_heuristic")
            .collect();
        assert!(
            !heuristic.is_empty(),
            "a timing-heuristic leg must still be REPORTED, or the agent never \
             learns the link was suspected: {v}"
        );
        for leg in &heuristic {
            assert_eq!(
                leg["identifier_match"], false,
                "the guess must be labeled a guess: {v}"
            );
            assert_eq!(
                leg["followed"], false,
                "the walk must stop at a guess rather than chaining guesses: {v}"
            );
            assert_eq!(
                leg["depth"], 1,
                "a leg reached by a guess is a leaf, so nothing can sit under \
                 it: {v}"
            );
        }
        assert!(
            v["heuristic_edges"].as_u64().unwrap_or(0) > 0,
            "the count of guessed edges is what tells an agent how much of this \
             tree is inference: {v}"
        );
    }

    /// The row cap bounds the answer AND says so, and a leg the cap stopped the
    /// walk short of is not reported as searched.
    #[tokio::test]
    async fn call_tree_truncates_at_the_limit_without_claiming_it_walked_further() {
        let srv = one_root_two_children();
        let v = json_of(
            &srv.get_call_tree(Parameters(CallTreeParams {
                call_id: "root@test".to_string(),
                limit: Some(2),
            }))
            .await
            .expect("the call succeeds"),
        );

        assert_eq!(v["total_legs"], 2, "the cap includes the root: {v}");
        assert_eq!(
            v["truncated"], true,
            "a cut walk must say it was cut, or the tree reads as complete: {v}"
        );
        assert_eq!(
            v["legs"][1]["identifier_match"], true,
            "kid1@test is an identifier match, so `followed` cannot simply be \
             restating the strategy: {v}"
        );
        assert_eq!(
            v["legs"][1]["followed"], false,
            "the cap ended the walk while kid1@test was still queued, so it was \
             never expanded; reporting it as followed would claim its subtree \
             was searched and came back empty: {v}"
        );
    }

    /// An unknown Call-ID is an error, not an empty tree — the two are
    /// different answers.
    #[tokio::test]
    async fn call_tree_rejects_an_unknown_call_id() {
        let srv = three_leg_chain();
        let err = srv
            .get_call_tree(Parameters(CallTreeParams {
                call_id: "nope@test".to_string(),
                limit: None,
            }))
            .await
            .expect_err("an unknown root must not return a tree");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    /// A call with no other legs still returns itself, with no edge fields set.
    #[tokio::test]
    async fn call_tree_of_a_lone_dialog_is_the_dialog() {
        let srv = server_with(vec![invite("lone@test", &[], base_ts())]);
        let v = json_of(
            &srv.get_call_tree(Parameters(CallTreeParams {
                call_id: "lone@test".to_string(),
                limit: None,
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(v["total_legs"], 1, "{v}");
        assert_eq!(v["max_depth"], 0, "{v}");
        assert!(v["legs"][0]["strategy"].is_null(), "{v}");
        assert_eq!(
            v["legs"][0]["followed"], true,
            "the root is always walked, even when the walk finds nothing: {v}"
        );
    }

    /// Capture-derived free text in the leg summaries is fenced, and the
    /// response carries the provenance note that explains the marks.
    #[tokio::test]
    async fn call_tree_fences_the_capture_text_in_its_leg_summaries() {
        let srv = three_leg_chain();
        let result = srv
            .get_call_tree(Parameters(CallTreeParams {
                call_id: "a@test".to_string(),
                limit: None,
            }))
            .await
            .expect("the call succeeds");
        let v = json_of(&result);
        assert_eq!(
            v["legs"][0]["dialog"]["from_user"],
            crate::mcp::shape::fence("alice"),
            "a From user is text the sender chose and must arrive fenced: {v}"
        );
        let note = crate::mcp::shape::untrusted_note();
        assert!(
            result
                .content
                .iter()
                .filter_map(|c| c.as_text())
                .any(|t| t.text == note),
            "a response carrying fenced text must carry the note that says what \
             the fence means"
        );
    }

    // ── validate_filter ───────────────────────────────────────────────

    /// A malformed expression is a successful call reporting the parse error,
    /// never a tool failure.
    #[tokio::test]
    async fn validate_filter_returns_the_parse_error_rather_than_failing() {
        let srv = three_leg_chain();
        let result = srv
            .validate_filter(Parameters(ValidateFilterParams {
                expr: "state = ".to_string(),
            }))
            .await
            .expect("a bad expression must NOT make the tool fail");
        let v = json_of(&result);
        assert_eq!(v["valid"], false, "{v}");
        assert!(
            v["error"].as_str().is_some_and(|e| !e.is_empty()),
            "the parser's own message is the whole product of this call: {v}"
        );
        assert!(
            v["total_matched"].is_null(),
            "a count for an expression that never compiled would read as \
             'parsed, matched nothing': {v}"
        );
        assert_eq!(
            v["total_dialogs"], 3,
            "the denominator is reported even on a parse failure: {v}"
        );
    }

    /// A valid expression is counted against the store, with no rows returned.
    #[tokio::test]
    async fn validate_filter_counts_matches_without_returning_rows() {
        let srv = three_leg_chain();
        let v = json_of(
            &srv.validate_filter(Parameters(ValidateFilterParams {
                expr: "call_id == \"b@test\"".to_string(),
            }))
            .await
            .expect("the call succeeds"),
        );
        assert_eq!(v["valid"], true, "{v}");
        assert_eq!(
            v["total_matched"], 1,
            "exactly one of the three dialogs is b@test: {v}"
        );
        assert_eq!(v["total_dialogs"], 3, "{v}");
        assert!(
            v.get("dialogs").is_none() && v.get("legs").is_none(),
            "the tool exists to avoid paying for rows; it must not return \
             any: {v}"
        );
    }

    /// Zero matches on a populated store is distinguishable from zero matches
    /// on an empty one, which is what `total_dialogs` is for.
    #[tokio::test]
    async fn validate_filter_separates_no_matches_from_no_dialogs() {
        let populated = json_of(
            &three_leg_chain()
                .validate_filter(Parameters(ValidateFilterParams {
                    expr: "call_id == \"absent@test\"".to_string(),
                }))
                .await
                .expect("the call succeeds"),
        );
        let empty = json_of(
            &server_with(Vec::new())
                .validate_filter(Parameters(ValidateFilterParams {
                    expr: "call_id == \"absent@test\"".to_string(),
                }))
                .await
                .expect("the call succeeds"),
        );

        assert_eq!(populated["total_matched"], 0, "{populated}");
        assert_eq!(empty["total_matched"], 0, "{empty}");
        assert_ne!(
            populated["total_dialogs"], empty["total_dialogs"],
            "both matched nothing; only the denominator tells an agent whether \
             the expression is wrong or the capture is empty"
        );
    }

    /// The tool compiles through the same path `list_dialogs` does, so a
    /// diagnostic alias resolves here too.
    #[tokio::test]
    async fn validate_filter_accepts_the_same_aliases_the_other_tools_take() {
        let v = json_of(
            &three_leg_chain()
                .validate_filter(Parameters(ValidateFilterParams {
                    expr: "problems".to_string(),
                }))
                .await
                .expect("the call succeeds"),
        );
        assert_eq!(
            v["valid"], true,
            "an alias `list_dialogs` accepts must not be reported as a syntax \
             error here, or the tool sends agents away from working filters: {v}"
        );
    }
}
