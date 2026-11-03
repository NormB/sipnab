// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Who is feeding this run's HEP listener, who went silent, and who it is
//! turning away.
//!
//! # Why this is a tool of its own
//!
//! The listener keeps a roster of its senders (see
//! [`crate::capture::hep_roster`]), and a collector operator's first question
//! is exactly what it answers: is proxy seven still sending, and why is the
//! new PBX not showing up? `capture_health` is the wrong home for it. That tool
//! carries integers and booleans only, a guarantee its callers rely on, and a
//! roster carries addresses.
//!
//! # What it returns, and why it needs no fence
//!
//! [`crate::output::model::HepSendersReport`], byte for byte what
//! `GET /v1/hep/senders` returns for the same roster. It holds a claimed
//! capture id, a socket address, counters and timestamps per sender — no byte
//! of any packet — so, like `runtime_stats`, it goes out without the untrusted
//! content note.
//!
//! # Only where a listener can exist
//!
//! Compiled with the `hep` feature, as the REST route is: a tool that lists
//! and can never have anything to report is one an agent plans around for
//! nothing.

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::resolve_limit_with_cap;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::Deserialize;

/// Parameters for `hep_senders`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct HepSendersParams {
    /// The most rows each list (senders, refused sources) may carry.
    /// Omitted or 0, 50: the default page. At most --mcp-max-rows. The totals
    /// always count everything.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Parameters for `th_mappings`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ThMappingsParams {
    /// Only the mapping naming this Call-ID, on either side. Use it to find
    /// why one call did not join: no row means no event named it.
    #[serde(default)]
    pub call_id: Option<String>,
    /// Only mappings in this state: conflict, pending or joined.
    #[serde(default)]
    pub state: Option<String>,
    /// The most rows to return. Omitted or 0, 50: the default page. At most
    /// --mcp-max-rows. total_matched counts every match.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[tool_router(router = hep_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// The HEP listener's sender roster.
    ///
    /// # Errors
    ///
    /// Only if the report fails to serialize, which a struct of strings and
    /// integers cannot.
    #[tool(
        name = "hep_senders",
        description = "Returns the HEP listener's sender roster: each sender \
                       keyed by the capture id it claims and the address it \
                       sent from, with its admitted packet count, first and \
                       last time heard, idle seconds and whether it has been \
                       silent for the --hep-silence-warn threshold; the \
                       addresses the listener refused, with counts by reason; \
                       refusal totals by reason; and the authentication mode \
                       the listener admits packets under. The capture id is \
                       the sender's \
                       claim, never proven, and each row says so in identity. \
                       A run with no HEP listener returns listening false and \
                       a note. Every value is sipnab's own count, a claimed \
                       id, an address or a time; no packet payload is in it. \
                       Same fields and values as GET /v1/hep/senders, plus \
                       source_exhausted and source_stopped_early.",
        output_schema = schema_for_output::<crate::output::model::HepSendersReport>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn hep_senders(
        &self,
        Parameters(params): Parameters<HepSendersParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        // The one builder `GET /v1/hep/senders` and `--hep-senders` call, over
        // the roster the listener hung on the capture meter. The report is
        // handed to the content block as the struct, as REST hands it to
        // `Json`, so both carry the same fields and values. The bytes differ:
        // the MCP block is sorted by key and dispatch adds the completeness
        // stamp (`hep_senders_carries_the_rest_fields_plus_the_stamp`).
        let report = crate::capture::hep_roster::senders_report(
            self.capture_meter.as_ref().and_then(|m| m.hep_roster()),
            limit,
        );
        Ok(CallToolResult::success(vec![ContentBlock::json(report)?]))
    }

    /// The OpenSIPS topology-hiding mappings held, one row each.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for a `state` other than `conflict`,
    /// `pending` or `joined`.
    #[tool(
        name = "th_mappings",
        description = "Lists the OpenSIPS topology-hiding mappings sipnab \
                       holds from E_SIPNAB_TH_MAP events: each one's caller-side \
                       and callee-side Call-IDs, its state (conflict, pending \
                       or joined) and whether each leg is captured, conflicts \
                       first, beside the event counts and the hidden legs by \
                       status. Pass call_id (either leg) to see why one call \
                       did not join: no row means no event named it. Same \
                       fields as GET /v1/th-mappings.",
        output_schema = schema_for_output::<crate::output::query::th_mappings::ThMappings>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn th_mappings(
        &self,
        Parameters(params): Parameters<ThMappingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let wanted = params
            .state
            .as_deref()
            .map(crate::sip::th_mapping::ThMappingState::parse)
            .transpose()
            .map_err(|e| {
                crate::mcp::errors::refuse_param(
                    crate::mcp::errors::Reason::InvalidValue,
                    "state",
                    e,
                )
            })?;
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        // The one builder `GET /v1/th-mappings` and `--th-mappings` call.
        let answer = {
            // Capture lock first, stores second, as every capture answer takes
            // them, so the identity describes the store the rows came from.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            drop(ss);
            crate::output::query::th_mappings::th_mappings(
                &ds,
                params.call_id.as_deref(),
                wanted,
                limit,
                Some(capture_identity),
            )
        };
        // The Call-IDs came off the wire, in events from a listed sender.
        Ok(CallToolResult::success(vec![
            ContentBlock::json(answer)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::*;
    use crate::capture::hep_roster::{
        HepRefusal, HepRoster, RosterState, SenderTrust, hep_source_label,
    };
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    type TestError = Box<dyn std::error::Error>;

    /// A server with no capture attached.
    fn server() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// A roster with senders 7 and 9 and one refused address, on a frozen
    /// clock.
    fn roster() -> Result<HepRoster, TestError> {
        let t = std::time::Instant::now();
        let mut state = RosterState::new(
            SenderTrust::SharedSecretHmac,
            64,
            std::time::Duration::from_secs(30),
            t,
            chrono::Utc::now(),
        );
        for (id, peer) in [(7u32, "192.0.2.7"), (9, "192.0.2.9")] {
            let peer: std::net::IpAddr = peer.parse().map_err(|e| format!("literal: {e:?}"))?;
            state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), t);
        }
        let bad: std::net::IpAddr = "203.0.113.66"
            .parse()
            .map_err(|e| format!("literal: {e:?}"))?;
        state.refused(HepRefusal::HmacBadMac, bad, t);
        Ok(HepRoster::with_clock(state, Arc::new(move || t)))
    }

    /// The JSON block of a tool result.
    fn json_of(result: &CallToolResult) -> Result<serde_json::Value, TestError> {
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .ok_or("a JSON block")?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("the payload is JSON: {e:?}"))?)
    }

    /// `th_mappings` lists the store's mappings with their state, narrows by
    /// Call-ID and state, and refuses an unknown state with the three real
    /// ones named.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn th_mappings_lists_the_held_mappings() -> Result<(), TestError> {
        use crate::sip::th_mapping::ThMapping;
        let (mut ds, caller, hidden) = crate::test_utils::th_hidden_call_store("right", None)?;
        let now = chrono::Utc::now();
        for (a, b) in [
            (caller.as_str(), hidden.as_str()),
            ("waiting@example.com", "DLGCH_waiting"),
        ] {
            ds.apply_th_mapping(
                Ok(ThMapping {
                    caller_call_id: a.into(),
                    callee_call_id: b.into(),
                }),
                now,
            );
        }
        let srv = SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        );
        let ask = |call_id: Option<&str>, state: Option<&str>| ThMappingsParams {
            call_id: call_id.map(str::to_string),
            state: state.map(str::to_string),
            limit: None,
        };
        let v = json_of(
            &srv.th_mappings(Parameters(ask(None, None)))
                .await
                .map_err(|e| format!("the call succeeds: {e:?}"))?,
        )?;
        assert_eq!(v["total_matched"], 2, "{v}");
        assert_eq!(v["mappings"][0]["state"], "pending", "{v}");
        assert_eq!(v["mappings"][1]["state"], "joined", "{v}");
        assert_eq!(v["counts"]["held"], 2, "{v}");
        assert_eq!(v["th_callid"]["mapped"], 1, "{v}");
        let v = json_of(
            &srv.th_mappings(Parameters(ask(Some(&hidden), None)))
                .await
                .map_err(|e| format!("the call succeeds: {e:?}"))?,
        )?;
        assert_eq!(v["total_matched"], 1, "{v}");
        assert_eq!(v["mappings"][0]["caller_call_id"], caller.as_str(), "{v}");
        let v = json_of(
            &srv.th_mappings(Parameters(ask(None, Some("pending"))))
                .await
                .map_err(|e| format!("the call succeeds: {e:?}"))?,
        )?;
        assert_eq!(v["total_matched"], 1, "{v}");
        let err = srv
            .th_mappings(Parameters(ask(None, Some("stuck"))))
            .await
            .err()
            .ok_or("an unknown state is refused")?;
        assert!(err.message.contains("conflict, pending, joined"), "{err:?}");
        Ok(())
    }

    /// A page size never moves the capture-wide claims beside the rows:
    /// `total_matched`, the event counts and the hidden legs by status read
    /// the same at `limit` 1 as at the default.
    #[tokio::test]
    async fn a_page_size_never_moves_the_mapping_counts() -> Result<(), TestError> {
        use crate::sip::th_mapping::ThMapping;
        let mut ds = DialogStore::new(100, false);
        let now = chrono::Utc::now();
        for n in 0..3 {
            ds.apply_th_mapping(
                Ok(ThMapping {
                    caller_call_id: format!("{n}-page@example.com"),
                    callee_call_id: format!("DLGCH_page{n}"),
                }),
                now,
            );
        }
        let srv = SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        );
        let ask = |limit: Option<u32>| ThMappingsParams {
            call_id: None,
            state: None,
            limit,
        };
        let one = json_of(
            &srv.th_mappings(Parameters(ask(Some(1))))
                .await
                .map_err(|e| format!("the call succeeds: {e:?}"))?,
        )?;
        let all = json_of(
            &srv.th_mappings(Parameters(ask(None)))
                .await
                .map_err(|e| format!("the call succeeds: {e:?}"))?,
        )?;
        assert_eq!(one["mappings"].as_array().map(Vec::len), Some(1), "{one}");
        assert_eq!(all["mappings"].as_array().map(Vec::len), Some(3), "{all}");
        for key in ["total_matched", "counts", "th_callid"] {
            assert_eq!(one[key], all[key], "{key} moved with the page size");
        }
        assert_eq!(one["total_matched"], 3, "{one}");
        Ok(())
    }

    /// Registered, and annotated read-only, so a `read`-scoped token reaches
    /// it and a host can call it without asking.
    #[test]
    fn hep_senders_is_registered_and_annotated_read_only() -> Result<(), TestError> {
        let router = SipnabMcp::hep_router();
        let tool = router
            .get("hep_senders")
            .ok_or("hep_senders must be registered")?;
        let annotations = tool
            .annotations
            .as_ref()
            .ok_or("hep_senders must carry tool annotations")?;
        assert_eq!(annotations.read_only_hint, Some(true));
        assert!(tool.output_schema.is_some(), "it declares its output shape");
        Ok(())
    }

    /// The tool answers with the roster the listener hung on the meter.
    #[tokio::test]
    async fn hep_senders_returns_the_listeners_roster() -> Result<(), TestError> {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()?));
        let srv = server().with_capture_meter(Some(meter));
        let body = json_of(
            &srv.hep_senders(Parameters(HepSendersParams { limit: None }))
                .await
                .map_err(|e| format!("the tool answers: {e:?}"))?,
        )?;
        assert_eq!(body["listening"], true);
        assert_eq!(body["trust"], "shared_secret_hmac");
        assert_eq!(body["senders"][0]["source"], "hep:7@192.0.2.7");
        assert_eq!(body["senders"][1]["source"], "hep:9@192.0.2.9");
        assert_eq!(body["refused_sources"][0]["by_reason"]["hmac_bad_mac"], 1);
        Ok(())
    }

    /// A row limit caps each list and not the totals.
    #[tokio::test]
    async fn hep_senders_honors_its_row_limit() -> Result<(), TestError> {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()?));
        let srv = server().with_capture_meter(Some(meter));
        let body = json_of(
            &srv.hep_senders(Parameters(HepSendersParams { limit: Some(1) }))
                .await
                .map_err(|e| format!("the tool answers: {e:?}"))?,
        )?;
        assert_eq!(body["senders"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["senders_tracked"], 2);
        Ok(())
    }

    /// **A page size never moves a roster-wide claim.** Everything but the two
    /// row lists is identical at a page of one and a page of fifty — the
    /// property `tests/population_claim_test.rs` holds for every other paging
    /// tool, driven here because only here can a roster exist.
    #[tokio::test]
    async fn a_page_size_never_moves_the_roster_totals() -> Result<(), TestError> {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()?));
        let srv = server().with_capture_meter(Some(meter));
        let at = |limit| {
            let srv = &srv;
            async move {
                json_of(
                    &srv.hep_senders(Parameters(HepSendersParams { limit: Some(limit) }))
                        .await
                        .map_err(|e| format!("the tool answers: {e:?}"))?,
                )
            }
        };
        let mut small = at(1).await?;
        let mut large = at(50).await?;
        assert_eq!(
            small["senders"].as_array().map(Vec::len),
            Some(1),
            "precondition: the small page really was cut"
        );
        assert_eq!(large["senders"].as_array().map(Vec::len), Some(2));
        for rows in ["senders", "refused_sources"] {
            small.as_object_mut().map(|o| o.remove(rows));
            large.as_object_mut().map(|o| o.remove(rows));
        }
        assert_eq!(
            small, large,
            "a roster-wide figure moved with the page size"
        );
        Ok(())
    }

    /// The tool's description and its `limit` schema text, as `tools/list`
    /// sends them.
    fn wire_text() -> Result<(String, String), TestError> {
        let router = SipnabMcp::hep_router();
        let tool = router.get("hep_senders").ok_or("registered")?;
        let limit = tool.input_schema["properties"]["limit"]["description"]
            .as_str()
            .ok_or("limit has a description")?
            .to_string();
        Ok((
            tool.description.clone().unwrap_or_default().to_string(),
            limit,
        ))
    }

    /// MCP-A4(a): `limit` 0 (or omitted) is the default page of
    /// `DEFAULT_LIMIT` rows, as on every list tool, and the schema text says
    /// so. It said "the server's row cap", which a roster past 50 senders
    /// shows to be false.
    #[tokio::test]
    async fn hep_senders_limit_zero_is_the_default_page_its_text_names() -> Result<(), TestError> {
        use crate::mcp::shape::DEFAULT_LIMIT;
        let t = std::time::Instant::now();
        let mut state = RosterState::new(
            SenderTrust::Unauthenticated,
            DEFAULT_LIMIT + 20,
            std::time::Duration::from_secs(30),
            t,
            chrono::Utc::now(),
        );
        for id in 0..u32::try_from(DEFAULT_LIMIT + 10)? {
            let peer = std::net::IpAddr::from([192, 0, 2, u8::try_from(id)?]);
            state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), t);
        }
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(HepRoster::with_clock(state, Arc::new(move || t))));
        let srv = server().with_capture_meter(Some(meter));
        for limit in [None, Some(0)] {
            let body = json_of(
                &srv.hep_senders(Parameters(HepSendersParams { limit }))
                    .await
                    .map_err(|e| format!("the tool answers: {e:?}"))?,
            )?;
            assert_eq!(body["senders_tracked"], DEFAULT_LIMIT + 10, "{limit:?}");
            assert_eq!(
                body["senders"].as_array().map(Vec::len),
                Some(DEFAULT_LIMIT),
                "{limit:?}: the default page, not the row cap"
            );
        }
        let (_, limit_text) = wire_text()?;
        assert!(
            limit_text.contains(&format!("Omitted or 0, {DEFAULT_LIMIT}: the default page")),
            "the schema names the default page: {limit_text}"
        );
        Ok(())
    }

    /// MCP-A4(b): the answer carries the fields and values `GET
    /// /v1/hep/senders` returns for the same roster, plus this server's
    /// completeness stamp, and the description says exactly that. It said
    /// "same bytes", which the stamp and the key order make false.
    #[tokio::test]
    async fn hep_senders_carries_the_rest_fields_plus_the_stamp() -> Result<(), TestError> {
        use crate::mcp::completeness::{SOURCE_EXHAUSTED_KEY, SOURCE_STOPPED_EARLY_KEY};
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()?));
        let rest = serde_json::to_value(crate::capture::hep_roster::senders_report(
            meter.hep_roster(),
            crate::mcp::shape::DEFAULT_LIMIT,
        ))?;
        let srv = server().with_capture_meter(Some(meter));
        let mut result = srv
            .hep_senders(Parameters(HepSendersParams { limit: None }))
            .await
            .map_err(|e| format!("the tool answers: {e:?}"))?;
        crate::mcp::completeness::stamp("hep_senders", true, false, &mut result);
        let mut mcp = json_of(&result)?;
        let object = mcp.as_object_mut().ok_or("an object")?;
        for key in [SOURCE_EXHAUSTED_KEY, SOURCE_STOPPED_EARLY_KEY] {
            assert!(object.remove(key).is_some(), "the stamp carries {key}");
        }
        assert_eq!(mcp, rest, "the same fields and values as REST");
        let (description, _) = wire_text()?;
        assert!(
            description.contains(
                "Same fields and values as GET /v1/hep/senders, plus \
                 source_exhausted and source_stopped_early"
            ) && !description.contains("Same bytes"),
            "{description}"
        );
        Ok(())
    }

    /// No listener: `listening: false` and a note, never an empty roster.
    #[tokio::test]
    async fn hep_senders_without_a_listener_says_nothing_is_listening() -> Result<(), TestError> {
        let body = json_of(
            &server()
                .hep_senders(Parameters(HepSendersParams { limit: None }))
                .await
                .map_err(|e| format!("the tool answers: {e:?}"))?,
        )?;
        assert_eq!(body["listening"], false);
        assert!(
            body["note"]
                .as_str()
                .is_some_and(|n| n.contains("no HEP listener"))
        );
        Ok(())
    }
}
