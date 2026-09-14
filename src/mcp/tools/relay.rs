// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where an endpoint came from, and whether that path could be trusted.
//!
//! # Why this exists
//!
//! An agent that reports "media anchored at `<addr>`" cannot today say whether
//! that address came from SDP the two parties exchanged, from a relay sipnab
//! asked directly, or from a mirrored datagram anybody on the network could
//! have sent. Those three carry very different weight in an incident review and
//! every surface renders them identically.
//!
//! The distinction is not academic. Sniffed relay control is gated on the
//! destination port, and the SOURCE is still not authenticated -- a residual
//! `a_mirror_from_any_source_is_still_believed_on_the_hep_port` pins on
//! purpose. So "the relay told us" and "something claiming to be the relay told
//! us" are both a media-relay assertion in the store, and only the delivery
//! path separates them.
//!
//! # Where the authentication answer comes from
//!
//! From the run's configuration, not from a per-packet record, and that is
//! correct rather than a shortcut: a datagram that failed authentication was
//! REJECTED at ingest, so every assertion still in the store arrived under
//! whatever posture was configured. Recording a bit per packet would restate
//! the configuration once per packet and let the two drift.
//!
//! # Relay-agnostic on purpose
//!
//! Nothing here names rtpengine. RP2 moved the vocabulary into `crate::relay`
//! precisely so a second control decoder needs no second tool, and
//! `relay_seam_test::no_mcp_tool_is_named_after_a_relay_vendor` refuses one.

use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// How a relay-asserted endpoint reached this process, and what that is worth.
///
/// Ordered from strongest to weakest, which is the order an incident review
/// cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryTrust {
    /// sipnab asked the relay directly over its control socket.
    ///
    /// The strongest: no third party was in a position to answer.
    Asked,
    /// Delivered over HEP with an authenticated token.
    HmacVerified,
    /// Delivered over HEP with a shared secret compared byte for byte.
    ///
    /// Weaker than HMAC: the token does not cover the datagram, so an on-path
    /// attacker who has seen one packet can reuse the secret.
    PlainSecret,
    /// Accepted because it arrived on the expected port, and for no other
    /// reason.
    ///
    /// The source was not authenticated. Anyone who can reach that port can
    /// assert an endpoint, which is the residual sipnab pins rather than
    /// pretends away.
    PortGatedOnly,
    /// The endpoint is the parties' own claim in SDP, not a relay's.
    NotRelayAsserted,
}

impl DeliveryTrust {
    /// One sentence an operator can act on.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::Asked => {
                "sipnab asked the relay over its control socket; no third party could answer"
            }
            Self::HmacVerified => {
                "delivered over HEP and authenticated with an HMAC token covering the datagram"
            }
            Self::PlainSecret => {
                "delivered over HEP with a shared secret; the token does not cover the \
                 datagram, so a captured one can be reused"
            }
            Self::PortGatedOnly => {
                "accepted because it arrived on the expected port and for no other reason -- \
                 the source is NOT authenticated, so anyone who can reach that port can \
                 assert this endpoint"
            }
            Self::NotRelayAsserted => {
                "the parties' own claim in SDP, not a relay's statement about its allocation"
            }
        }
    }
}

/// One endpoint, and the provenance behind it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EndpointProvenance {
    /// The address this row is about.
    pub address: String,
    /// The port.
    pub port: u16,
    /// `signaled` or `media-relay`.
    pub asserted_by: String,
    /// Which capture source carried it, when one did.
    ///
    /// `None` means sipnab ASKED rather than captured -- there is no source to
    /// name, and that absence is itself the strongest provenance available.
    pub input_origin: Option<String>,
    /// When the assertion was learned.
    pub observed_at: Option<String>,
    /// How much the delivery path is worth.
    pub delivery_trust: DeliveryTrust,
    /// That verdict in a sentence.
    pub delivery_note: &'static str,
}

/// What `explain_attribution` answers with.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct AttributionExplanation {
    /// The call this is about.
    pub call_id: String,
    /// One row per endpoint the call's streams touch.
    pub endpoints: Vec<EndpointProvenance>,
    /// How many rows rest on a path whose source was never authenticated.
    ///
    /// Surfaced as its own number because it is the one an incident review
    /// acts on, and a reader should not have to count rows to find it.
    pub unauthenticated_endpoints: usize,
    /// Schema version for this payload.
    pub schema_version: u32,
    /// Which capture answered, and at which store revision.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// Arguments for `explain_attribution`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExplainAttributionParams {
    /// Call-ID to explain, as returned by `list_dialogs`.
    pub call_id: String,
}

/// Why one stream has no dialog, as far as this process can honestly say.
///
/// Deliberately NOT a re-spelling of [`crate::relay::reconcile::Unattributed`].
/// That vocabulary answers "the relay was asked and said X", and this server
/// holds no live reconciler -- it reads stores another part of the process
/// filled. Reporting `RelayDoesNotHoldIt` here would assert an answer nobody
/// received, which is the exact failure `Unattributed` was written to prevent:
/// "no attribution" and "could not ask" are different facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
pub enum OrphanReason {
    /// A relay named this endpoint, but no dialog in this capture claims it.
    ///
    /// The signaling for this call is missing rather than the media being
    /// unexplained -- most often one leg of a call whose other leg was never
    /// captured.
    RelayAssertedButNoDialog,
    /// Something in SDP named this endpoint, and still no dialog holds it.
    ///
    /// Usually a dialog the capture dropped, or one whose SDP was in a message
    /// that arrived before capture started.
    SignaledButNoDialog,
    /// Nothing in this capture ever named this endpoint.
    ///
    /// Media with no signaling behind it at all. A relay could answer this, and
    /// none was asked.
    NeverNamed,
}

impl OrphanReason {
    /// What an operator should do about it.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::RelayAssertedButNoDialog => {
                "a relay named this endpoint but no captured dialog claims it -- the \
                 signaling is missing, not the media"
            }
            Self::SignaledButNoDialog => {
                "an SDP body named this endpoint but no dialog holds it -- the dialog was \
                 dropped, or its SDP arrived before capture started"
            }
            Self::NeverNamed => {
                "nothing in this capture named this endpoint. A relay could answer it and \
                 none was asked: that is an absence of evidence, not evidence of absence"
            }
        }
    }
}

/// Which reason an unexplained stream carries, from what named its endpoint.
///
/// A free function for the reason [`classify`] is one: the handler that calls
/// it needs a server, a store and a capture, and none of that is needed to
/// state which reason belongs to which assertion. Extracted from the match
/// inside `reconcile_orphans`, so the rule lives in one place -- a second copy
/// would agree today and drift the first time a variant is added.
#[must_use]
pub fn orphan_reason(named: Option<crate::rtp::stream_store::EndpointAssertion>) -> OrphanReason {
    use crate::rtp::stream_store::EndpointAssertion;
    match named {
        Some(EndpointAssertion::MediaRelay { .. }) => OrphanReason::RelayAssertedButNoDialog,
        Some(EndpointAssertion::Signaled) => OrphanReason::SignaledButNoDialog,
        None => OrphanReason::NeverNamed,
    }
}

/// One unexplained stream.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct OrphanRow {
    /// The RTP synchronization source.
    pub ssrc: u32,
    /// Sender address.
    pub src: String,
    /// Receiver address.
    pub dst: String,
    /// Which endpoint, if either, anything ever named.
    pub named_endpoint: Option<String>,
    /// What produced that name, when something did.
    pub asserted_by: Option<String>,
    /// The verdict.
    pub reason: OrphanReason,
    /// The verdict in a sentence.
    pub note: &'static str,
}

/// What `reconcile_orphans` answers with.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct OrphanReconciliation {
    /// One row per orphaned stream, most recent first.
    pub orphans: Vec<OrphanRow>,
    /// How many orphans this capture holds in total.
    pub total_orphans: usize,
    /// Whether rows were cut to `limit`.
    pub truncated: bool,
    /// Whether a relay was ever asked about any of this.
    ///
    /// `false` means every `never-named` verdict below is "nobody asked",
    /// which is a weaker statement than "asked and told no" and must not be
    /// read as the stronger one.
    pub relay_was_consulted: bool,
    /// Schema version for this payload.
    pub schema_version: u32,
    /// Which capture answered, and at which store revision.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// Arguments for `reconcile_orphans`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ReconcileOrphansParams {
    /// Maximum rows to return. Default 50.
    pub limit: Option<u32>,
}

#[tool_router(router = relay_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// How each of this call's endpoints was learned, and whether that path
    /// was authenticated.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` names no dialog.
    #[tool(
        name = "explain_attribution",
        description = "For one call, report where each media endpoint came \
                       from and how much that path is worth: whether sipnab \
                       ASKED a relay, or a relay's statement arrived over an \
                       authenticated HEP path, or it was accepted only because \
                       it landed on the expected port with the source \
                       unauthenticated, or it is simply the parties' own SDP \
                       claim. 'The relay told us' and 'something claiming to \
                       be the relay told us' are the same assertion in the \
                       store and differ only in delivery.",
        output_schema = schema_for_output::<AttributionExplanation>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn explain_attribution(
        &self,
        Parameters(params): Parameters<ExplainAttributionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let trust = self.relay_delivery_trust();

        let (rows, identity) = {
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            if ds.get(&params.call_id).is_none() {
                drop(ds);
                return Err(rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                ));
            }
            let ss = self.stream_store.read();
            let identity = state.identity.etag(ds.generation(), ss.generation());
            let mut seen = std::collections::BTreeSet::new();
            let mut rows = Vec::new();
            for stream in ss.streams_for(&params.call_id) {
                for sock in [stream.key.src, stream.key.dst] {
                    if !seen.insert((sock.ip(), sock.port())) {
                        continue;
                    }
                    let p = ss.sdp_endpoint_provenance(sock.ip(), sock.port());
                    let asserted = p
                        .as_ref()
                        .map_or(crate::rtp::stream_store::EndpointAssertion::Signaled, |p| {
                            p.asserted_by
                        });
                    let origin = p.as_ref().and_then(|p| p.origin);
                    rows.push(EndpointProvenance {
                        address: sock.ip().to_string(),
                        port: sock.port(),
                        asserted_by: asserted.as_str().to_string(),
                        input_origin: origin.map(|o| o.as_str().to_string()),
                        observed_at: p
                            .as_ref()
                            .and_then(|p| p.observed_at)
                            .map(|t| t.to_rfc3339()),
                        delivery_trust: classify(asserted, origin, trust),
                        delivery_note: classify(asserted, origin, trust).explain(),
                    });
                }
            }
            (rows, identity)
        };

        let unauthenticated = rows
            .iter()
            .filter(|r| r.delivery_trust == DeliveryTrust::PortGatedOnly)
            .count();
        let payload = AttributionExplanation {
            call_id: params.call_id,
            endpoints: rows,
            unauthenticated_endpoints: unauthenticated,
            schema_version: 1,
            capture_identity: identity,
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?,
        )?]))
    }
    /// Why each unexplained stream is unexplained.
    ///
    /// # Errors
    ///
    /// Does not fail on an empty capture: no orphans is an answer.
    #[tool(
        name = "reconcile_orphans",
        description = "For every RTP stream with no dialog, say WHY rather \
                       than only that it is orphaned: whether a relay named \
                       the endpoint and the signaling is missing, whether SDP \
                       named it and the dialog was dropped, or whether nothing \
                       in the capture ever named it. Reports whether a relay \
                       was consulted at all, because 'nobody asked' is a \
                       weaker statement than 'asked and told no' and must not \
                       be read as the stronger one.",
        output_schema = schema_for_output::<OrphanReconciliation>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn reconcile_orphans(
        &self,
        Parameters(params): Parameters<ReconcileOrphansParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = params.limit.unwrap_or(50).max(1) as usize;
        let (rows, total, consulted, identity) = {
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let identity = state.identity.etag(ds.generation(), ss.generation());
            let mut rows = Vec::new();
            let mut total = 0usize;
            let mut consulted = false;
            for stream in ss.iter().filter(|s| s.orphaned()) {
                total += 1;
                // Ask about BOTH ends: a relay allocation is the midpoint of a
                // leg, so the named side is as often the destination as the
                // source.
                let named = [stream.key.src, stream.key.dst].into_iter().find_map(|a| {
                    ss.sdp_endpoint_provenance(a.ip(), a.port())
                        .map(|p| (a, p.asserted_by))
                });
                let reason = orphan_reason(named.map(|(_, asserted)| asserted));
                let (endpoint, asserted) = match named {
                    Some((a, crate::rtp::stream_store::EndpointAssertion::MediaRelay { .. })) => {
                        (Some(a.to_string()), Some("media-relay".to_string()))
                    }
                    Some((a, crate::rtp::stream_store::EndpointAssertion::Signaled)) => {
                        (Some(a.to_string()), Some("signaled".to_string()))
                    }
                    None => (None, None),
                };
                // Accumulated over EVERY orphan, not only those that fit under
                // `limit`. Read off the truncated page, a small limit would
                // report "nobody asked" about a capture whose sixtieth orphan
                // is a relay assertion -- turning an absence of evidence into
                // evidence of absence, which is the one reading this field
                // exists to prevent.
                consulted |= reason == OrphanReason::RelayAssertedButNoDialog;
                if rows.len() >= limit {
                    continue;
                }
                rows.push(OrphanRow {
                    ssrc: stream.key.ssrc,
                    src: stream.key.src.to_string(),
                    dst: stream.key.dst.to_string(),
                    named_endpoint: endpoint,
                    asserted_by: asserted,
                    reason,
                    note: reason.explain(),
                });
            }
            (rows, total, consulted, identity)
        };

        let payload = OrphanReconciliation {
            truncated: total > rows.len(),
            total_orphans: total,
            orphans: rows,
            relay_was_consulted: consulted,
            schema_version: 1,
            capture_identity: identity,
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?,
        )?]))
    }

    /// Decode one captured relay control message.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `frame_ref` is blank. A pointer that
    /// cannot be followed is a result with `status: "unresolvable"`, never a
    /// call failure -- the reason is the answer, exactly as in
    /// `decode_evidence`.
    #[tool(
        name = "decode_ng",
        description = "Follows one frame pointer back to a captured relay \
                       control message and decodes it: the command, the \
                       call it names, whether it carries SDP, and -- the part \
                       no other surface reports -- which delivery path carried \
                       it and whether that path authenticated its sender. A \
                       message mirrored to the HEP port is believed because of \
                       the port and nothing else, so its sender is \
                       unauthenticated; one delivered over an HMAC-authenticated \
                       HEP listener is not. Status is `verified`, `unverified` \
                       or `unresolvable`, as in decode_evidence. Sources are \
                       confined to --mcp-file-root.",
        output_schema = schema_for_output::<NgDecode>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn decode_ng(
        &self,
        Parameters(params): Parameters<DecodeNgParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let pointer = params.frame_ref.trim();
        if pointer.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "frame_ref must name one frame pointer, in the \
                 <source>#<ordinal>@<digest> form the query tools emit. A blank \
                 string names no frame, and an empty decode would read as 'this \
                 frame holds no control message'"
                    .to_string(),
                None,
            ));
        }
        let payload = decode_ng_one(self, pointer);
        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Ask the live relay what it is holding.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when the run cannot or may not ask, naming
    /// which of the three reasons applies: the opt-in is off, no relay address
    /// was configured, or this run reads a file and can obtain no transmit
    /// permit. Three separate messages rather than one, because the operator
    /// action differs for each.
    #[tool(
        name = "query_relay",
        description = "Asks the configured relay what it is \
                       holding right now: every Call-ID it knows, or the ports \
                       and tags for one call. This is the only MCP tool that \
                       TRANSMITS -- every other one answers from bytes sipnab \
                       already has. It closes the gap a passive decoder cannot: \
                       a call already in progress when sipnab started has no \
                       control exchange left to read, which is exactly the case \
                       during incident response. Off unless \
                       --mcp-allow-relay-query is given, refused on a run \
                       reading a file, and the destination comes from operator \
                       configuration only -- never from an argument.",
        output_schema = schema_for_output::<RelayAnswer>(),
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    pub async fn query_relay(
        &self,
        Parameters(params): Parameters<QueryRelayParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let Some(access) = self.relay_query_access() else {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "query_relay is not available on this server. It transmits, \
                     so it needs three things: --mcp-allow-relay-query to enable \
                     it, {} <addr:port> to say which relay to ask, and a live \
                     source. A run reading a capture file can obtain no transmit \
                     permit, so an analyst opening somebody else's pcap cannot \
                     make sipnab talk to the addresses inside it.",
                    crate::cli::RELAY_CONTROL_FLAG
                ),
                None,
            ));
        };

        // Handed in by the composition root. This layer asks a relay a
        // question; which relay, and what speaks to it, is not its business.
        let client = &access.relay;
        let asked = if params.call_id.is_some() {
            "query"
        } else {
            "list"
        };
        let reply = match params.call_id.as_deref() {
            Some(call_id) => client.query(&access.permit, call_id),
            None => client.list(
                &access.permit,
                params
                    .max_calls
                    .unwrap_or(crate::relay::reconcile::DEFAULT_LIST_LIMIT),
            ),
        };
        let reply = reply.map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!(
                    "the relay at {} did not answer: {e:#}. Nothing is known \
                     about what it holds; this is not an answer that it holds \
                     nothing.",
                    access.addr
                ),
                None,
            )
        })?;

        let payload = RelayAnswer::from_reply(asked, access.addr, &reply);
        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Ask the relay for its own statistics counters (C1/C2/C3).
    ///
    /// A global ask returns the relay's own counters; a `call_id` scopes them to
    /// one call; `names_only` returns the names the relay knows rather than their
    /// values, for "what can I even ask for". Tiered `relay_reported` throughout:
    /// these are the relay's claims about itself, never blended with what sipnab
    /// measured -- that comparison is `relay_compare`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when the run cannot or may not ask -- the opt-in
    /// is off, no relay address was configured, or this run reads a file and can
    /// obtain no transmit permit. `internal_error` (-32603) when the relay was
    /// asked and nothing came back: nothing is known, which is not the same as
    /// the relay reporting nothing. A relay that answered but declined the ask
    /// (a Call-ID it does not hold) is a success carrying `outcome: "refused"`
    /// with the relay's own words -- the relay answered, it just said no.
    #[tool(
        name = "relay_stats",
        description = "Asks the configured relay for the statistics it keeps \
                       about ITSELF: its global counters, the counters for one \
                       Call-ID, or -- with names_only -- the names it knows so \
                       an agent learns what it can ask for, since the key set is \
                       version-specific. Every figure is tiered relay_reported, \
                       never blended with what sipnab measured. Like query_relay \
                       this TRANSMITS, so it is off unless --mcp-allow-relay-query \
                       is given, refused on a run reading a file, and the \
                       destination comes from operator configuration only.",
        output_schema = schema_for_output::<RelayStatsAnswer>(),
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    pub async fn relay_stats(
        &self,
        Parameters(params): Parameters<RelayStatsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let Some(access) = self.relay_query_access() else {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "relay_stats is not available on this server. It transmits, \
                     so it needs three things: --mcp-allow-relay-query to enable \
                     it, {} <addr:port> to say which relay to ask, and a live \
                     source. A run reading a capture file can obtain no transmit \
                     permit.",
                    crate::cli::RELAY_CONTROL_FLAG
                ),
                None,
            ));
        };

        let client = &access.relay;
        let call_id = params.call_id.as_deref();
        // names_only is a global concept -- "what can I even ask for" -- so it is
        // honored only without a call_id, matching the REST names route.
        let names_only = params.names_only.unwrap_or(false) && call_id.is_none();
        let reply = match call_id {
            Some(cid) => client.call_statistics(&access.permit, cid),
            None => client.statistics(&access.permit),
        };
        let reply = reply.map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!(
                    "the relay at {} did not answer: {e:#}. Nothing is known \
                     about its statistics; this is not an answer that it has none.",
                    access.addr
                ),
                None,
            )
        })?;

        let payload = RelayStatsAnswer::from_reply(access.addr, &reply, call_id, names_only);
        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Compare the relay's per-call RTP count against this capture's (C4).
    ///
    /// A comparison, never a sum: both figures travel with their tiers, the
    /// verdict is a word, and a note explains that an ordinary gap is not a
    /// relay fault -- the two count different sockets over different windows. A
    /// side that produced nothing is reported absent, never coerced to zero, so
    /// "the relay does not hold this call" never reads as a gap the relay must
    /// answer for.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when the run cannot or may not ask, or when
    /// `call_id` is blank. `internal_error` (-32603) when the relay was asked
    /// and nothing came back. A relay that answered is a success whose `outcome`
    /// says what was found: `compared`, `sipnab_has_no_rtp`,
    /// `relay_does_not_hold_call`, `neither`, `refused`, or `suspect`.
    #[tool(
        name = "relay_compare",
        description = "Compares the relay's reported RTP packet count for one \
                       call against the count sipnab measured from the packets \
                       it captured. Shows both figures with their tiers \
                       (relay_reported and sipnab_measured) and a word verdict; \
                       it never sums or subtracts them, because the two count \
                       different sockets over different windows. Like query_relay \
                       this TRANSMITS: off unless --mcp-allow-relay-query is \
                       given, refused on a run reading a file, destination from \
                       operator configuration only.",
        output_schema = schema_for_output::<RelayCompareAnswer>(),
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    pub async fn relay_compare(
        &self,
        Parameters(params): Parameters<RelayCompareParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let Some(access) = self.relay_query_access() else {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "relay_compare is not available on this server. It transmits, \
                     so it needs three things: --mcp-allow-relay-query to enable \
                     it, {} <addr:port> to say which relay to ask, and a live \
                     source. A run reading a capture file can obtain no transmit \
                     permit.",
                    crate::cli::RELAY_CONTROL_FLAG
                ),
                None,
            ));
        };

        let call_id = params.call_id.trim();
        if call_id.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "relay_compare needs a call_id to compare; a blank string names \
                 no call, and comparing nothing has no answer."
                    .to_string(),
                None,
            ));
        }

        // sipnab's own side first: no linked stream is ABSENT, not a measured
        // zero, so a call sipnab never saw is not rendered as `0` against the
        // relay. Held only long enough to read.
        let sipnab_side = {
            let ss = self.stream_store.read();
            if ss.streams_for(call_id).next().is_some() {
                Some(ss.measured_packet_count_for(call_id))
            } else {
                None
            }
        };

        let reply = access
            .relay
            .call_statistics(&access.permit, call_id)
            .map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!(
                        "the relay at {} did not answer for call {call_id}: {e:#}. \
                     Nothing is known; this is not an answer that it holds nothing.",
                        access.addr
                    ),
                    None,
                )
            })?;

        use crate::relay::types::ControlReply;
        use crate::stats_vocab::{
            StatisticValue, lookup, ready_comparison, relay_reply_refusal, relay_reported,
        };
        let payload = match reply {
            ControlReply::Statistics(pairs) => {
                if let Some(reason) = relay_reply_refusal(&pairs) {
                    RelayCompareAnswer::refused(access.addr, call_id, reason)
                } else {
                    let tiered = relay_reported(&pairs);
                    let relay_side = match lookup(&tiered, "totals.RTP.packets") {
                        StatisticValue::Counted(s) => s.parse::<u64>().ok(),
                        _ => None,
                    };
                    RelayCompareAnswer::from_outcome(
                        access.addr,
                        call_id,
                        ready_comparison(relay_side, sipnab_side),
                    )
                }
            }
            _ => RelayCompareAnswer::suspect(access.addr, call_id),
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::to_value(&payload).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("serialization failed: {e}"), None)
            })?)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

/// Decide what one endpoint's delivery path is worth.
///
/// A free function rather than a method so it can be driven with every
/// combination directly, including ones this tree cannot currently produce.
#[must_use]
pub fn classify(
    asserted: crate::rtp::stream_store::EndpointAssertion,
    origin: Option<crate::capture::parse::InputOrigin>,
    configured: DeliveryTrust,
) -> DeliveryTrust {
    if asserted.implementation().is_none() {
        return DeliveryTrust::NotRelayAsserted;
    }
    match origin {
        // No capture source: sipnab asked for this rather than observing it.
        None => DeliveryTrust::Asked,
        // It arrived over a capture path, so the run's configured posture is
        // what it was worth -- a datagram that failed was never stored.
        Some(_) => configured,
    }
}

/// Parameters for `decode_ng`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DecodeNgParams {
    /// One frame pointer, in the `<source>#<ordinal>@<digest>` form the query
    /// tools emit.
    ///
    /// One pointer rather than a batch, for the reason `decode_evidence` takes
    /// one: a decode is a whole message, and a batch of them fills a context
    /// window with control traffic nobody asked to read.
    pub frame_ref: String,
}

/// How a control message reached the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
pub enum NgDelivery {
    /// Encapsulated in HEP.
    Hep,
    /// A bare `ng` datagram, read off the wire.
    SniffedUdp,
}

/// One decoded relay control message, and what its delivery path is worth.
///
/// The decode fields are absent on `unresolvable`, so a caller cannot read a
/// partially-filled answer as a thin one -- the same split `decode_evidence`
/// makes for the same reason.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct NgDecode {
    /// The pointer this answers for, echoed.
    pub pointer: String,
    /// `verified` (the bytes still match the digest), `unverified`, or
    /// `unresolvable`.
    pub status: String,
    /// Why the pointer led nowhere. Present only on `unresolvable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The capture file, as a leaf name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Which frame of that file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u64>,
    /// Which path carried the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<NgDelivery>,
    /// What that path is worth, on the same scale `explain_attribution` uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_trust: Option<DeliveryTrust>,
    /// The one-line reading of `delivery_trust`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_note: Option<String>,
    /// Whether the datagram arrived on a port a sniffed mirror is believed on.
    ///
    /// Reported separately from `delivery_trust` because it is the ONLY reason
    /// a sniffed message is believed at all, and an operator reading a decode
    /// should see the whole of that reason rather than its conclusion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_believed_mirror_port: Option<bool>,
    /// The `ng` verb, as the relay spells it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The call the message names, where it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// The HEP correlation-id, which names the call on a REPLY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Whether the message carries SDP.
    pub has_sdp: bool,
    /// How much SDP, where there is any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_bytes: Option<usize>,
    /// Version of this response shape.
    pub schema_version: u32,
}

/// The answer for a pointer that leads to no control message anyone can read.
fn ng_unresolvable(pointer: &str, reason: String) -> NgDecode {
    NgDecode {
        pointer: pointer.to_string(),
        status: "unresolvable".to_string(),
        reason: Some(reason),
        source: None,
        ordinal: None,
        delivery: None,
        delivery_trust: None,
        delivery_note: None,
        on_believed_mirror_port: None,
        command: None,
        call_id: None,
        correlation_id: None,
        has_sdp: false,
        sdp_bytes: None,
        schema_version: 1,
    }
}

/// Build the answer for a message that decoded.
fn describe_control_message(
    pointer: &str,
    status: &str,
    leaf: &str,
    ordinal: u64,
    trust: DeliveryTrust,
    decoded: &crate::relay::DecodedControl,
) -> NgDecode {
    NgDecode {
        pointer: pointer.to_string(),
        status: status.to_string(),
        reason: None,
        source: Some(leaf.to_string()),
        ordinal: Some(ordinal),
        delivery: Some(match decoded.delivery {
            crate::relay::ControlDelivery::Encapsulated => NgDelivery::Hep,
            crate::relay::ControlDelivery::BareDatagram => NgDelivery::SniffedUdp,
        }),
        delivery_trust: Some(trust),
        delivery_note: Some(trust.explain().to_string()),
        on_believed_mirror_port: decoded.on_believed_mirror_port,
        command: decoded.message.command.clone(),
        call_id: decoded.message.call_id.clone(),
        correlation_id: decoded.correlation_id.clone(),
        has_sdp: decoded.message.sdp_bytes.is_some(),
        sdp_bytes: decoded.message.sdp_bytes,
        schema_version: 1,
    }
}

/// Follow one pointer, confine it, resolve it and decode the control message.
///
/// The order of the refusals matches `decode_evidence`, and the ordering is
/// load-bearing rather than stylistic: a uprobe pointer has to be refused
/// BEFORE the path logic, because `Path::file_name()` on `uprobe:opensips/1234`
/// returns `"1234"` and would send it down the file-root check to answer with a
/// missing file -- a wrong answer about evidence rather than an honest refusal.
fn decode_ng_one(server: &SipnabMcp, pointer: &str) -> NgDecode {
    let parsed = match crate::capture::resolve::parse_pointer(pointer) {
        Ok(p) => p,
        Err(e) => return ng_unresolvable(pointer, e.to_string()),
    };

    if matches!(
        parsed.kind,
        crate::capture::packet::FrameSource::Uprobe { .. }
    ) {
        return ng_unresolvable(
            pointer,
            "pointer names a uprobe read. sipnab took those bytes where an \
             application handed them to its TLS library and never saw a \
             datagram, so there is no control message to decode"
                .to_string(),
        );
    }

    let Some(leaf) = std::path::Path::new(parsed.source.as_ref())
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
    else {
        return ng_unresolvable(
            pointer,
            format!(
                "'{}' does not name a capture file. A pointer from live capture \
                 or from a HEP listener cannot be followed: sipnab holds parsed \
                 messages, not frames, so there is nothing to seek to.",
                parsed.source
            ),
        );
    };

    let path = match server.resolve_in_root(&leaf) {
        Ok(p) => p,
        Err(e) => {
            return ng_unresolvable(
                pointer,
                format!(
                    "source '{}' is not reachable from the configured file \
                     root: {}",
                    parsed.source, e.message
                ),
            );
        }
    };

    // Resolve against the CONFINED path, never the one the pointer carried.
    let confined = crate::capture::packet::FrameRef {
        // Confinement rewrites where to look, never what was asked for.
        bytes: parsed.bytes.clone(),
        source: path.display().to_string().into(),
        origin: parsed.origin,
        kind: parsed.kind.clone(),
    };
    let resolution = match crate::capture::resolve::resolve(&confined) {
        Ok(r) => r,
        Err(e) => return ng_unresolvable(pointer, e.to_string()),
    };
    let frame = resolution.bytes();
    let status = if resolution.is_verified() {
        "verified"
    } else {
        "unverified"
    };

    // The link type decides how many bytes precede the IP header, and decoding
    // an SLL or PPPoE capture as Ethernet produces addressing that looks
    // decoded and is wrong.
    let link_type = match crate::capture::file::open_offline(&path) {
        Ok((cap, _guard)) => cap.get_datalink().0,
        Err(e) => {
            return ng_unresolvable(
                pointer,
                format!(
                    "the frame resolved, but '{leaf}' would not reopen for its \
                     link-layer type: {e:#}. Decoding it as Ethernet would be a \
                     guess about the wire format, and a wrong guess reads as a \
                     decoded message."
                ),
            );
        }
    };

    let packet = crate::capture::packet::Packet::with_source(
        chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        frame.to_vec(),
        frame.len(),
        frame.len(),
        Some(std::sync::Arc::from(leaf.as_str())),
        link_type,
    );
    let decoded = match crate::capture::parse::parse_packet(&packet) {
        Ok(d) => d,
        Err(e) => {
            return ng_unresolvable(
                pointer,
                format!(
                    "frame {} of '{leaf}' carries no decodable transport: {e}",
                    parsed.origin.ordinal
                ),
            );
        }
    };

    // Decoding belongs to whatever speaks the relay's protocol. This layer
    // asks for a control message and is told what arrived.
    let Some(decoder) = server.control_decoder() else {
        return ng_unresolvable(
            pointer,
            "this server has no relay control decoder installed, so it cannot \
             say what a control datagram contains. Nothing was decoded; this is \
             not an answer that the frame holds no control message."
                .to_string(),
        );
    };
    let Some(control) = decoder.decode(&decoded.payload, decoded.dst_port) else {
        return ng_unresolvable(
            pointer,
            format!(
                "frame {} of '{leaf}' carries no relay control message. One is a \
                 cookie, a space, and a complete dictionary consuming the rest \
                 of the datagram; this payload is not one, either bare or \
                 encapsulated.",
                parsed.origin.ordinal
            ),
        );
    };

    // An encapsulated message can have been authenticated on delivery, and what
    // that is worth is a property of this RUN's configuration. A bare datagram
    // cannot have been: it is believed because of where it landed and for no
    // other reason, which is what `PortGatedOnly` says.
    let trust = match control.delivery {
        crate::relay::ControlDelivery::Encapsulated => server.relay_delivery_trust(),
        crate::relay::ControlDelivery::BareDatagram => DeliveryTrust::PortGatedOnly,
    };
    describe_control_message(
        pointer,
        status,
        &leaf,
        parsed.origin.ordinal,
        trust,
        &control,
    )
}

/// Parameters for `query_relay`.
///
/// # Why there is no address here
///
/// The relay's address comes from `--rtpengine-control` and from nowhere else.
/// A tool argument naming the destination would make this surface a way to send
/// packets to a host of the caller's choosing, which is a far larger act than
/// reading a capture -- and the address sipnab could otherwise infer is one it
/// learned from packets, which may belong to somebody's laptop now.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct QueryRelayParams {
    /// One Call-ID to ask about. Omit it to enumerate what the relay holds.
    pub call_id: Option<String>,
    /// Cap on the Call-IDs an enumeration returns.
    ///
    /// Named for what it bounds rather than `limit`: this is the relay's own
    /// `list` argument, traveling to another process, not a page over data
    /// sipnab already holds. rtpengine warns that raising it may exceed a UDP
    /// datagram, and a truncated answer is reported rather than padded.
    pub max_calls: Option<u32>,
}

/// One relay-side port, as the relay describes it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayStreamView {
    /// The relay's own address for this stream.
    pub local_address: String,
    /// The relay's own port -- the half a capture can see without signaling.
    pub local_port: u16,
    /// Where the relay currently sends, once it has learned it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// What the far side advertised in SDP, which may differ from `endpoint`
    /// behind NAT -- and the difference is often the bug being chased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_endpoint: Option<String>,
    /// Whether this port carries RTCP rather than RTP.
    pub is_rtcp: bool,
    /// Every SSRC the relay has seen on this port.
    pub ssrcs: Vec<u32>,
}

/// One side of a call, as the relay holds it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayTagView {
    /// The SIP tag identifying this side.
    pub tag: String,
    /// The tags this side exchanges media with in an offer/answer DIALOG.
    ///
    /// Offer/answer ONLY. A relay also lets one side receive another's media by
    /// SUBSCRIPTION, which is how relay-side recording and forking are built,
    /// and a subscriber is not the party the call is with. Folding the two
    /// together reported a recorder as the other end, so a two-party call came
    /// back with three parties.
    pub in_dialogue_with: Vec<String>,
    /// The tags whose media this side receives by SUBSCRIPTION.
    ///
    /// Separate from `in_dialogue_with` because the two answer different
    /// questions. An agent asked "who is on this call" must read the former; an
    /// agent asked "why is there a third stream" needs this one.
    pub media_subscriptions: Vec<String>,
    /// Whether this side only SUBSCRIBES and holds no dialog of its own.
    ///
    /// True for a recorder or a fork: its ports are real and belong to the
    /// call, so they are still attributed, but calling it a leg would turn a
    /// two-party conversation into a three-party one in every answer built on
    /// top of this.
    pub is_media_subscriber: bool,
    /// The codec the relay recorded, where it recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Ports the relay holds for this side, RTP and RTCP together.
    pub streams: Vec<RelayStreamView>,
}

/// What the relay said, and what asking it is worth.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayAnswer {
    /// `list` or `query` -- which question was put.
    pub asked: String,
    /// The address asked, echoed so the answer names its own source.
    ///
    /// Echoed from CONFIGURATION, which is the only place it can come from.
    pub relay_address: String,
    /// `calls`, `call`, or `refused`.
    pub outcome: String,
    /// The Call-IDs an enumeration returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_ids: Option<Vec<String>>,
    /// Whether the relay held more than it returned.
    ///
    /// A capped enumeration read as a complete one is the failure this field
    /// exists to prevent: "the relay holds these 32 calls" and "the relay
    /// returned the first 32 of an unknown number" are different statements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// The Call-ID a `query` asked about, carried from the REQUEST.
    ///
    /// rtpengine's `query` answer does not echo the Call-ID it was asked about,
    /// so pairing the answer with its question is the caller's job and cannot
    /// be checked from the bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Each side of the call a `query` returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<RelayTagView>>,
    /// The relay's own words when it declined.
    ///
    /// A refusal is not a transport failure: the relay was reached, understood
    /// the question, and said no.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// Always `asked` -- sipnab put the question to the relay over its control
    /// socket, so no third party could have answered it.
    pub delivery_trust: DeliveryTrust,
    /// The one-line reading of `delivery_trust`.
    pub delivery_note: String,
    /// The relay's own counters, when statistics were asked for.
    ///
    /// Name/value pairs as the relay wrote them. `None` on every other answer,
    /// and on a run where nothing asked -- which is most of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<Vec<(String, String)>>,
    /// Version of this response shape.
    pub schema_version: u32,
}

impl RelayAnswer {
    /// Render one control reply for an agent.
    fn from_reply(
        asked: &str,
        addr: std::net::SocketAddr,
        reply: &crate::relay::types::ControlReply,
    ) -> Self {
        use crate::relay::types::ControlReply;
        let base = |outcome: &str| Self {
            // Absent unless statistics were what was asked for.
            statistics: None,
            asked: asked.to_string(),
            relay_address: addr.to_string(),
            outcome: outcome.to_string(),
            call_ids: None,
            truncated: None,
            call_id: None,
            tags: None,
            refusal: None,
            // This tool ASKED. That is the strongest reading on the scale, and
            // the only one no third party could have produced.
            delivery_trust: DeliveryTrust::Asked,
            delivery_note: DeliveryTrust::Asked.explain().to_string(),
            schema_version: 1,
        };
        match reply {
            ControlReply::Calls(e) => Self {
                call_ids: Some(e.call_ids.clone()),
                truncated: Some(e.truncated),
                ..base("calls")
            },
            // Counters, as the relay named them. Not mapped onto a schema of
            // sipnab's own: the two relays count different things under
            // different names, and asserting an equivalence neither promised
            // would be inventing one.
            ControlReply::Statistics(pairs) => Self {
                statistics: Some(pairs.clone()),
                ..base("statistics")
            },
            ControlReply::Call(view) => Self {
                call_id: Some(view.call_id.clone()),
                tags: Some(
                    view.tags
                        .iter()
                        .map(|t| RelayTagView {
                            tag: t.tag.clone(),
                            in_dialogue_with: t.in_dialogue_with.clone(),
                            media_subscriptions: t.media_subscriptions.clone(),
                            is_media_subscriber: t.is_media_subscriber(),
                            codec: t.codec.clone(),
                            streams: t
                                .streams
                                .iter()
                                .map(|s| RelayStreamView {
                                    local_address: s.local_address.clone(),
                                    local_port: s.local_port,
                                    endpoint: s.endpoint.clone(),
                                    advertised_endpoint: s.advertised_endpoint.clone(),
                                    is_rtcp: s.is_rtcp,
                                    ssrcs: s.ssrcs.clone(),
                                })
                                .collect(),
                        })
                        .collect(),
                ),
                ..base("call")
            },
            ControlReply::Refused { reason } => Self {
                refusal: Some(reason.clone()),
                ..base("refused")
            },
        }
    }
}

// ── relay_stats / relay_compare (ST6) ────────────────────────────────────────

/// Arguments to `relay_stats`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayStatsParams {
    /// A Call-ID to scope the counters to one call. Omit for the relay's own
    /// global counters.
    pub call_id: Option<String>,
    /// Return the NAMES the relay knows rather than their values -- "what can I
    /// even ask for", since the key set is version-specific. Ignored when a
    /// `call_id` is given.
    pub names_only: Option<bool>,
}

/// Arguments to `relay_compare`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayCompareParams {
    /// The Call-ID to compare the relay's count against this capture's.
    pub call_id: String,
}

/// One counted statistic the relay reported, its value uncoerced.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayStatView {
    /// The relay's own name for it, unaltered.
    pub name: String,
    /// The value, as the relay wrote it (kept as text; never parsed narrower).
    pub value: String,
}

/// The relay's own statistics, tiered `relay_reported` (ST6 / C1–C3).
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayStatsAnswer {
    /// The relay and where it was asked.
    pub relay_address: String,
    /// Always `relay_reported`: these are the relay's claims about itself, never
    /// blended with what sipnab measured.
    pub tier: String,
    /// `ok`, or `refused` when the relay declined (e.g. a Call-ID it does not
    /// hold), or `suspect` when the reply was not statistics.
    pub outcome: String,
    /// Counted values (C1 global, or C2 per-call). Absent on a names-only or
    /// refused answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<Vec<RelayStatView>>,
    /// The names the relay knows (C3), when `names_only` was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// How the name set was determined: `listed` (the relay enumerated them) or
    /// `probed` (the names that did not refuse). Present only with `names`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names_source: Option<String>,
    /// One sentence stating what `names_source` means, so a probed set is never
    /// read as a definitive enumeration. Present only with `names`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names_note: Option<&'static str>,
    /// The relay's own words when it declined -- reached, understood, said no.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// Always `asked`: sipnab put the question over the control socket.
    pub delivery_trust: DeliveryTrust,
    /// The one-line reading of `delivery_trust`.
    pub delivery_note: &'static str,
    /// Version of this response shape.
    pub schema_version: u32,
}

impl RelayStatsAnswer {
    /// A relay-reported answer with the given outcome and every optional field
    /// empty, for one of the branches below to fill.
    fn base(addr: std::net::SocketAddr, outcome: &str) -> Self {
        Self {
            relay_address: addr.to_string(),
            tier: crate::stats_vocab::StatisticTier::RelayReported
                .as_wire_str()
                .to_string(),
            outcome: outcome.to_string(),
            statistics: None,
            names: None,
            names_source: None,
            names_note: None,
            refusal: None,
            delivery_trust: DeliveryTrust::Asked,
            delivery_note: DeliveryTrust::Asked.explain(),
            schema_version: 1,
        }
    }

    /// Render a `statistics`/`call_statistics` reply for an agent, applying the
    /// SAME rules the REST surface does.
    ///
    /// `call_id` is `Some` for a per-call ask and drives one difference: only a
    /// per-call reply can be the relay saying it does not hold the call, so the
    /// `result: error` refusal check ([`crate::stats_vocab::relay_reply_refusal`],
    /// the one copy REST also reads) is applied there and not to the global
    /// query, exactly as `relay_rest_answer` does. `names_only` is honored only
    /// for a global ask; the caller does not set it with a `call_id`.
    fn from_reply(
        addr: std::net::SocketAddr,
        reply: &crate::relay::types::ControlReply,
        call_id: Option<&str>,
        names_only: bool,
    ) -> Self {
        use crate::relay::types::ControlReply;
        use crate::stats_vocab::{
            NameSource, known_names, relay_reply_refusal, relay_reported, resolve_for_wire,
        };
        let ControlReply::Statistics(pairs) = reply else {
            return Self::base(addr, "suspect");
        };
        // Only a per-call reply can be the relay's "I do not hold that call".
        if call_id.is_some()
            && let Some(reason) = relay_reply_refusal(pairs)
        {
            let mut a = Self::base(addr, "refused");
            a.refusal = Some(reason);
            return a;
        }
        let tiered = relay_reported(pairs);
        if names_only {
            // The current relay enumerates its statistics -- the reply IS the
            // list -- so the source is `listed`, matching the REST names route.
            let source = NameSource::Listed;
            let mut a = Self::base(addr, "ok");
            a.names = Some(known_names(&tiered));
            a.names_source = Some(source.as_wire_str().to_string());
            a.names_note = Some(source.how_determined());
            a
        } else {
            let wire = resolve_for_wire(&tiered);
            let mut a = Self::base(addr, "ok");
            a.statistics = Some(
                wire.present
                    .iter()
                    .map(|v| RelayStatView {
                        name: v.name.clone(),
                        value: v.value.clone(),
                    })
                    .collect(),
            );
            a
        }
    }
}

/// The relay's per-call RTP count beside this capture's (ST6 / C4).
///
/// A comparison, never a sum: both figures with their tiers, a word verdict,
/// and a note. The two count different sockets over different windows, so an
/// ordinary gap is not a relay fault.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayCompareAnswer {
    /// The relay and where it was asked.
    pub relay_address: String,
    /// The call compared.
    pub call_id: String,
    /// `compared`, `sipnab_has_no_rtp`, `relay_does_not_hold_call`, `neither`,
    /// `refused` (the relay said no), or `suspect` (the reply was not
    /// statistics).
    pub outcome: String,
    /// The relay's count (`relay_reported`) and its own key name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_reported: Option<RelayComparedFigure>,
    /// What sipnab measured (`sipnab_measured`), when it captured RTP for this
    /// call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sipnab_measured: Option<u64>,
    /// `match` or `differ`, present only when both sides were compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// Why a difference is ordinary, in the operator's words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The relay's own words when it declined the per-call ask. Present only on
    /// a `refused` outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// Always `asked`.
    pub delivery_trust: DeliveryTrust,
    /// The one-line reading of `delivery_trust`.
    pub delivery_note: &'static str,
    /// Version of this response shape.
    pub schema_version: u32,
}

/// The relay's side of a comparison: its count and its own key name.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RelayComparedFigure {
    /// The count.
    pub value: u64,
    /// The relay's own name for the counter (`totals.RTP.packets`).
    pub name: String,
}

impl RelayCompareAnswer {
    /// A comparison answer with the given outcome and every optional field
    /// empty, for one of the constructors below to fill.
    fn base(addr: std::net::SocketAddr, call_id: &str, outcome: &str) -> Self {
        Self {
            relay_address: addr.to_string(),
            call_id: call_id.to_string(),
            outcome: outcome.to_string(),
            relay_reported: None,
            sipnab_measured: None,
            verdict: None,
            note: None,
            refusal: None,
            delivery_trust: DeliveryTrust::Asked,
            delivery_note: DeliveryTrust::Asked.explain(),
            schema_version: 1,
        }
    }

    /// The relay declined the per-call ask; carry its own words verbatim.
    fn refused(addr: std::net::SocketAddr, call_id: &str, reason: String) -> Self {
        let mut a = Self::base(addr, call_id, "refused");
        a.refusal = Some(reason);
        a
    }

    /// The relay answered with something other than statistics.
    fn suspect(addr: std::net::SocketAddr, call_id: &str) -> Self {
        Self::base(addr, call_id, "suspect")
    }

    /// Render a readied C4 comparison, keeping an absent side absent rather than
    /// coercing it to zero.
    fn from_outcome(
        addr: std::net::SocketAddr,
        call_id: &str,
        outcome: crate::stats_vocab::CompareOutcome,
    ) -> Self {
        use crate::stats_vocab::CompareOutcome;
        let base = |o: &str| Self::base(addr, call_id, o);
        match outcome {
            CompareOutcome::Compared(c) => {
                let mut a = base("compared");
                a.relay_reported = Some(RelayComparedFigure {
                    value: c.relay.value,
                    name: c
                        .relay
                        .name
                        .clone()
                        .unwrap_or_else(|| "RTP packets".to_string()),
                });
                a.sipnab_measured = Some(c.sipnab.value);
                a.verdict = Some(c.verdict.as_wire_str().to_string());
                a.note = Some(c.note.clone());
                a
            }
            CompareOutcome::SipnabHasNoRtp { relay_value } => {
                let mut a = base("sipnab_has_no_rtp");
                a.relay_reported = Some(RelayComparedFigure {
                    value: relay_value,
                    name: "totals.RTP.packets".to_string(),
                });
                a.note = Some(
                    "the relay holds this call but this capture measured no RTP for it; \
                     widen the capture filter to include the media"
                        .to_string(),
                );
                a
            }
            CompareOutcome::RelayDoesNotHoldCall { sipnab_value } => {
                let mut a = base("relay_does_not_hold_call");
                a.sipnab_measured = Some(sipnab_value);
                a
            }
            CompareOutcome::NeitherSide => base("neither"),
        }
    }
}

#[cfg(test)]
mod query_relay_view_tests {
    use super::*;
    use crate::relay::types::{CallView, ControlReply, RelayStream, RelayTag};

    /// The address a query answer echoes. A literal, so no test depends on
    /// anything an operator configured.
    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:22222".parse().expect("a literal address")
    }

    /// Run tags through the conversion `query_relay` actually performs.
    ///
    /// Driven through `from_reply` rather than over the wire because
    /// `query_relay` TRANSMITS and cannot run against a stock test server --
    /// the same reason it sits in `SCHEMA_NOT_DRIVEN`. Every test here
    /// exercises the real conversion rather than a restatement of it.
    fn view_of(tags: Vec<RelayTag>) -> Vec<RelayTagView> {
        let reply = ControlReply::Call(CallView {
            call_id: "call-1@192.0.2.10".to_string(),
            tags,
        });
        RelayAnswer::from_reply("query", addr(), &reply)
            .tags
            .expect("a query answer carries tags")
    }

    /// A leg that ALSO has media subscribed off it is still a leg.
    ///
    /// The boundary the `&&` in `is_media_subscriber` draws. A recorded call
    /// has exactly this shape: `from-tag-a` talks to `to-tag-b` AND a recorder
    /// subscribes to it. Reading "has subscriptions" as "is a subscriber" would
    /// erase the caller from their own call.
    #[test]
    fn a_leg_with_subscriptions_taken_off_it_is_still_a_leg() {
        let tags = view_of(vec![RelayTag {
            tag: "from-tag-a".to_string(),
            in_dialogue_with: vec!["to-tag-b".to_string()],
            media_subscriptions: vec!["recorder-1".to_string()],
            codec: None,
            streams: Vec::new(),
        }]);
        assert!(
            !tags[0].is_media_subscriber,
            "a tag holding a dialog is a party to the call however many things \
             subscribe to it"
        );
        assert_eq!(tags[0].media_subscriptions, vec!["recorder-1".to_string()]);
    }

    /// A tag with neither is neither.
    ///
    /// The empty case has to be decided rather than fall out. A tag the relay
    /// returned with no peer and no subscriber is a tag sipnab knows nothing
    /// about, and calling that a subscriber would invent a role for it.
    #[test]
    fn a_tag_with_no_peer_and_no_subscription_is_not_a_subscriber() {
        let tags = view_of(vec![RelayTag {
            tag: "lonely".to_string(),
            in_dialogue_with: Vec::new(),
            media_subscriptions: Vec::new(),
            codec: None,
            streams: Vec::new(),
        }]);
        assert!(
            !tags[0].is_media_subscriber,
            "knowing nothing about a tag is not the same as knowing it subscribes"
        );
    }

    /// Both fields reach the wire, not merely the struct.
    ///
    /// A field that exists in Rust and is skipped by serde is invisible to the
    /// agent this whole change is for. The struct compiling proves nothing
    /// about what a caller receives.
    #[test]
    fn the_subscription_facts_are_serialized_not_merely_stored() {
        let tags = view_of(vec![RelayTag {
            tag: "recorder-1".to_string(),
            in_dialogue_with: Vec::new(),
            media_subscriptions: vec!["from-tag-a".to_string()],
            codec: None,
            streams: Vec::new(),
        }]);
        let wire = serde_json::to_value(&tags[0]).expect("serializes");
        assert_eq!(
            wire.get("is_media_subscriber"),
            Some(&serde_json::json!(true)),
            "the flag must reach the caller: {wire}"
        );
        assert_eq!(
            wire.get("media_subscriptions"),
            Some(&serde_json::json!(["from-tag-a"])),
            "and so must the list it rests on: {wire}"
        );
    }

    /// A client validating against the declared schema can see them.
    ///
    /// `query_relay` publishes an `outputSchema`, and a schema that omits a
    /// field a client is expected to read is a promise broken quietly --
    /// validation passes while the client has no idea the field exists.
    #[test]
    fn the_declared_schema_names_both_subscription_fields() {
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(RelayAnswer))
            .expect("the output schema serializes");
        let text = schema.to_string();
        for field in ["media_subscriptions", "is_media_subscriber"] {
            assert!(
                text.contains(field),
                "the published schema omits {field}, so a client validating \
                 against it cannot know to read it"
            );
        }
    }

    /// Every subscriber is listed, not just the first.
    ///
    /// Forking makes more than one. A view that carried only the first would be
    /// wrong in exactly the deployment this field exists for.
    #[test]
    fn every_subscriber_of_one_leg_is_listed() {
        let tags = view_of(vec![RelayTag {
            tag: "from-tag-a".to_string(),
            in_dialogue_with: vec!["to-tag-b".to_string()],
            media_subscriptions: vec!["rec-1".to_string(), "fork-2".to_string()],
            codec: None,
            streams: Vec::new(),
        }]);
        assert_eq!(
            tags[0].media_subscriptions,
            vec!["rec-1".to_string(), "fork-2".to_string()]
        );
    }

    /// A subscriber's PORTS still reach the caller.
    ///
    /// The seam attributes a fork's port to its call deliberately -- refusing
    /// it would leave real relay media unexplained. Reclassifying the tag must
    /// not quietly drop the ports with it, or the agent trades one wrong answer
    /// for a missing one.
    #[test]
    fn a_subscribers_ports_are_still_reported() {
        let tags = view_of(vec![RelayTag {
            tag: "recorder-1".to_string(),
            in_dialogue_with: Vec::new(),
            media_subscriptions: vec!["from-tag-a".to_string()],
            codec: None,
            streams: vec![RelayStream {
                local_address: "192.0.2.10".to_string(),
                local_port: 30000,
                endpoint: None,
                advertised_endpoint: None,
                is_rtcp: false,
                ssrcs: vec![1],
            }],
        }]);
        assert!(tags[0].is_media_subscriber);
        assert_eq!(
            tags[0].streams.len(),
            1,
            "a subscriber's media is real and must still be visible"
        );
        assert_eq!(tags[0].streams[0].local_port, 30000);
    }

    /// The view does not keep a second copy of the seam's rule.
    ///
    /// `is_media_subscriber` must be the seam's own answer, not a predicate
    /// re-derived here that agrees today. Two copies of one rule are two
    /// chances to disagree, and the disagreement is silent.
    #[test]
    fn the_view_reports_the_seams_own_verdict() {
        for (dialog, subs) in [
            (vec![], vec!["x".to_string()]),
            (vec!["y".to_string()], vec!["x".to_string()]),
            (vec!["y".to_string()], vec![]),
            (vec![], vec![]),
        ] {
            let tag = RelayTag {
                tag: "t".to_string(),
                in_dialogue_with: dialog.clone(),
                media_subscriptions: subs.clone(),
                codec: None,
                streams: Vec::new(),
            };
            let expected = tag.is_media_subscriber();
            let tags = view_of(vec![tag]);
            assert_eq!(
                tags[0].is_media_subscriber, expected,
                "the view disagreed with the seam for dialog={dialog:?} subs={subs:?}"
            );
        }
    }

    /// An enumeration answer is unaffected.
    ///
    /// `list` returns Call-IDs and no tags. A change to the tag view must not
    /// have grown a tags array onto the shape that has none.
    #[test]
    fn an_enumeration_answer_still_carries_no_tags() {
        let reply = ControlReply::Calls(crate::relay::types::Enumeration {
            call_ids: vec!["call-1@192.0.2.10".to_string()],
            truncated: false,
        });
        let answer = RelayAnswer::from_reply("list", addr(), &reply);
        assert!(answer.tags.is_none(), "a list answer has no tags to carry");
        assert_eq!(answer.outcome, "calls");
    }

    /// A refusal is unaffected.
    ///
    /// The relay was reached and declined. That is not a call view, and must
    /// not acquire one.
    #[test]
    fn a_refusal_still_carries_no_tags() {
        let reply = ControlReply::Refused {
            reason: "unknown call-id".to_string(),
        };
        let answer = RelayAnswer::from_reply("query", addr(), &reply);
        assert!(answer.tags.is_none());
        assert_eq!(answer.outcome, "refused");
        assert_eq!(answer.refusal.as_deref(), Some("unknown call-id"));
    }

    /// A subscriber reaches the agent as a subscriber, not as the other end.
    ///
    /// The seam separates offer/answer peers from media SUBSCRIBERS, because a
    /// relay lets one side receive another's media without being party to the
    /// call -- which is how relay-side recording and forking are built. That
    /// separation is worth nothing if the tool that answers agents folds them
    /// back together: an agent asked "who is on this call" would be told a
    /// recorder is, and a two-party conversation would come back with three
    /// parties.
    ///
    /// Driven through `from_reply` rather than over the wire because
    /// `query_relay` TRANSMITS and cannot run against a stock test server --
    /// the same reason it sits in `SCHEMA_NOT_DRIVEN`. This is the conversion
    /// that surface performs, exercised directly.
    #[test]
    fn a_media_subscriber_is_not_published_as_a_dialogue_peer() {
        let leg = RelayTag {
            tag: "from-tag-a".to_string(),
            in_dialogue_with: vec!["to-tag-b".to_string()],
            media_subscriptions: Vec::new(),
            codec: Some("PCMU".to_string()),
            streams: Vec::new(),
        };
        // A fork or recorder: it receives the leg's media and holds no dialog.
        let recorder = RelayTag {
            tag: "recorder-1".to_string(),
            in_dialogue_with: Vec::new(),
            media_subscriptions: vec!["from-tag-a".to_string()],
            codec: None,
            streams: Vec::new(),
        };
        let reply = ControlReply::Call(CallView {
            call_id: "call-1@192.0.2.10".to_string(),
            tags: vec![leg, recorder],
        });

        let answer = RelayAnswer::from_reply(
            "query",
            "127.0.0.1:22222".parse().expect("a literal address"),
            &reply,
        );
        let tags = answer.tags.expect("a query answer carries tags");

        assert!(
            !tags[0].is_media_subscriber,
            "a tag holding an offer/answer dialog is a leg: {:?}",
            tags[0].tag
        );
        assert_eq!(tags[0].in_dialogue_with, vec!["to-tag-b".to_string()]);
        assert!(
            tags[0].media_subscriptions.is_empty(),
            "a leg that nothing subscribes to must list no subscriptions"
        );

        assert!(
            tags[1].is_media_subscriber,
            "a tag that only subscribes is not a party to the call"
        );
        assert!(
            tags[1].in_dialogue_with.is_empty(),
            "a subscriber must NOT appear as the other end -- that is the whole \
             defect: it turns a two-party call into a three-party one"
        );
        assert_eq!(
            tags[1].media_subscriptions,
            vec!["from-tag-a".to_string()],
            "and the agent must still be able to see WHOSE media it receives"
        );
    }

    /// Every delivery-trust level explains itself, distinctly and in terms an
    /// operator can act on.
    ///
    /// The ordering is strongest to weakest and an incident review reads it
    /// that way, so the sentences have to differ: two levels sharing one
    /// explanation would tell a reviewer that an authenticated assertion and a
    /// port-gated one are the same fact. `PortGatedOnly` is the one that must
    /// state its own weakness, because it is the residual sipnab pins rather
    /// than pretends away.
    #[test]
    fn every_delivery_trust_level_explains_itself_distinctly() {
        let all = [
            DeliveryTrust::Asked,
            DeliveryTrust::HmacVerified,
            DeliveryTrust::PlainSecret,
            DeliveryTrust::PortGatedOnly,
            DeliveryTrust::NotRelayAsserted,
        ];
        let texts: Vec<&str> = all.iter().map(|t| t.explain()).collect();
        let unique: std::collections::BTreeSet<&&str> = texts.iter().collect();
        assert_eq!(
            unique.len(),
            texts.len(),
            "two trust levels share an explanation: {texts:?}"
        );
        for (level, text) in all.iter().zip(&texts) {
            assert!(
                text.len() > 40,
                "{level:?} explains itself in {} characters, which is not an \
                 instruction to anybody",
                text.len()
            );
        }
        assert!(
            DeliveryTrust::PortGatedOnly
                .explain()
                .contains("NOT authenticated"),
            "the weakest level must say so in its own sentence: {}",
            DeliveryTrust::PortGatedOnly.explain()
        );
        assert!(
            DeliveryTrust::NotRelayAsserted.explain().contains("SDP"),
            "and the one that is not a relay statement must say whose claim it is"
        );
    }

    /// A pointer nobody can resolve answers `unresolvable`, with the reason and
    /// nothing invented around it.
    ///
    /// Every optional field stays empty. A decode answer carrying a `command`
    /// or a `call_id` beside `unresolvable` would read as a partial decode --
    /// as though sipnab had got some of the message -- when it got none of it.
    #[test]
    fn an_unresolvable_pointer_carries_its_reason_and_nothing_else() {
        let d = ng_unresolvable("capture.pcap#7@deadbeef", "no such frame".to_string());
        assert_eq!(d.status, "unresolvable");
        assert_eq!(d.pointer, "capture.pcap#7@deadbeef");
        assert_eq!(d.reason.as_deref(), Some("no such frame"));
        assert_eq!(d.schema_version, 1);
        assert!(d.source.is_none(), "no source is claimed");
        assert!(d.ordinal.is_none(), "no ordinal is claimed");
        assert!(d.delivery.is_none(), "no delivery path is claimed");
        assert!(d.delivery_trust.is_none(), "and no trust in one");
        assert!(d.command.is_none() && d.call_id.is_none());
        assert!(!d.has_sdp, "and nothing about a body it never read");
        assert!(d.sdp_bytes.is_none());
    }

    /// A decoded control message reports the path it arrived on, and the note
    /// that says what that path is worth.
    ///
    /// The two delivery paths are not interchangeable: HEP-encapsulated came
    /// from a relay that chose to send it, and a bare datagram was sniffed off
    /// the wire. An answer that collapsed them would hide which of the two an
    /// operator is looking at.
    #[test]
    fn a_decoded_control_message_reports_its_delivery_and_what_it_is_worth() {
        let decoded = decoded_control(crate::relay::ControlDelivery::Encapsulated, Some(120));
        let d = describe_control_message(
            "cap.pcap#3@abc",
            "decoded",
            "cap.pcap",
            3,
            DeliveryTrust::HmacVerified,
            &decoded,
        );
        assert_eq!(d.status, "decoded");
        assert_eq!(d.source.as_deref(), Some("cap.pcap"));
        assert_eq!(d.ordinal, Some(3));
        assert!(matches!(d.delivery, Some(NgDelivery::Hep)));
        assert_eq!(d.delivery_trust, Some(DeliveryTrust::HmacVerified));
        assert_eq!(
            d.delivery_note.as_deref(),
            Some(DeliveryTrust::HmacVerified.explain()),
            "the note is the trust level's own sentence, not a second wording \
             of it that could drift"
        );
        assert!(d.has_sdp, "120 bytes of SDP is SDP");
        assert_eq!(d.sdp_bytes, Some(120));
        assert!(d.reason.is_none(), "a decode that worked states no reason");
    }

    /// A bare datagram is reported as sniffed, not as something a relay sent.
    #[test]
    fn a_bare_datagram_is_reported_as_sniffed_rather_than_sent() {
        let decoded = decoded_control(crate::relay::ControlDelivery::BareDatagram, None);
        let d = describe_control_message(
            "cap.pcap#9@abc",
            "decoded",
            "cap.pcap",
            9,
            DeliveryTrust::PortGatedOnly,
            &decoded,
        );
        assert!(
            matches!(d.delivery, Some(NgDelivery::SniffedUdp)),
            "a datagram sipnab picked up off the wire is not a relay's \
             statement to it"
        );
        assert!(!d.has_sdp, "no SDP bytes means no SDP");
        assert!(d.sdp_bytes.is_none(), "and no count is invented for it");
        assert_eq!(
            d.delivery_note.as_deref(),
            Some(DeliveryTrust::PortGatedOnly.explain())
        );
    }

    /// A decoded control message for the tests above.
    fn decoded_control(
        delivery: crate::relay::ControlDelivery,
        sdp_bytes: Option<usize>,
    ) -> crate::relay::DecodedControl {
        crate::relay::DecodedControl {
            delivery,
            on_believed_mirror_port: Some(true),
            correlation_id: Some("corr-1".to_string()),
            message: crate::relay::ControlMessage {
                command: Some("offer".to_string()),
                call_id: Some("call-1@example.invalid".to_string()),
                sdp_bytes,
            },
        }
    }

    /// Every reason an unexplained stream can carry, driven directly.
    ///
    /// The three arms are what `reconcile_orphans` tells an operator when it
    /// cannot attach media to a call, and the distinction between them is the
    /// whole value of the tool: "a relay named this endpoint but no dialog
    /// claims it" sends someone to look for missing signaling, while "nothing
    /// named it" says the capture never saw an explanation at all. Getting one
    /// arm wrong points the investigation at the wrong half of the estate.
    ///
    /// Driven through a free function rather than through the async handler,
    /// for the reason `classify` above is free: the handler needs a server, a
    /// store and a live capture, and none of that is required to state which
    /// reason belongs to which assertion.
    #[test]
    fn each_kind_of_unexplained_stream_gets_its_own_reason() {
        use crate::rtp::stream_store::EndpointAssertion;

        assert_eq!(
            // Whichever relay: this test is about the orphan reason, and
            // naming one here would make a rule about attributions look like
            // a rule about one vendor.
            orphan_reason(Some(EndpointAssertion::media_relay(
                crate::relay::RelayImplementation::default(),
                crate::relay::ControlDelivery::BareDatagram,
            ))),
            OrphanReason::RelayAssertedButNoDialog,
            "a relay named the endpoint, so the signaling is what is missing"
        );
        assert_eq!(
            orphan_reason(Some(EndpointAssertion::Signaled)),
            OrphanReason::SignaledButNoDialog,
            "an SDP body named it, so a dialog was dropped or arrived before \
             capture started"
        );
        assert_eq!(
            orphan_reason(None),
            OrphanReason::NeverNamed,
            "nothing named it: an absence of evidence, which must not be \
             reported as a relay having answered"
        );
    }

    /// Each reason explains itself in terms an operator can act on, and no two
    /// explanations are the same sentence.
    ///
    /// Three identical strings would satisfy the mapping test above while
    /// telling the reader nothing, which is the failure mode of a classifier
    /// whose labels were copied.
    #[test]
    fn every_orphan_reason_explains_itself_distinctly() {
        let all = [
            OrphanReason::RelayAssertedButNoDialog,
            OrphanReason::SignaledButNoDialog,
            OrphanReason::NeverNamed,
        ];
        let explanations: Vec<&str> = all.iter().map(|r| r.explain()).collect();
        for (reason, text) in all.iter().zip(&explanations) {
            assert!(
                text.len() > 30,
                "{reason:?} explains itself in {} characters, which is not an \
                 instruction to anybody",
                text.len()
            );
        }
        let unique: std::collections::BTreeSet<&&str> = explanations.iter().collect();
        assert_eq!(
            unique.len(),
            explanations.len(),
            "two reasons share an explanation, so the distinction the caller \
             was given is not visible to the reader: {explanations:?}"
        );
    }
}

#[cfg(test)]
mod relay_stats_view_tests {
    use super::*;
    use crate::relay::types::ControlReply;
    use crate::stats_vocab::ready_comparison;

    /// The address a stats answer echoes -- a literal, so no test depends on
    /// anything an operator configured.
    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:22222".parse().expect("a literal address")
    }

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// A global stats reply is `ok`, tiered `relay_reported`, and carries the
    /// relay's counters verbatim -- a counted zero included, never dropped.
    ///
    /// Driven through `from_reply` rather than over the wire because relay_stats
    /// TRANSMITS and cannot run against a stock test server, the same reason
    /// query_relay's conversion is tested directly.
    #[test]
    fn a_global_reply_is_ok_and_carries_the_relays_counters() {
        let reply = ControlReply::Statistics(pairs(&[
            ("totals.RTP.packets", "9000"),
            ("totals.RTP.bytes", "0"),
        ]));
        let a = RelayStatsAnswer::from_reply(addr(), &reply, None, false);
        assert_eq!(a.outcome, "ok");
        assert_eq!(a.tier, "relay_reported");
        let stats = a.statistics.expect("a values answer carries statistics");
        assert_eq!(stats.len(), 2);
        let zero = stats
            .iter()
            .find(|s| s.name == "totals.RTP.bytes")
            .expect("the zero counter must survive, not be dropped");
        assert_eq!(zero.value, "0", "a counted zero is a value, not an absence");
        assert!(a.names.is_none(), "a values answer names nothing");
        assert!(a.refusal.is_none());
        assert_eq!(a.delivery_trust, DeliveryTrust::Asked);
    }

    /// `names_only` returns the names the relay knows, the source token, and the
    /// sentence that says how the set was determined -- so a probed set is never
    /// read as a definitive enumeration.
    #[test]
    fn a_names_only_reply_lists_names_with_their_source_and_note() {
        let reply = ControlReply::Statistics(pairs(&[
            ("totals.RTP.packets", "9000"),
            ("totals.RTP.bytes", "12"),
        ]));
        let a = RelayStatsAnswer::from_reply(addr(), &reply, None, true);
        assert_eq!(a.outcome, "ok");
        let names = a.names.expect("a names answer carries names");
        assert!(names.contains(&"totals.RTP.packets".to_string()));
        assert_eq!(a.names_source.as_deref(), Some("listed"));
        assert!(
            a.names_note.unwrap_or("").len() > 20,
            "the names note must state how the set was determined"
        );
        assert!(a.statistics.is_none(), "a names answer carries no values");
    }

    /// A per-call reply that is the relay's own no (`result: error`) is
    /// `refused`, carrying the relay's reason verbatim -- never rendered as
    /// counters.
    #[test]
    fn a_per_call_result_error_is_refused_with_the_relays_reason() {
        let reply = ControlReply::Statistics(pairs(&[
            ("result", "error"),
            ("error-reason", "Unknown call-id"),
        ]));
        let a = RelayStatsAnswer::from_reply(addr(), &reply, Some("nope@host"), false);
        assert_eq!(a.outcome, "refused");
        assert_eq!(a.refusal.as_deref(), Some("Unknown call-id"));
        assert!(
            a.statistics.is_none(),
            "a refusal must not be rendered as counters"
        );
    }

    /// The refusal check is applied ONLY to a per-call ask, matching REST: a
    /// GLOBAL reply that happens to carry a `result` key is rendered as counters,
    /// not read as a refusal. The `call_id` argument is what draws that line.
    #[test]
    fn the_refusal_check_is_scoped_to_a_per_call_ask() {
        let reply = ControlReply::Statistics(pairs(&[("result", "error")]));
        let global = RelayStatsAnswer::from_reply(addr(), &reply, None, false);
        assert_eq!(
            global.outcome, "ok",
            "a global ask does not apply the per-call refusal rule"
        );
        let per_call = RelayStatsAnswer::from_reply(addr(), &reply, Some("c@h"), false);
        assert_eq!(
            per_call.outcome, "refused",
            "the same reply on a per-call ask IS a refusal"
        );
    }

    /// A reply that is not statistics at all is `suspect` -- an answer arrived,
    /// and it cannot be trusted as counters.
    ///
    /// The stats path's decoder returns only `Statistics` or an error, so this
    /// is the defensive fallback for a shape the current client never produces;
    /// it is asserted so a future decoder that could cannot silently pass a
    /// non-statistics reply off as `ok`.
    #[test]
    fn a_non_statistics_reply_is_suspect() {
        let reply = ControlReply::Refused {
            reason: "unexpected on the stats path".to_string(),
        };
        let a = RelayStatsAnswer::from_reply(addr(), &reply, None, false);
        assert_eq!(a.outcome, "suspect");
        assert!(a.statistics.is_none());
    }

    /// A comparison shows both figures with their tiers and a word verdict, and
    /// never a summed or differenced field -- the two counts are shown, not
    /// combined.
    #[test]
    fn a_comparison_shows_both_sides_and_a_word_verdict() {
        let differ = RelayCompareAnswer::from_outcome(
            addr(),
            "c@h",
            ready_comparison(Some(9000), Some(4500)),
        );
        assert_eq!(differ.outcome, "compared");
        assert_eq!(differ.verdict.as_deref(), Some("differ"));
        assert_eq!(differ.relay_reported.as_ref().map(|f| f.value), Some(9000));
        assert_eq!(differ.sipnab_measured, Some(4500));
        assert!(
            differ.note.unwrap_or_default().len() > 20,
            "a differ verdict must carry the note that a gap is not a relay fault"
        );
        let same = RelayCompareAnswer::from_outcome(
            addr(),
            "c@h",
            ready_comparison(Some(9000), Some(9000)),
        );
        assert_eq!(same.verdict.as_deref(), Some("match"));
    }

    /// An absent side is reported as absent, never coerced to zero: a relay that
    /// does not hold the call carries sipnab's measured count and NO relay
    /// figure, and the reverse for a call sipnab never captured.
    #[test]
    fn an_absent_side_is_never_rendered_as_zero() {
        let relay_missing =
            RelayCompareAnswer::from_outcome(addr(), "c@h", ready_comparison(None, Some(4500)));
        assert_eq!(relay_missing.outcome, "relay_does_not_hold_call");
        assert!(
            relay_missing.relay_reported.is_none(),
            "an absent relay side must not be a zero figure"
        );
        assert_eq!(relay_missing.sipnab_measured, Some(4500));

        let sipnab_missing =
            RelayCompareAnswer::from_outcome(addr(), "c@h", ready_comparison(Some(9000), None));
        assert_eq!(sipnab_missing.outcome, "sipnab_has_no_rtp");
        assert_eq!(
            sipnab_missing.relay_reported.as_ref().map(|f| f.value),
            Some(9000)
        );
        assert!(sipnab_missing.sipnab_measured.is_none());

        let neither = RelayCompareAnswer::from_outcome(addr(), "c@h", ready_comparison(None, None));
        assert_eq!(neither.outcome, "neither");
        assert!(neither.relay_reported.is_none() && neither.sipnab_measured.is_none());
    }

    /// The compare tool's own refusal and suspect constructors carry the same
    /// meaning as the stats tool: the relay's own no, and an untrusted answer.
    #[test]
    fn compare_refused_and_suspect_carry_their_meaning() {
        let refused = RelayCompareAnswer::refused(addr(), "c@h", "Unknown call-id".to_string());
        assert_eq!(refused.outcome, "refused");
        assert_eq!(refused.refusal.as_deref(), Some("Unknown call-id"));
        assert!(refused.verdict.is_none());

        let suspect = RelayCompareAnswer::suspect(addr(), "c@h");
        assert_eq!(suspect.outcome, "suspect");
        assert!(suspect.relay_reported.is_none() && suspect.sipnab_measured.is_none());
    }
}
