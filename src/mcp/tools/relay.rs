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
//! us" are both `EndpointAssertion::MediaRelay` in the store, and only the
//! delivery path separates them.
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
                let (endpoint, asserted, reason) = match named {
                    Some((a, crate::rtp::stream_store::EndpointAssertion::MediaRelay)) => (
                        Some(a.to_string()),
                        Some("media-relay".to_string()),
                        OrphanReason::RelayAssertedButNoDialog,
                    ),
                    Some((a, crate::rtp::stream_store::EndpointAssertion::Signaled)) => (
                        Some(a.to_string()),
                        Some("signaled".to_string()),
                        OrphanReason::SignaledButNoDialog,
                    ),
                    None => (None, None, OrphanReason::NeverNamed),
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
    use crate::rtp::stream_store::EndpointAssertion;
    if asserted != EndpointAssertion::MediaRelay {
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
}
