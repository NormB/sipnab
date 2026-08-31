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
