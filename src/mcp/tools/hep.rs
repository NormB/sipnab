// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// The most rows each list (senders, refused sources) may carry. Omitted
    /// or 0, the server's row cap. The totals beside each list always count
    /// everything.
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
                       a note. Every value is sipnab's own count; nothing in \
                       it is packet content. Same bytes as GET \
                       /v1/hep/senders.",
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
        // `Json`, so both serialize it the same way and one roster is one
        // byte sequence on both doors.
        let report = crate::capture::hep_roster::senders_report(
            self.capture_meter.as_ref().and_then(|m| m.hep_roster()),
            limit,
        );
        Ok(CallToolResult::success(vec![ContentBlock::json(report)?]))
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

    /// A server with no capture attached.
    fn server() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// A roster with senders 7 and 9 and one refused address, on a frozen
    /// clock.
    fn roster() -> HepRoster {
        let t = std::time::Instant::now();
        let mut state = RosterState::new(
            SenderTrust::SharedSecretHmac,
            64,
            std::time::Duration::from_secs(30),
            t,
            chrono::Utc::now(),
        );
        for (id, peer) in [(7u32, "192.0.2.7"), (9, "192.0.2.9")] {
            let peer: std::net::IpAddr = peer.parse().expect("literal");
            state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), t);
        }
        let bad: std::net::IpAddr = "203.0.113.66".parse().expect("literal");
        state.refused(HepRefusal::HmacBadMac, bad, t);
        HepRoster::with_clock(state, Arc::new(move || t))
    }

    /// The JSON block of a tool result.
    fn json_of(result: &CallToolResult) -> serde_json::Value {
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("a JSON block");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// Registered, and annotated read-only, so a `read`-scoped token reaches
    /// it and a host can call it without asking.
    #[test]
    fn hep_senders_is_registered_and_annotated_read_only() {
        let router = SipnabMcp::hep_router();
        let tool = router
            .get("hep_senders")
            .expect("hep_senders must be registered");
        let annotations = tool
            .annotations
            .as_ref()
            .expect("hep_senders must carry tool annotations");
        assert_eq!(annotations.read_only_hint, Some(true));
        assert!(tool.output_schema.is_some(), "it declares its output shape");
    }

    /// The tool answers with the roster the listener hung on the meter.
    #[tokio::test]
    async fn hep_senders_returns_the_listeners_roster() {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()));
        let srv = server().with_capture_meter(Some(meter));
        let body = json_of(
            &srv.hep_senders(Parameters(HepSendersParams { limit: None }))
                .await
                .expect("the tool answers"),
        );
        assert_eq!(body["listening"], true);
        assert_eq!(body["trust"], "shared_secret_hmac");
        assert_eq!(body["senders"][0]["source"], "hep:7@192.0.2.7");
        assert_eq!(body["senders"][1]["source"], "hep:9@192.0.2.9");
        assert_eq!(body["refused_sources"][0]["by_reason"]["hmac_bad_mac"], 1);
    }

    /// A row limit caps each list and not the totals.
    #[tokio::test]
    async fn hep_senders_honors_its_row_limit() {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()));
        let srv = server().with_capture_meter(Some(meter));
        let body = json_of(
            &srv.hep_senders(Parameters(HepSendersParams { limit: Some(1) }))
                .await
                .expect("the tool answers"),
        );
        assert_eq!(body["senders"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["senders_tracked"], 2);
    }

    /// **A page size never moves a roster-wide claim.** Everything but the two
    /// row lists is identical at a page of one and a page of fifty — the
    /// property `tests/population_claim_test.rs` holds for every other paging
    /// tool, driven here because only here can a roster exist.
    #[tokio::test]
    async fn a_page_size_never_moves_the_roster_totals() {
        let (_tx, rx) = crate::capture::channel::packet_channel(8);
        let meter = rx.meter();
        assert!(meter.attach_hep_roster(roster()));
        let srv = server().with_capture_meter(Some(meter));
        let at = |limit| {
            let srv = &srv;
            async move {
                json_of(
                    &srv.hep_senders(Parameters(HepSendersParams { limit: Some(limit) }))
                        .await
                        .expect("the tool answers"),
                )
            }
        };
        let mut small = at(1).await;
        let mut large = at(50).await;
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
    }

    /// No listener: `listening: false` and a note, never an empty roster.
    #[tokio::test]
    async fn hep_senders_without_a_listener_says_nothing_is_listening() {
        let body = json_of(
            &server()
                .hep_senders(Parameters(HepSendersParams { limit: None }))
                .await
                .expect("the tool answers"),
        );
        assert_eq!(body["listening"], false);
        assert!(
            body["note"]
                .as_str()
                .is_some_and(|n| n.contains("no HEP listener"))
        );
    }
}
