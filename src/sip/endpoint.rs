// SPDX-License-Identifier: MIT OR Apache-2.0

//! Everything one endpoint did, selected by ip OR user.
//!
//! Shared by the MCP `describe_endpoint` tool and the REST `/v1/endpoints`
//! route so the two surfaces read one store the same way. This module returns
//! raw data — banner text, codec tokens and dialog Call-IDs unfenced — and each
//! surface renders it: MCP fences the sender-authored strings before they reach
//! a model, REST hands a program the values it keys on.
//!
//! Security findings are NOT here. The alert engine files them against a source
//! address in a ring the REST server does not hold, so they are the separate
//! `security_findings` capability; the MCP tool adds them on top of this report.

use crate::rtp::stream::RtpStream;
use crate::rtp::stream_store::StreamStore;
use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;
use crate::sip::dialog_store::DialogStore;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;

/// Which entity a lookup is about.
///
/// A small enum rather than two `Option`s threaded through the scan: every
/// predicate differs between the two, and an `Option` pair leaves "both" and
/// "neither" representable long after they were rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// An address, matched against message and stream endpoints.
    Ip(IpAddr),
    /// A SIP URI user part, matched against dialog From/To users.
    User(String),
}

impl Selector {
    /// Read a selector from an optional ip and an optional user.
    ///
    /// # Errors
    ///
    /// A message (each surface renders it in its own error type) when neither
    /// or both are present, or when the address does not parse.
    pub fn parse(ip: Option<&str>, user: Option<&str>) -> Result<Self, String> {
        match (ip, user) {
            (Some(ip), None) => ip
                .parse::<IpAddr>()
                .map(Selector::Ip)
                .map_err(|e| format!("ip '{ip}' is not an address: {e}")),
            (None, Some(user)) => Ok(Selector::User(user.to_string())),
            (None, None) => Err("give exactly one of ip or user: an endpoint is \
                                 either an address or a URI user part, and neither \
                                 can be inferred from the other"
                .to_string()),
            (Some(_), Some(_)) => Err("give exactly one of ip or user, not both: \
                                       the two select different sets, and whether \
                                       you meant their intersection or their union \
                                       changes the answer"
                .to_string()),
        }
    }

    /// The selector's name, for the response.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::User(_) => "user",
        }
    }

    /// The selector's value, for the response.
    #[must_use]
    pub fn value(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::User(u) => u.clone(),
        }
    }

    /// Whether this dialog involves the endpoint.
    #[must_use]
    pub fn matches_dialog(&self, d: &SipDialog) -> bool {
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

    /// Whether the endpoint SENT this message. Always false for a user selector:
    /// a URI user part names a party, not a socket, and the sender of a given
    /// message is not recoverable from it.
    #[must_use]
    pub fn sent(&self, m: &SipMessage) -> bool {
        match self {
            Self::Ip(ip) => m.src_addr == *ip,
            Self::User(_) => false,
        }
    }

    /// Whether the message was addressed TO the endpoint. False for a user
    /// selector, for the reason [`Self::sent`] gives.
    #[must_use]
    pub fn received(&self, m: &SipMessage) -> bool {
        match self {
            Self::Ip(ip) => m.dst_addr == *ip,
            Self::User(_) => false,
        }
    }

    /// Whether this RTP stream belongs to the endpoint. An address matches the
    /// media 5-tuple directly. A user has no media identity of its own, so its
    /// streams are the ones linked to its dialogs.
    #[must_use]
    pub fn matches_stream(&self, s: &RtpStream, call_ids: &HashSet<&str>) -> bool {
        match self {
            Self::Ip(ip) => s.key.src.ip() == *ip || s.key.dst.ip() == *ip,
            Self::User(_) => s
                .associated_dialog
                .as_deref()
                .is_some_and(|id| call_ids.contains(id)),
        }
    }
}

/// A `User-Agent` or `Server` banner an endpoint sent, and how often. RAW value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointBanner {
    /// The header that carried it — `User-Agent` on a request, `Server` on a
    /// response, kept apart because they name different roles.
    pub header: String,
    /// The banner text, as the sender wrote it (unfenced).
    pub value: String,
    /// Messages carrying it.
    pub count: usize,
}

/// INVITE outcomes for an endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct CallOutcomes {
    /// INVITE dialogs involving the endpoint.
    pub invites: usize,
    /// Of those, how many reached a final INVITE response.
    pub with_final_status: usize,
    /// Of those, how many ended 4xx, 5xx or 6xx.
    pub failed: usize,
    /// `failed` over `with_final_status`, as a percent. `None` when nothing has
    /// reached a final status — a zero there would report a perfect endpoint on
    /// a capture holding no completed call.
    pub failure_rate_pct: Option<f64>,
    /// Count per final INVITE status code.
    pub by_final_status: BTreeMap<String, usize>,
}

/// REGISTER activity for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// False when the endpoint sent no REGISTER at all.
    pub applicable: bool,
    /// Dialogs carrying a REGISTER request.
    pub dialogs: usize,
    /// Of those, how many drew a 2xx.
    pub succeeded: usize,
    /// Of those, how many the diagnosis calls a registration failure.
    pub failed: usize,
    /// Of those, how many are looping on authentication.
    pub auth_loops: usize,
    /// Call-IDs of the REGISTER dialogs that failed or looped, bounded by limit.
    pub problem_call_ids: Vec<String>,
}

/// RTP an endpoint sent or received. Codecs are RAW (a surface that fences does
/// so itself).
#[derive(Debug, Clone, PartialEq)]
pub struct EndpointStreams {
    /// Streams attributed to the endpoint.
    pub count: usize,
    /// Of those, how many are not linked to any dialog.
    pub orphaned: usize,
    /// Total RTP packets across them.
    pub packets: u64,
    /// Total packets the sequence gaps say were lost.
    pub lost_packets: u64,
    /// Worst interarrival jitter seen on any of them, milliseconds.
    pub max_jitter_ms: Option<f64>,
    /// Codecs observed, sorted, unfenced.
    pub codecs: Vec<String>,
}

/// Everything one endpoint did, computed in one pass. Raw: a rendering surface
/// fences the banner values, the codec tokens and the recent dialogs itself.
#[derive(Debug, Clone)]
pub struct EndpointReport {
    /// The selector kind, `ip` or `user`.
    pub kind: &'static str,
    /// The selector value.
    pub value: String,
    /// Dialogs the endpoint took part in.
    pub dialogs: usize,
    /// Dialog count per method.
    pub by_method: BTreeMap<String, usize>,
    /// Dialog count per state.
    pub by_state: BTreeMap<String, usize>,
    /// Messages the endpoint SENT (zero for a user lookup).
    pub messages_sent: usize,
    /// Messages addressed TO the endpoint (zero for a user lookup).
    pub messages_received: usize,
    /// Banners the endpoint sent, most frequent first, raw.
    pub banners: Vec<EndpointBanner>,
    /// Call outcomes.
    pub calls: CallOutcomes,
    /// Registration state.
    pub registration: Registration,
    /// Which signaling stack built the endpoint's requests.
    pub stack: crate::sip::stack_fingerprint::StackFingerprint,
    /// Whether a private `Contact` this endpoint registered was rewritten.
    pub contact_rewrite: Option<crate::sip::contact_rewrite::ContactRewriteFinding>,
    /// Media attributed to the endpoint.
    pub streams: EndpointStreams,
    /// Call-IDs of the most recent dialogs, newest first, bounded by `limit`,
    /// for the caller to render summaries from.
    pub recent_call_ids: Vec<String>,
    /// True when `dialogs` exceeds `recent_call_ids.len()`.
    pub truncated: bool,
}

/// The RTP an endpoint sent or received, raw codecs.
///
/// An address matches the media 5-tuple. A user has no media identity, so its
/// streams are the ones linked to its dialogs — which is why the matched
/// Call-IDs are passed in.
#[must_use]
pub fn endpoint_streams(
    ss: &StreamStore,
    selector: &Selector,
    call_ids: &HashSet<&str>,
) -> EndpointStreams {
    let mut out = EndpointStreams {
        count: 0,
        orphaned: 0,
        packets: 0,
        lost_packets: 0,
        max_jitter_ms: None,
        codecs: Vec::new(),
    };
    let mut codecs: BTreeSet<String> = BTreeSet::new();
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
    out.codecs = codecs.into_iter().collect();
    out
}

/// Everything one endpoint did, in one pass over the store. Findings excluded —
/// a caller that has the alert ring adds them.
#[must_use]
pub fn describe(
    ds: &DialogStore,
    ss: &StreamStore,
    selector: &Selector,
    limit: usize,
) -> EndpointReport {
    let mut dialogs: Vec<&SipDialog> = Vec::new();
    let mut by_method: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
    let mut messages_sent = 0usize;
    let mut messages_received = 0usize;
    let mut banners: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut stack = crate::sip::stack_fingerprint::FingerprintAccumulator::default();
    // The first REGISTER observation, the address it arrived from, and the AoR
    // it registered. The AoR is the tie the corroboration needs: a request
    // misrouted to the private `Contact` carries no address belonging to this
    // endpoint, so only the registered user in its request URI and `To` can
    // find it.
    let mut contact_observation: Option<(
        crate::sip::contact_rewrite::ContactObservation,
        IpAddr,
        Option<String>,
    )> = None;

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
                if let Some((header, value)) = crate::sip::talkers::banner_of(m) {
                    *banners.entry((header, value)).or_insert(0) += 1;
                }
                // REQUESTS only. A response echoes the request's branch, `From`
                // tag and Call-ID verbatim, so reading one would fingerprint the
                // party that SENT the request as if it had answered.
                if m.is_request {
                    stack.observe(
                        m.top_via_branch().unwrap_or_default(),
                        m.from_tag().unwrap_or_default(),
                        m.call_id().unwrap_or_default(),
                    );
                    // The FIRST REGISTER this endpoint sent. A later one may
                    // carry a Contact the endpoint learned from a 200 OK, and
                    // reading that would report the cure as the disease.
                    if m.method == Some(crate::sip::method::SipMethod::Register)
                        && contact_observation.is_none()
                    {
                        contact_observation = Some((
                            crate::sip::contact_rewrite::observe(
                                m.contact()
                                    .and_then(crate::sip::contact_rewrite::contact_host),
                                m.src_addr,
                            ),
                            m.src_addr,
                            m.to_user(),
                        ));
                    }
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

        // Keyed off the REQUEST rather than off `d.method`: a REGISTER can
        // arrive inside a dialog opened by something else once Call-ID reuse is
        // in play, and a registration that is not examined reports as healthy.
        let registers = d
            .messages
            .iter()
            .any(|m| m.is_request && m.method == Some(crate::sip::method::SipMethod::Register));
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

    // Newest first: an operator chasing a complaint wants what just happened.
    dialogs.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.call_id.cmp(&b.call_id))
    });
    let matched_call_ids: HashSet<&str> = dialogs.iter().map(|d| d.call_id.as_str()).collect();
    let streams = endpoint_streams(ss, selector, &matched_call_ids);

    // The conjunction. `rewrite_required` is the observation and is true for
    // three quarters of a healthy estate; what settles it is which address the
    // rest of the estate then used.
    let contact_rewrite = contact_observation.map(|(o, registered_from, aor)| {
        let contact_addr = o
            .contact_host
            .as_deref()
            .and_then(crate::sip::contact_rewrite::host_address);
        let mut to_contact = 0usize;
        let mut to_source = 0usize;
        // A second pass, over EVERY dialog rather than this endpoint's. Only
        // reached when a REGISTER was seen, and the only pass that can see a
        // request the registrar addressed somewhere this endpoint never was.
        if let Some(aor) = aor.as_deref() {
            for d in ds.iter() {
                for m in &d.messages {
                    if !m.is_request || m.method == Some(crate::sip::method::SipMethod::Register) {
                        continue;
                    }
                    // RFC 3261 §19.1.4 makes the user part case-sensitive, so
                    // `Alice` and `alice` are two URIs and folding them would
                    // attribute one endpoint's traffic to another.
                    if m.to_user().as_deref() != Some(aor) {
                        continue;
                    }
                    if Some(m.dst_addr) == contact_addr {
                        to_contact += 1;
                    } else if m.dst_addr == registered_from {
                        to_source += 1;
                    }
                    // Anything else went to a third address — a proxy, another
                    // leg — and says nothing about whether the registrar
                    // rewrote.
                }
            }
        }
        crate::sip::contact_rewrite::corroborate(o, to_contact, to_source)
    });

    let mut banner_rows: Vec<EndpointBanner> = banners
        .into_iter()
        .map(|((header, value), count)| EndpointBanner {
            header,
            value,
            count,
        })
        .collect();
    banner_rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));

    let total_dialogs = dialogs.len();
    let recent_call_ids: Vec<String> = dialogs
        .iter()
        .take(limit)
        .map(|d| d.call_id.clone())
        .collect();

    EndpointReport {
        kind: selector.kind(),
        value: selector.value(),
        dialogs: total_dialogs,
        by_method,
        by_state,
        messages_sent,
        messages_received,
        banners: banner_rows,
        calls: CallOutcomes {
            invites,
            with_final_status,
            failed,
            failure_rate_pct: (with_final_status > 0)
                .then(|| (failed as f64 / with_final_status as f64) * 100.0),
            by_final_status,
        },
        registration: Registration {
            applicable: reg_dialogs > 0,
            dialogs: reg_dialogs,
            succeeded: reg_succeeded,
            failed: reg_failed,
            auth_loops: reg_auth_loops,
            problem_call_ids: reg_problem_ids,
        },
        stack: stack.finish(),
        contact_rewrite,
        streams,
        truncated: total_dialogs > recent_call_ids.len(),
        recent_call_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use chrono::{TimeZone, Utc};
    use std::net::Ipv4Addr;

    fn ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Ingest one INVITE (from `src`) and its final response into a store.
    fn store_with_invite(src: IpAddr, dst: IpAddr, final_code: u16, ua: &str) -> DialogStore {
        let mut ds = DialogStore::new(1000, true);
        let inv = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: ep-1@h",
                "CSeq: 1 INVITE",
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        ds.process_message(
            parse_sip(&inv, ts(), src, dst, 5060, 5060, TransportProto::Udp).expect("parse"),
        );
        let rsp = build_sip(
            &format!("SIP/2.0 {final_code} X"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: ep-1@h",
                "CSeq: 1 INVITE",
                &format!("Server: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        ds.process_message(
            parse_sip(&rsp, ts(), dst, src, 5060, 5060, TransportProto::Udp).expect("parse"),
        );
        ds
    }

    /// By ip, the report attributes the INVITE the address SENT, its banner
    /// raw, its messages-sent, and its failed outcome — and it is the sender's
    /// address, not the destination's, that selects.
    #[test]
    fn describe_by_ip_attributes_what_the_sender_did() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let ds = store_with_invite(a, b, 486, "Sipnabophone/9");
        let ss = StreamStore::new(100);
        let r = describe(&ds, &ss, &Selector::Ip(a), 50);

        assert_eq!(r.kind, "ip");
        assert_eq!(r.dialogs, 1);
        assert_eq!(r.by_method.get("INVITE"), Some(&1));
        assert_eq!(r.messages_sent, 1, "the INVITE it sent");
        assert_eq!(r.messages_received, 1, "the response it received");
        assert_eq!(r.calls.invites, 1);
        assert_eq!(r.calls.failed, 1, "486 is a failure");
        assert_eq!(r.calls.failure_rate_pct, Some(100.0));
        // The banner is raw here; the MCP surface fences it.
        assert_eq!(r.banners[0].value, "Sipnabophone/9");
        assert_eq!(r.recent_call_ids, vec!["ep-1@h".to_string()]);
    }

    /// A selector is exactly one of ip or user. Neither and both are refused,
    /// and a malformed address is named.
    #[test]
    fn selector_demands_exactly_one() {
        assert!(matches!(
            Selector::parse(Some("192.0.2.1"), None),
            Ok(Selector::Ip(_))
        ));
        assert!(matches!(
            Selector::parse(None, Some("alice")),
            Ok(Selector::User(_))
        ));
        assert!(Selector::parse(None, None).is_err());
        assert!(Selector::parse(Some("192.0.2.1"), Some("alice")).is_err());
        assert!(Selector::parse(Some("not-an-ip"), None).is_err());
    }

    /// A user selector names a URI, not a socket, so it reports no messages sent
    /// or received — a count derived from something else under that name would
    /// be worse than zero.
    #[test]
    fn a_user_selector_has_no_socket_side() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let ds = store_with_invite(a, b, 200, "UA/1");
        let ss = StreamStore::new(100);
        let r = describe(&ds, &ss, &Selector::User("alice".to_string()), 50);
        assert_eq!(r.kind, "user");
        assert_eq!(r.dialogs, 1, "alice is the From user");
        assert_eq!(r.messages_sent, 0, "a user has no socket");
        assert_eq!(r.messages_received, 0);
    }
}
