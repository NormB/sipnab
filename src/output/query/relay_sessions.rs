// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What a live relay holds, and whether media is reaching it: one snapshot.
//!
//! [`relay_sessions`] is the one function every surface asks. It sends `list`,
//! then `query` for the selected Call-ID and, on a scan, for up to `cap` of the
//! held calls, and returns a [`RelaySessions`]. `--relay-sessions` prints it,
//! `GET /v1/relay/sessions` returns its [`RelaySessions::body`], the MCP
//! `query_relay` tool carries it under `sessions`, and the TUI's relay sessions
//! view renders it with [`RelaySessions::render`].
//!
//! # What the verdicts say
//!
//! Each RTP socket of a party to the call is one direction: what the relay
//! RECEIVED there is what that party sent. [`media_verdict`] judges it from one
//! reply, on the relay's own clock, and never against sipnab's:
//!
//! - `never_received`: the socket counted 0 packets in and the relay has not
//!   marked it `confirmed`;
//! - `stalled`: its `last packet` is more than [`STALL_SECONDS`] behind the
//!   newest `last packet` of any RTP socket in the same reply;
//! - `flowing`: otherwise;
//! - `not_reported`: the counters, `last packet` or flags are absent, so the
//!   relay did not say enough to judge.
//!
//! A call with an early media branch is not judged per direction: in a
//! recorded parallel fork the answered branch's socket counted nothing while
//! that party's media was counted on the early branch's socket, so a verdict
//! per socket would call a live party silent. Its counters are shown unjudged.
//!
//! Every value is tier `relay_reported`. A value the relay did not report is
//! absent, never zero.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::output::ReportFormat;
use crate::output::relay_statistics as fmt;
use crate::relay::reconcile::ReadOnlyRelay;
use crate::relay::types::{CallView, ControlReply, RelayStream, RelayStreamFacts, StreamCounters};
use crate::security::transmit_guard::TransmitPermit;
use crate::stats_vocab::StatisticsOutcome;

/// How far, in whole seconds, a socket's `last packet` may trail the newest one
/// in the same reply before it is `stalled`.
///
/// Measured on 2026-11-04 against rtpengine 12.5.1, userspace and kernel: a
/// live socket trailed by at most 1 s in 1314 observations (the field is whole
/// seconds), and a silent socket's lag tracked its true silence within
/// 0.8 s. With 2, a stall is reported after 2.2 to 3.0 s of silence. Not
/// measured: comfort noise or silence suppression, a held call, and loss
/// bursts, each of which can make a live socket trail by more.
pub const STALL_SECONDS: i64 = 2;

/// The tier every value in a sessions answer carries.
pub const TIER: &str = "relay_reported";

/// What the answer says about a call the relay still lists after it ended.
pub const DELETE_DELAY_NOTE: &str = "a relay keeps a call it was told to delete for its \
     delete delay (30 s by default) and its answer does not mark it; a call sipnab \
     did not see end in SIP may have ended up to about 30 s ago";

/// What the answer says about the limits of `stalled`.
pub const STALL_NOTE: &str = "stalled means no packet for more than 2 s while another \
     socket of the same call received one; silence suppression, comfort noise, hold \
     and loss bursts were not measured and can also produce it";

/// What one `relay_sessions` call asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionsAsk<'a> {
    /// The Call-ID to query on every refresh, if any.
    pub selected: Option<&'a str>,
    /// Whether to query the other held calls too, up to `cap`.
    pub scan: bool,
    /// The most held calls a scan queries.
    pub cap: u32,
    /// The `limit` the `list` asks for.
    pub list_limit: u32,
    /// Set when the cap asked for was above the ceiling and was lowered to it.
    pub clamped: Option<crate::relay::scan_cap::CapClamp>,
}

impl<'a> SessionsAsk<'a> {
    /// An ask whose scan and `list` both take `cap`, the answer of
    /// [`crate::relay::scan_cap::scan_cap`], so every surface bounds its
    /// scan by the one rule and states a clamp the same way.
    #[must_use]
    pub const fn capped(
        selected: Option<&'a str>,
        scan: bool,
        cap: crate::relay::scan_cap::ScanCap,
    ) -> Self {
        Self {
            selected,
            scan,
            cap: cap.cap,
            list_limit: cap.cap,
            clamped: cap.clamped,
        }
    }
}

/// Whether media is reaching the relay on one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum MediaVerdict {
    /// Nothing has arrived: 0 packets in, and not `confirmed`.
    NeverReceived,
    /// Nothing for more than [`STALL_SECONDS`] while another socket received.
    Stalled,
    /// Packets are arriving.
    Flowing,
    /// The relay did not report enough to judge.
    NotReported,
}

impl MediaVerdict {
    /// The wire word.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::NeverReceived => "never_received",
            Self::Stalled => "stalled",
            Self::Flowing => "flowing",
            Self::NotReported => "not_reported",
        }
    }
}

/// Whether the relay forwards one socket's media in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum KernelVerdict {
    /// `kernelized`, without `no kernel support`.
    Kernel,
    /// `no kernel support`, or no `kernelized`.
    Userspace,
    /// The answer carried no flags for this socket.
    NotReported,
}

/// Whether sipnab saw the call's SIP dialog end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum SipDialog {
    /// sipnab saw the dialog reach a final state.
    Ended,
    /// sipnab did not see it end: it may be up, unknown to this capture, or
    /// ended and still in the relay's delete delay.
    NotSeenEnded,
}

/// Packets, bytes and errors, each absent when the relay did not report it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct Counters {
    /// Packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    /// Bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<u64>,
}

impl From<StreamCounters> for Counters {
    fn from(c: StreamCounters) -> Self {
        Self {
            packets: c.packets,
            bytes: c.bytes,
            errors: c.errors,
        }
    }
}

/// One relay socket, as the relay counted it. Never judged on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SessionSocket {
    /// The relay's own address for this socket.
    pub local_address: String,
    /// The relay's own port.
    pub local_port: u16,
    /// The media section, as the relay numbered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_index: Option<u32>,
    /// `rtp`, `rtcp`, or `not_reported` when the answer carried no flags.
    pub kind: String,
    /// Where the relay sends to, once it learned it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// What arrived at this socket.
    pub ingress: Counters,
    /// What the relay sent out of it.
    pub egress: Counters,
    /// When a packet last arrived, whole seconds on the relay's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_packet: Option<i64>,
    /// Kernel or userspace forwarding.
    pub kernel: KernelVerdict,
}

/// One side of the call and its sockets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SessionTag {
    /// The SIP tag.
    pub tag: String,
    /// The tags it is in an offer/answer dialog with.
    pub in_dialogue_with: Vec<String>,
    /// Whether it only receives another side's media (a recorder, a fork).
    pub is_media_subscriber: bool,
    /// Its sockets, RTP and RTCP.
    pub sockets: Vec<SessionSocket>,
}

/// The verdict for media one party sends, read at one relay RTP socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct Direction {
    /// The tag of the party that sends this media.
    pub from_tag: String,
    /// The relay socket it arrives at.
    pub local_address: String,
    /// The relay port it arrives at.
    pub local_port: u16,
    /// The media section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_index: Option<u32>,
    /// The verdict.
    pub verdict: MediaVerdict,
    /// How many seconds this socket's `last packet` trails the newest in the
    /// reply, on a `stalled` verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_packet_for_s: Option<i64>,
}

/// One queried call, as the relay answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct SessionCall {
    /// The Call-ID asked about.
    pub call_id: String,
    /// `ok`, or the classification when the relay did not answer about it:
    /// `refused`, `unreachable` or `suspect`.
    pub outcome: String,
    /// What went wrong, in the relay's own words on a refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Whether sipnab saw this call's SIP dialog end.
    pub sip_dialog: SipDialog,
    /// One verdict per direction. Empty when the call is not judged.
    pub directions: Vec<Direction>,
    /// Why the call is not judged per direction, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unjudged: Option<String>,
    /// Every side the relay holds, with its sockets' counters.
    pub tags: Vec<SessionTag>,
    /// Which engine was asked, when engine selection is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<CallEngine>,
}

/// A call the relay listed and this snapshot did not query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct NotQueried {
    /// The Call-ID.
    pub call_id: String,
    /// Whether sipnab saw its SIP dialog end.
    pub sip_dialog: SipDialog,
    /// Which engines listed it, when engine selection is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<ListedBy>,
}

/// Which engine a call was asked of, and why, when engine selection is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct CallEngine {
    /// The engine asked, or absent when no engine could be chosen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    /// `ng_offer` (the newest ng `offer` sipnab saw reached this engine),
    /// `map_row`, `sdp_address`, `listed` (nothing a rule applies to was seen
    /// for the call, and this engine's list names it), `default` (nothing
    /// seen, and no engine's list names it), or `unknown` (nothing was
    /// asked).
    pub chosen_by: String,
    /// Why, in words.
    pub reason: String,
    /// The engine the call's SDP named before it moved, when it moved and the
    /// previous engine was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<PreviousEngine>,
    /// The engines whose `list` named this Call-ID.
    pub listed_by: Vec<String>,
    /// Whether two or more engines hold this Call-ID, by their lists or their
    /// answers: a call that moved and left a session on the old engine.
    pub held_by_several_engines: bool,
    /// The engines the call moved off that no `delete` reached, from ng
    /// control traffic, and whether each was asked to confirm.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leftovers: Vec<LeftoverSession>,
}

/// An engine a call moved off that never received a `delete` for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct LeftoverSession {
    /// The engine as the ng traffic named it: `homer-id 2001`, or
    /// `listen-ng 192.0.2.5:2223` for a captured request.
    pub engine: String,
    /// The engine asked to confirm, when it was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// `confirmed` (it still holds the call), `released` (it does not),
    /// `not_asked`, `unreachable` or `suspect`.
    pub status: String,
    /// Why it was not asked, or what it said when it did not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What the previous engine of a moved call said about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct PreviousEngine {
    /// The engine asked.
    pub relay: String,
    /// `ng_offer`, `map_row` or `sdp_address`.
    pub chosen_by: String,
    /// Why this engine, in words.
    pub reason: String,
    /// `ok` when it answered about the call, `refused` when it declined (it
    /// does not hold it), or `unreachable` or `suspect`.
    pub outcome: String,
    /// Whether it still holds the call.
    pub holds: bool,
    /// What it said when it did not answer with the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Which engines listed a call this snapshot did not query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ListedBy {
    /// The engines whose `list` named this Call-ID.
    pub listed_by: Vec<String>,
    /// Whether two or more engines list it.
    pub held_by_several_engines: bool,
}

/// What one engine answered to `list`, when several engines are asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct EngineListing {
    /// The engine.
    pub relay: String,
    /// `ok`, or `unreachable`, `refused` or `suspect`.
    pub reach: String,
    /// What went wrong when it did not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How many Call-IDs it returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held: Option<usize>,
    /// Whether it returned as many as asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

/// One snapshot of what the relay holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct RelaySessions {
    /// Which relay answered.
    pub relay: String,
    /// When the snapshot was taken, RFC 3339.
    pub obtained_at: String,
    /// Always `relay_reported`.
    pub tier: String,
    /// `ok` when the relay answered its `list`, or `unreachable`, `refused` or
    /// `suspect`.
    pub reach: String,
    /// What went wrong when it did not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How many Call-IDs `list` returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held: Option<usize>,
    /// The `limit` the `list` asked for.
    pub list_limit: u32,
    /// Whether `list` returned as many as asked for, so the relay may hold more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// Whether this snapshot scanned the held calls.
    pub scan: bool,
    /// The most held calls a scan queries.
    pub cap: u32,
    /// Present when the cap asked for was above the ceiling of 1024 and was
    /// lowered to it: the number asked for and the ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_clamped: Option<crate::relay::scan_cap::CapClamp>,
    /// The calls queried, in the order asked.
    pub calls: Vec<SessionCall>,
    /// The calls listed and not queried.
    pub not_queried: Vec<NotQueried>,
    /// The threshold `stalled` uses, in seconds.
    pub stall_seconds: i64,
    /// What every reader should know about these verdicts.
    pub notes: Vec<String>,
    /// What each engine answered to `list`, when engine selection is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<Vec<EngineListing>>,
}

/// The kernel verdict for one socket's flags.
///
/// `kernelized` counts only without `no kernel support`: rtpengine 12.5.1 in
/// userspace (`--table=-1`) flags every received RTP socket with both, and
/// with the kernel module loaded it flags them `kernelized` alone.
#[must_use]
pub fn kernel_verdict(flags: Option<&[String]>) -> KernelVerdict {
    let Some(flags) = flags else {
        return KernelVerdict::NotReported;
    };
    let has = |f: &str| flags.iter().any(|x| x == f);
    if has("kernelized") && !has("no kernel support") {
        KernelVerdict::Kernel
    } else {
        KernelVerdict::Userspace
    }
}

/// The media verdict for one RTP socket, against the newest `last packet` of
/// any RTP socket in the same reply. Also returns how many seconds it trails,
/// on `stalled`.
///
/// Both times are the relay's own, from one answer, so no second clock is
/// involved. `never_received` is 0 packets in AND no `confirmed` flag; the
/// socket's `last packet` is not compared with the call's creation, because a
/// callee socket's `last packet` starts at the answer time.
#[must_use]
pub fn media_verdict(
    facts: &RelayStreamFacts,
    newest_last_packet: Option<i64>,
) -> (MediaVerdict, Option<i64>) {
    let (Some(flags), Some(packets), Some(last), Some(newest)) = (
        facts.flags.as_ref(),
        facts.ingress.packets,
        facts.last_packet,
        newest_last_packet,
    ) else {
        return (MediaVerdict::NotReported, None);
    };
    if packets == 0 && !flags.iter().any(|f| f == "confirmed") {
        return (MediaVerdict::NeverReceived, None);
    }
    let behind = newest.saturating_sub(last);
    if behind > STALL_SECONDS {
        (MediaVerdict::Stalled, Some(behind))
    } else {
        (MediaVerdict::Flowing, None)
    }
}

/// Whether a call holds an early media branch: more than two sides that are
/// neither a media subscriber nor in a dialog the others recognize.
///
/// Read from the relay's own tags. In the recorded parallel fork the early
/// branch is a third side with no `offer/answer` subscription, beside the
/// caller and the answered callee.
fn has_early_media_branch(view: &CallView) -> bool {
    view.tags
        .iter()
        .filter(|t| !t.is_media_subscriber())
        .count()
        > 2
}

/// The words an unjudged call carries.
const EARLY_MEDIA_UNJUDGED: &str = "the call has an early media branch: a relay can count one \
     party's media on another branch's socket, so its sockets are shown unjudged";

/// Read one queried call into its directions, verdicts and counters.
#[must_use]
pub fn judge_call(view: &CallView, sip_dialog: SipDialog) -> SessionCall {
    let newest = view
        .tags
        .iter()
        .flat_map(|t| t.streams.iter())
        .filter(|s| is_rtp(s))
        .filter_map(|s| s.facts.last_packet)
        .max();
    let branched = has_early_media_branch(view);
    let mut directions = Vec::new();
    if !branched {
        for tag in view.tags.iter().filter(|t| !t.is_media_subscriber()) {
            for stream in tag.streams.iter().filter(|s| is_rtp(s)) {
                let (verdict, no_packet_for_s) = media_verdict(&stream.facts, newest);
                directions.push(Direction {
                    from_tag: tag.tag.clone(),
                    local_address: stream.local_address.clone(),
                    local_port: stream.local_port,
                    media_index: stream.facts.media_index,
                    verdict,
                    no_packet_for_s,
                });
            }
        }
    }
    let tags = view
        .tags
        .iter()
        .map(|t| SessionTag {
            tag: t.tag.clone(),
            in_dialogue_with: t.in_dialogue_with.clone(),
            is_media_subscriber: t.is_media_subscriber(),
            sockets: t.streams.iter().map(socket_of).collect(),
        })
        .collect();
    SessionCall {
        call_id: view.call_id.clone(),
        outcome: "ok".to_string(),
        detail: None,
        sip_dialog,
        directions,
        unjudged: branched.then(|| EARLY_MEDIA_UNJUDGED.to_string()),
        tags,
        engine: None,
    }
}

/// One relay socket as the answer shows it.
fn socket_of(s: &RelayStream) -> SessionSocket {
    let kind = match &s.facts.flags {
        None => "not_reported",
        Some(_) if s.is_rtcp => "rtcp",
        Some(_) if is_rtp(s) => "rtp",
        Some(_) => "not_reported",
    };
    SessionSocket {
        local_address: s.local_address.clone(),
        local_port: s.local_port,
        media_index: s.facts.media_index,
        kind: kind.to_string(),
        endpoint: s.endpoint.clone(),
        ingress: s.facts.ingress.into(),
        egress: s.facts.egress.into(),
        last_packet: s.facts.last_packet,
        kernel: kernel_verdict(s.facts.flags.as_deref()),
    }
}

/// A queried call the relay did not answer about.
fn unanswered_call(
    call_id: &str,
    outcome: StatisticsOutcome,
    detail: String,
    sip_dialog: SipDialog,
) -> SessionCall {
    SessionCall {
        call_id: call_id.to_string(),
        outcome: outcome.as_wire_str().to_string(),
        detail: Some(detail),
        sip_dialog,
        directions: Vec::new(),
        unjudged: None,
        tags: Vec::new(),
        engine: None,
    }
}

/// Whether sipnab saw `call_id`'s SIP dialog reach a final state.
///
/// The one rule every surface hands [`relay_sessions`]: the dialog store's own
/// list of end states ([`crate::sip::dialog::DialogState::is_final`]). A
/// Call-ID the store does not hold was not seen ending.
#[must_use]
pub fn sip_saw_end(store: &crate::sip::dialog_store::DialogStore, call_id: &str) -> bool {
    store.get(call_id).is_some_and(|d| d.state().is_final())
}

/// Which side of the "did sipnab see it end" line a Call-ID is on.
fn sip_dialog_of(sip_ended: &dyn Fn(&str) -> bool, call_id: &str) -> SipDialog {
    if sip_ended(call_id) {
        SipDialog::Ended
    } else {
        SipDialog::NotSeenEnded
    }
}

/// The calls one snapshot queries: the selected call, then on a scan the
/// listed calls in Call-ID order, `ask.cap` in all.
fn calls_to_query(listed: &[String], ask: &SessionsAsk<'_>) -> Vec<String> {
    let mut to_query: Vec<String> = Vec::new();
    if let Some(sel) = ask.selected {
        to_query.push(sel.to_string());
    }
    if ask.scan {
        // The cap bounds the whole scan, the selected call included: one
        // `list` and at most `cap` queries per press.
        let cap = usize::try_from(ask.cap)
            .unwrap_or(usize::MAX)
            .saturating_sub(to_query.len());
        to_query.extend(
            listed
                .iter()
                .filter(|c| Some(c.as_str()) != ask.selected)
                .take(cap)
                .cloned(),
        );
    }
    to_query
}

/// Query one call on `relay`, named `label` in what the answer says.
fn ask_call(
    relay: &dyn ReadOnlyRelay,
    label: &str,
    permit: &TransmitPermit,
    call_id: &str,
    sip: SipDialog,
) -> SessionCall {
    match relay.query(permit, call_id) {
        Ok(ControlReply::Call(view)) => judge_call(&view, sip),
        Ok(ControlReply::Refused { reason }) => unanswered_call(
            call_id,
            StatisticsOutcome::Refused,
            format!("{label} for call {call_id}: {reason}"),
            sip,
        ),
        Ok(_) => unanswered_call(
            call_id,
            StatisticsOutcome::Suspect,
            crate::relay::types::ReplyKind::CallView
                .wrong_kind_reason()
                .to_string(),
            sip,
        ),
        Err(e) => {
            let (outcome, detail) = super::relay_holdings::fetch_failure(label, &e);
            unanswered_call(call_id, outcome, detail, sip)
        }
    }
}

/// Take one snapshot: `list`, then `query` for the selected call and, on a
/// scan, up to `ask.cap` held calls in Call-ID order.
///
/// `sip_ended` says whether sipnab saw a Call-ID's SIP dialog end; `clock`
/// stamps the snapshot. Both are injected so the function is tested without a
/// capture or a wall clock. Transmits only `list` and `query`, through the
/// relay it is handed, and nothing after a `list` that was not answered.
#[must_use]
pub fn relay_sessions(
    relay: &dyn ReadOnlyRelay,
    permit: &TransmitPermit,
    ask: &SessionsAsk<'_>,
    sip_ended: &dyn Fn(&str) -> bool,
    clock: &dyn Fn() -> DateTime<Utc>,
) -> RelaySessions {
    let label = super::relay_holdings::relay_label(relay);
    let mut out = RelaySessions {
        relay: label.clone(),
        obtained_at: String::new(),
        tier: TIER.to_string(),
        reach: "ok".to_string(),
        detail: None,
        held: None,
        list_limit: ask.list_limit,
        truncated: None,
        scan: ask.scan,
        cap: ask.cap,
        cap_clamped: ask.clamped,
        calls: Vec::new(),
        not_queried: Vec::new(),
        stall_seconds: STALL_SECONDS,
        notes: vec![DELETE_DELAY_NOTE.to_string(), STALL_NOTE.to_string()],
        engines: None,
    };
    let unanswered = |out: &mut RelaySessions, outcome: StatisticsOutcome, detail: String| {
        out.reach = outcome.as_wire_str().to_string();
        out.detail = Some(detail);
    };
    let mut listed = match relay.list(permit, ask.list_limit) {
        Ok(ControlReply::Calls(e)) => {
            out.held = Some(e.call_ids.len());
            out.truncated = Some(e.truncated);
            e.call_ids
        }
        Ok(ControlReply::Refused { reason }) => {
            unanswered(
                &mut out,
                StatisticsOutcome::Refused,
                format!("{label}: {reason}"),
            );
            out.obtained_at = clock().to_rfc3339();
            return out;
        }
        Ok(_) => {
            unanswered(
                &mut out,
                StatisticsOutcome::Suspect,
                crate::relay::types::ReplyKind::CallList
                    .wrong_kind_reason()
                    .to_string(),
            );
            out.obtained_at = clock().to_rfc3339();
            return out;
        }
        Err(e) => {
            let (outcome, detail) = super::relay_holdings::fetch_failure(&label, &e);
            unanswered(&mut out, outcome, detail);
            out.obtained_at = clock().to_rfc3339();
            return out;
        }
    };
    listed.sort();
    listed.dedup();

    let to_query = calls_to_query(&listed, ask);
    for call_id in &to_query {
        let sip = sip_dialog_of(sip_ended, call_id);
        out.calls
            .push(ask_call(relay, &label, permit, call_id, sip));
    }
    out.not_queried = listed
        .iter()
        .filter(|c| !to_query.contains(c))
        .map(|c| NotQueried {
            call_id: c.clone(),
            sip_dialog: sip_dialog_of(sip_ended, c),
            engine: None,
        })
        .collect();
    out.obtained_at = clock().to_rfc3339();
    out
}

/// How a snapshot chooses the engine for each call, when engine selection is
/// on.
pub struct Routed<'a> {
    /// The run's engine rule.
    pub routing: &'a crate::relay::engines::EngineRouting,
    /// A call's evidence, from the dialog store.
    pub sdp_of: &'a dyn Fn(&str) -> crate::relay::engines::CallEvidence,
}

/// [`relay_sessions`], with engine selection when `routed` is given.
#[must_use]
pub fn relay_sessions_routed(
    relay: &(dyn ReadOnlyRelay + Sync),
    routed: Option<&Routed<'_>>,
    permit: &TransmitPermit,
    ask: &SessionsAsk<'_>,
    sip_ended: &dyn Fn(&str) -> bool,
    clock: &dyn Fn() -> DateTime<Utc>,
) -> RelaySessions {
    let Some(routed) = routed else {
        return relay_sessions(relay, permit, ask, sip_ended, clock);
    };
    let routing = routed.routing;
    let default = routing.default_engine();
    // The default engine is the relay the surface handed in; every other
    // engine is reached through the routing's constructor.
    let with_engine = |addr: std::net::SocketAddr, f: &mut dyn FnMut(&dyn ReadOnlyRelay, &str)| {
        if addr == default {
            f(relay, &super::relay_holdings::relay_label(relay));
        } else {
            let r = routing.relay(addr);
            f(r.as_ref(), &super::relay_holdings::relay_label(r.as_ref()));
        }
    };

    // Which calls are held is asked of every engine the operator named.
    let mut listings: Vec<EngineListing> = Vec::new();
    let mut listed_by: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut listed_at: std::collections::BTreeMap<String, Vec<std::net::SocketAddr>> =
        std::collections::BTreeMap::new();
    // Every engine's `list` at once, so an engine that does not answer costs
    // one control timeout, not one per engine; the answers are then read in
    // the engines' order.
    let engines = routing.listing_engines();
    let answers = crate::relay::fan_out::ask_each(engines.clone(), |addr| {
        let mut answer = None;
        with_engine(addr, &mut |r, label| {
            answer = Some((label.to_string(), r.list(permit, ask.list_limit)));
        });
        answer
    });
    for (addr, answer) in engines.into_iter().zip(answers) {
        let Some((label, listed)) = answer else {
            continue;
        };
        let label = label.as_str();
        let mut listing = EngineListing {
            relay: label.to_string(),
            reach: "ok".to_string(),
            detail: None,
            held: None,
            truncated: None,
        };
        match listed {
            Ok(ControlReply::Calls(e)) => {
                listing.held = Some(e.call_ids.len());
                listing.truncated = Some(e.truncated);
                for c in e.call_ids {
                    let at = listed_at.entry(c.clone()).or_default();
                    if !at.contains(&addr) {
                        at.push(addr);
                    }
                    let by = listed_by.entry(c).or_default();
                    if !by.iter().any(|l| l == label) {
                        by.push(label.to_string());
                    }
                }
            }
            Ok(ControlReply::Refused { reason }) => {
                listing.reach = StatisticsOutcome::Refused.as_wire_str().to_string();
                listing.detail = Some(format!("{label}: {reason}"));
            }
            Ok(_) => {
                listing.reach = StatisticsOutcome::Suspect.as_wire_str().to_string();
                listing.detail = Some(
                    crate::relay::types::ReplyKind::CallList
                        .wrong_kind_reason()
                        .to_string(),
                );
            }
            Err(e) => {
                let (outcome, detail) = super::relay_holdings::fetch_failure(label, &e);
                listing.reach = outcome.as_wire_str().to_string();
                listing.detail = Some(detail);
            }
        }
        listings.push(listing);
    }

    let mut out = RelaySessions {
        relay: listings
            .iter()
            .map(|l| l.relay.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        obtained_at: String::new(),
        tier: TIER.to_string(),
        reach: "ok".to_string(),
        detail: None,
        held: None,
        list_limit: ask.list_limit,
        truncated: None,
        scan: ask.scan,
        cap: ask.cap,
        cap_clamped: ask.clamped,
        calls: Vec::new(),
        not_queried: Vec::new(),
        stall_seconds: STALL_SECONDS,
        notes: vec![DELETE_DELAY_NOTE.to_string(), STALL_NOTE.to_string()],
        engines: None,
    };
    let answered: Vec<&EngineListing> = listings.iter().filter(|l| l.reach == "ok").collect();
    if answered.is_empty() {
        // No engine answered: the snapshot is unanswered, in the first
        // engine's words, and nothing else is sent.
        if let Some(first) = listings.first() {
            out.reach.clone_from(&first.reach);
            out.detail.clone_from(&first.detail);
        }
        out.engines = Some(listings);
        out.obtained_at = clock().to_rfc3339();
        return out;
    }
    out.truncated = Some(answered.iter().any(|l| l.truncated == Some(true)));
    let listed: Vec<String> = listed_by.keys().cloned().collect();
    out.held = Some(listed.len());

    let to_query = calls_to_query(&listed, ask);
    for call_id in &to_query {
        let sip = sip_dialog_of(sip_ended, call_id);
        let by = listed_by.get(call_id).cloned().unwrap_or_default();
        let mut holders: std::collections::BTreeSet<String> = by.iter().cloned().collect();
        let at = listed_at.get(call_id).map_or(&[][..], Vec::as_slice);
        let chosen = routing.select_listed(&(routed.sdp_of)(call_id), at);
        let (mut entry, asked, chosen_by, reason) = match &chosen.current {
            Ok(engine) => {
                let mut asked = None;
                let mut entry = None;
                with_engine(engine.control, &mut |r, label| {
                    entry = Some(ask_call(r, label, permit, call_id, sip));
                    asked = Some(label.to_string());
                });
                let entry = entry.unwrap_or_else(|| {
                    unanswered_call(
                        call_id,
                        StatisticsOutcome::Suspect,
                        "no engine answered".to_string(),
                        sip,
                    )
                });
                if entry.outcome == "ok"
                    && let Some(label) = &asked
                {
                    holders.insert(label.clone());
                }
                (
                    entry,
                    asked,
                    engine.chosen_by_word().to_string(),
                    engine.reason().unwrap_or_default(),
                )
            }
            Err(unknown) => (
                unanswered_call(
                    call_id,
                    StatisticsOutcome::NotConfigured,
                    unknown.to_string(),
                    sip,
                ),
                None,
                "unknown".to_string(),
                unknown.to_string(),
            ),
        };
        let previous = match (&chosen.current, &chosen.previous) {
            (Ok(_), Some(prev)) if routing.asks_previous() => {
                let mut answer = None;
                with_engine(prev.control, &mut |r, label| {
                    answer = Some(ask_previous(r, label, permit, call_id, prev));
                });
                answer
            }
            _ => None,
        };
        if let Some(p) = previous.as_ref().filter(|p| p.holds) {
            holders.insert(p.relay.clone());
        }
        let leftovers: Vec<LeftoverSession> = chosen
            .leftovers
            .iter()
            .map(|left| {
                // The previous engine's answer, when it is this engine: it is
                // the same question, asked once.
                let asked_before = match (&chosen.previous, &previous) {
                    (Some(engine), Some(answer)) if Some(engine.control) == left.control => {
                        Some(answer.clone())
                    }
                    _ => None,
                };
                let answer = |control| {
                    let mut answer = None;
                    let engine = crate::relay::engines::Engine {
                        control,
                        chosen_by: crate::relay::engines::ChosenBy::NgOffer {
                            engine: left.engine,
                            row: None,
                        },
                    };
                    with_engine(control, &mut |r, label| {
                        answer = Some(ask_previous(r, label, permit, call_id, &engine));
                    });
                    answer
                };
                leftover_session(left, routing.asks_previous(), asked_before, answer)
            })
            .collect();
        for l in leftovers.iter().filter(|l| l.status == "confirmed") {
            if let Some(relay) = &l.relay {
                holders.insert(relay.clone());
            }
        }
        entry.engine = Some(CallEngine {
            asked,
            chosen_by,
            reason,
            previous,
            listed_by: by,
            held_by_several_engines: holders.len() > 1,
            leftovers,
        });
        out.calls.push(entry);
    }
    out.not_queried = listed
        .iter()
        .filter(|c| !to_query.contains(c))
        .map(|c| {
            let by = listed_by.get(c).cloned().unwrap_or_default();
            NotQueried {
                call_id: c.clone(),
                sip_dialog: sip_dialog_of(sip_ended, c),
                engine: Some(ListedBy {
                    held_by_several_engines: by.len() > 1,
                    listed_by: by,
                }),
            }
        })
        .collect();
    out.engines = Some(listings);
    out.obtained_at = clock().to_rfc3339();
    out
}

/// What sipnab knows of one leftover session: asked to confirm when the
/// operator permits asking (`asks`) and listed the engine, else why not.
///
/// `asked_before` is the previous engine's answer when the leftover is that
/// engine, so it is not asked twice; `ask` asks any other.
fn leftover_session(
    left: &crate::relay::engines::Leftover,
    asks: bool,
    asked_before: Option<PreviousEngine>,
    ask: impl FnOnce(std::net::SocketAddr) -> Option<PreviousEngine>,
) -> LeftoverSession {
    let mut out = LeftoverSession {
        engine: left.engine.to_string(),
        relay: None,
        status: "not_asked".to_string(),
        detail: None,
    };
    let Some(control) = left.control else {
        let mut detail = format!("no {} row names it", crate::cli::RELAY_NG_ENGINE_FLAG);
        if let Some(words) = crate::relay::engines::suggested_row_words(left.engine, left.reported)
        {
            detail.push_str(&format!(". {words}"));
        }
        out.detail = Some(detail);
        return out;
    };
    if !asks {
        out.detail = Some("add --relay-previous-engine to ask it".to_string());
        return out;
    }
    let Some(answer) = asked_before.or_else(|| ask(control)) else {
        return out;
    };
    out.relay = Some(answer.relay);
    if answer.holds {
        out.status = "confirmed".to_string();
    } else if answer.outcome == StatisticsOutcome::Refused.as_wire_str() {
        out.status = "released".to_string();
    } else {
        out.status = answer.outcome;
        out.detail = answer.detail;
    }
    out
}

/// Ask a moved call's previous engine whether it still holds the call.
fn ask_previous(
    relay: &dyn ReadOnlyRelay,
    label: &str,
    permit: &TransmitPermit,
    call_id: &str,
    engine: &crate::relay::engines::Engine,
) -> PreviousEngine {
    let mut out = PreviousEngine {
        relay: label.to_string(),
        chosen_by: engine.chosen_by_word().to_string(),
        reason: engine.reason().unwrap_or_default(),
        outcome: "ok".to_string(),
        holds: false,
        detail: None,
    };
    match relay.query(permit, call_id) {
        Ok(ControlReply::Call(_)) => out.holds = true,
        Ok(ControlReply::Refused { reason }) => {
            out.outcome = StatisticsOutcome::Refused.as_wire_str().to_string();
            out.detail = Some(format!("{label} for call {call_id}: {reason}"));
        }
        Ok(_) => {
            out.outcome = StatisticsOutcome::Suspect.as_wire_str().to_string();
            out.detail = Some(
                crate::relay::types::ReplyKind::CallView
                    .wrong_kind_reason()
                    .to_string(),
            );
        }
        Err(e) => {
            let (outcome, detail) = super::relay_holdings::fetch_failure(label, &e);
            out.outcome = outcome.as_wire_str().to_string();
            out.detail = Some(detail);
        }
    }
    out
}

impl RelaySessions {
    /// Whether the relay answered its `list`.
    #[must_use]
    pub fn answered(&self) -> bool {
        self.reach == "ok"
    }

    /// The JSON `GET /v1/relay/sessions` returns and `--relay-sessions --json`
    /// prints: the snapshot with `outcome: "ok"`, or the classification
    /// envelope every relay route uses when the relay did not answer `list`.
    #[must_use]
    pub fn body(&self) -> Value {
        if !self.answered() {
            let outcome = outcome_from_wire(&self.reach);
            let text = fmt::relay_rest_outcome(outcome, self.detail.as_deref().unwrap_or(""));
            return serde_json::from_str(&text).unwrap_or_else(|_| json!({ "outcome": "suspect" }));
        }
        let mut v = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        v["outcome"] = json!("ok");
        v
    }

    /// Every Call-ID the snapshot names, queried or not, in the order its
    /// rows are shown: Call-ID order.
    #[must_use]
    pub fn rows(&self) -> Vec<&str> {
        let mut rows: Vec<&str> = self
            .calls
            .iter()
            .map(|c| c.call_id.as_str())
            .chain(self.not_queried.iter().map(|n| n.call_id.as_str()))
            .collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    /// The status lines: which relay, when, reachable or not, how many it
    /// holds, how many were queried, and what every reader should know.
    #[must_use]
    pub fn render_status(&self) -> String {
        let mut out = format!(
            "Sessions of {}, asked {} ({TIER})\n",
            super::clean(&self.relay),
            self.obtained_at
        );
        if !self.answered() {
            out.push_str(&format!(
                "{}: {}\n",
                self.reach,
                super::clean(self.detail.as_deref().unwrap_or(""))
            ));
            out.push_str(&self.render_engines());
            out.push('\n');
            return out;
        }
        let held = self.held.unwrap_or(0);
        let more = if self.truncated == Some(true) {
            ", as many as asked for, so the relay may hold more"
        } else {
            ""
        };
        // Queried calls the relay listed, and those it did not (a selected
        // Call-ID asked about anyway). Every listed call is queried or in
        // `not_queried`, so the first is what `not_queried` leaves.
        let listed_queried = held.saturating_sub(self.not_queried.len());
        let unlisted = self.calls.len().saturating_sub(listed_queried);
        let also = if unlisted == 0 {
            String::new()
        } else {
            format!(
                "; also asked about {} the relay did not list",
                super::plural(unlisted as u64, "call")
            )
        };
        out.push_str(&format!(
            "reachable; {} listed{more}; queried {listed_queried} of {held}{}{also}\n",
            super::plural(held as u64, "call"),
            if self.scan { " (scan)" } else { "" }
        ));
        if let Some(clamp) = &self.cap_clamped {
            out.push_str(&clamp.sentence());
            out.push('\n');
        }
        out.push_str(&self.render_engines());
        for note in &self.notes {
            out.push_str(&format!("Note: {note}.\n"));
        }
        out.push('\n');
        out
    }

    /// One line per engine asked to `list`, when several are; nothing
    /// otherwise.
    fn render_engines(&self) -> String {
        let Some(engines) = &self.engines else {
            return String::new();
        };
        let mut out = String::new();
        for e in engines {
            if e.reach == "ok" {
                out.push_str(&format!(
                    "Engine {}: reachable; {} listed\n",
                    super::clean(&e.relay),
                    super::plural(e.held.unwrap_or(0) as u64, "call")
                ));
            } else {
                out.push_str(&format!(
                    "Engine {}: {}: {}\n",
                    super::clean(&e.relay),
                    e.reach,
                    super::clean(e.detail.as_deref().unwrap_or(""))
                ));
            }
        }
        out
    }

    /// One row per Call-ID with its verdicts, the cursor on `cursor`.
    #[must_use]
    pub fn render_rows(&self, cursor: Option<usize>) -> String {
        let rows = self.rows();
        if rows.is_empty() {
            return "The relay holds no calls.\n".to_string();
        }
        let mut out = String::new();
        for (i, id) in rows.iter().enumerate() {
            let mark = match cursor {
                Some(c) if c.min(rows.len() - 1) == i => "> ",
                Some(_) => "  ",
                None => "",
            };
            let (summary, sip) = match self.calls.iter().find(|c| c.call_id == *id) {
                Some(c) => (c.summary(), c.sip_dialog),
                None => (
                    "not queried".to_string(),
                    self.not_queried
                        .iter()
                        .find(|n| n.call_id == *id)
                        .map_or(SipDialog::NotSeenEnded, |n| n.sip_dialog),
                ),
            };
            let ended = if sip == SipDialog::Ended {
                "  ended in SIP"
            } else {
                ""
            };
            let several = self
                .calls
                .iter()
                .find(|c| c.call_id == *id)
                .and_then(|c| c.engine.as_ref().map(|e| e.held_by_several_engines))
                .or_else(|| {
                    self.not_queried
                        .iter()
                        .find(|n| n.call_id == *id)
                        .and_then(|n| n.engine.as_ref().map(|e| e.held_by_several_engines))
                })
                .unwrap_or(false);
            let several = if several {
                "  held by several engines"
            } else {
                ""
            };
            out.push_str(&format!(
                "{mark}{}{ended}{several}  {summary}\n",
                super::clean(id)
            ));
        }
        out
    }

    /// The snapshot as text: the status, a row per call, then each queried
    /// call's directions and sockets. `format` chooses the socket tables.
    #[must_use]
    pub fn render(&self, format: ReportFormat) -> String {
        let mut out = self.render_status();
        if !self.answered() {
            return out;
        }
        out.push_str(&self.render_rows(None));
        for call in &self.calls {
            out.push('\n');
            out.push_str(&call.render_as(format));
        }
        out
    }
}

/// A verdict in words.
fn verdict_words(d: &Direction) -> String {
    match d.verdict {
        MediaVerdict::NeverReceived => "never received".to_string(),
        MediaVerdict::Stalled => format!("no packet for {} s", d.no_packet_for_s.unwrap_or(0)),
        MediaVerdict::Flowing => "flowing".to_string(),
        MediaVerdict::NotReported => "not reported by this relay version".to_string(),
    }
}

/// A count, or the words for its absence.
fn count(v: Option<u64>) -> String {
    v.map_or_else(|| "not reported".to_string(), |n| n.to_string())
}

impl SessionCall {
    /// One line: each direction's verdict, why it is not judged, or why the
    /// relay did not answer about it.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.outcome != "ok" {
            return format!(
                "{}: {}",
                self.outcome,
                super::clean(self.detail.as_deref().unwrap_or(""))
            );
        }
        if self.unjudged.is_some() {
            return "early media branch: counters shown unjudged".to_string();
        }
        if self.directions.is_empty() {
            return "no RTP socket to judge".to_string();
        }
        self.directions
            .iter()
            .map(|d| format!("from {}: {}", super::clean(&d.from_tag), verdict_words(d)))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The call's directions and its sockets as text.
    #[must_use]
    pub fn render(&self) -> String {
        self.render_as(ReportFormat::Text)
    }

    /// The call's directions and sockets, the socket table in `format`.
    #[must_use]
    pub fn render_as(&self, format: ReportFormat) -> String {
        let mut out = format!("Call {} ({TIER})\n", super::clean(&self.call_id));
        if let Some(engine) = &self.engine {
            out.push_str(&engine.render());
        }
        if self.outcome != "ok" {
            out.push_str(&format!("{}\n", self.summary()));
            return out;
        }
        match self.sip_dialog {
            SipDialog::Ended => out.push_str("sipnab saw its SIP dialog end.\n"),
            SipDialog::NotSeenEnded => out.push_str(
                "sipnab did not see its SIP dialog end; the relay may still list a call \
                 for about 30 s after it ends.\n",
            ),
        }
        if let Some(why) = &self.unjudged {
            out.push_str(&format!("Not judged: {why}.\n"));
        }
        for d in &self.directions {
            out.push_str(&format!(
                "from {} to {}:{}: {}\n",
                super::clean(&d.from_tag),
                d.local_address,
                d.local_port,
                verdict_words(d)
            ));
        }
        let rows: Vec<Vec<String>> = self
            .tags
            .iter()
            .flat_map(|t| {
                t.sockets.iter().map(move |s| {
                    vec![
                        t.tag.clone(),
                        format!("{}:{}", s.local_address, s.local_port),
                        s.kind.clone(),
                        count(s.ingress.packets),
                        count(s.ingress.bytes),
                        count(s.ingress.errors),
                        count(s.egress.packets),
                        count(s.egress.bytes),
                        count(s.egress.errors),
                        s.last_packet
                            .map_or_else(|| "not reported".to_string(), |n| n.to_string()),
                        match s.kernel {
                            KernelVerdict::Kernel => "kernel",
                            KernelVerdict::Userspace => "userspace",
                            KernelVerdict::NotReported => "not reported",
                        }
                        .to_string(),
                    ]
                })
            })
            .collect();
        out.push_str(&super::table(
            format,
            &[
                "Tag",
                "Relay socket",
                "Kind",
                "In pkts",
                "In bytes",
                "In errs",
                "Out pkts",
                "Out bytes",
                "Out errs",
                "Last packet",
                "Forwarding",
            ],
            &rows,
        ));
        out
    }
}

impl CallEngine {
    /// Which engine was asked and why, what the previous engine said,
    /// whether several engines hold the call, and each leftover session.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        if let Some(asked) = &self.asked {
            out.push_str(&format!(
                "Asked {} ({}).\n",
                super::clean(asked),
                super::clean(&self.reason)
            ));
        }
        if let Some(p) = &self.previous {
            let said = if p.holds {
                "still holds this call; a session was left on the old engine".to_string()
            } else if p.outcome == "refused" {
                "does not hold this call".to_string()
            } else {
                format!(
                    "{}: {}",
                    p.outcome,
                    super::clean(p.detail.as_deref().unwrap_or(""))
                )
            };
            out.push_str(&format!(
                "Previous engine {} ({}): {said}.\n",
                super::clean(&p.relay),
                super::clean(&p.reason)
            ));
        }
        if self.held_by_several_engines {
            out.push_str("Held by several engines.\n");
        }
        for l in &self.leftovers {
            let relay = l
                .relay
                .as_deref()
                .map_or_else(String::new, |r| format!(" ({})", super::clean(r)));
            let said = match l.status.as_str() {
                "confirmed" => "confirmed, it still holds this call".to_string(),
                "released" => "released, it no longer holds this call".to_string(),
                other => format!(
                    "not confirmed ({other}: {})",
                    super::clean(l.detail.as_deref().unwrap_or(""))
                ),
            };
            out.push_str(&format!(
                "Leftover session on {}{relay}: {said}.\n",
                super::clean(&l.engine)
            ));
        }
        out
    }
}

/// The classification a `reach` word names.
fn outcome_from_wire(word: &str) -> StatisticsOutcome {
    StatisticsOutcome::all()
        .into_iter()
        .find(|o| o.as_wire_str() == word)
        .unwrap_or(StatisticsOutcome::Suspect)
}

/// Whether a socket carries RTP, by its flags.
fn is_rtp(stream: &RelayStream) -> bool {
    stream
        .facts
        .flags
        .as_ref()
        .is_some_and(|f| f.iter().any(|x| x == "RTP"))
}

/// The rule, the snapshot and the text, against a relay that answers from a
/// script in memory and records every ask. Nothing here opens a socket. The
/// real recorded replies are read through the real parser in the relay
/// implementation's own tests, because this layer may not name it.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::types::{Enumeration, RelayTag};
    use std::sync::Mutex;

    type TestError = Box<dyn std::error::Error>;

    /// What the scripted relay answers: the verb and its Call-ID in.
    type Script = fn(&str, Option<&str>) -> anyhow::Result<ControlReply>;

    /// A relay that answers from a script and records every ask.
    struct ScriptedRelay {
        script: Script,
        asked: Mutex<Vec<String>>,
    }

    impl ScriptedRelay {
        fn new(script: Script) -> Self {
            Self {
                script,
                asked: Mutex::new(Vec::new()),
            }
        }

        /// Every ask so far, in order.
        fn asked(&self) -> Result<Vec<String>, TestError> {
            Ok(self.asked.lock().map_err(|e| e.to_string())?.clone())
        }

        fn record(&self, what: String) -> anyhow::Result<()> {
            self.asked
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .push(what);
            Ok(())
        }
    }

    impl ReadOnlyRelay for ScriptedRelay {
        fn list(&self, _: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            self.record(format!("list {limit}"))?;
            (self.script)("list", None)
        }
        fn query(&self, _: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            self.record(format!("query {call_id}"))?;
            (self.script)("query", Some(call_id))
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            self.record("statistics".to_string())?;
            anyhow::bail!("a sessions snapshot never asks for statistics")
        }
        fn call_statistics(&self, _: &TransmitPermit, c: &str) -> anyhow::Result<ControlReply> {
            self.record(format!("call_statistics {c}"))?;
            anyhow::bail!("a sessions snapshot never asks for call statistics")
        }
        fn describe(&self) -> String {
            "scripted at 192.0.2.10:22222".to_string()
        }
    }

    fn permit() -> Result<TransmitPermit, TestError> {
        Ok(
            TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
                device: "eth0".to_owned(),
            })
            .ok_or("a live source grants a permit")?,
        )
    }

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-04T12:00:00Z")
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_default()
    }

    /// Three held calls, in the order a relay lists them (not sorted).
    const HELD: [&str; 3] = [
        "c-3@example.invalid",
        "c-1@example.invalid",
        "c-2@example.invalid",
    ];

    fn listed(ids: &[&str], truncated: bool) -> ControlReply {
        ControlReply::Calls(Enumeration {
            call_ids: ids.iter().map(|s| (*s).to_string()).collect(),
            truncated,
        })
    }

    /// Socket facts for an RTP socket.
    fn rtp(packets_in: u64, last: i64, confirmed: bool) -> RelayStreamFacts {
        let mut flags = vec!["RTP".to_string(), "filled".to_string()];
        if confirmed {
            flags.push("confirmed".to_string());
        }
        RelayStreamFacts {
            media_index: Some(1),
            ingress: StreamCounters {
                packets: Some(packets_in),
                bytes: Some(packets_in * 172),
                errors: Some(0),
            },
            egress: StreamCounters::default(),
            last_packet: Some(last),
            flags: Some(flags),
        }
    }

    /// Facts for an RTCP socket that received `packets_in` with its last at `last`.
    fn rtcp(packets_in: u64, last: i64) -> RelayStreamFacts {
        RelayStreamFacts {
            flags: Some(vec!["RTCP".to_string(), "filled".to_string()]),
            ..rtp(packets_in, last, false)
        }
    }

    fn stream(port: u16, facts: RelayStreamFacts) -> RelayStream {
        RelayStream {
            local_address: "192.0.2.11".to_string(),
            local_port: port,
            endpoint: Some("192.0.2.1:40000".to_string()),
            advertised_endpoint: None,
            is_rtcp: facts
                .flags
                .as_ref()
                .is_some_and(|f| f.iter().any(|x| x == "RTCP")),
            ssrcs: Vec::new(),
            facts,
        }
    }

    fn party(tag: &str, peer: &[&str], streams: Vec<RelayStream>) -> RelayTag {
        RelayTag {
            tag: tag.to_string(),
            in_dialogue_with: peer.iter().map(|s| (*s).to_string()).collect(),
            media_subscriptions: Vec::new(),
            codec: None,
            streams,
        }
    }

    /// A two-party call: the caller's RTP socket at `caller`, the callee's at
    /// `callee`, each with an RTCP socket that received nothing.
    fn two_party(caller: RelayStreamFacts, callee: RelayStreamFacts) -> CallView {
        CallView {
            call_id: "c-1@example.invalid".to_string(),
            tags: vec![
                party(
                    "caller-tag-1",
                    &["callee-tag-1"],
                    vec![stream(30000, caller), stream(30001, rtcp(0, 100))],
                ),
                party(
                    "callee-tag-1",
                    &["caller-tag-1"],
                    vec![stream(30002, callee), stream(30003, rtcp(0, 100))],
                ),
            ],
        }
    }

    // ── The verdict rule ────────────────────────────────────────────────

    /// A socket that counted nothing in and was never `confirmed` never
    /// received; one that counted packets and has the newest `last packet`
    /// is flowing.
    #[test]
    fn nothing_in_and_unconfirmed_never_received_and_packets_in_are_flowing() {
        assert_eq!(
            media_verdict(&rtp(0, 100, false), Some(140)),
            (MediaVerdict::NeverReceived, None),
            "A socket that counted nothing in and was never `confirmed` never received"
        );
        assert_eq!(
            media_verdict(&rtp(2250, 140, true), Some(140)),
            (MediaVerdict::Flowing, None),
            "A socket that counted nothing in and was never `confirmed` never received"
        );
    }

    /// Early in a call a socket can count packets before the relay marks it
    /// `confirmed`; that is not "never received". And `last packet` equal to
    /// the newest is not the test: 0 packets in is.
    #[test]
    fn packets_before_confirmed_are_not_never_received() {
        assert_eq!(
            media_verdict(&rtp(25, 140, false), Some(140)),
            (MediaVerdict::Flowing, None),
            "Early in a call a socket can count packets before the relay marks it `confirmed`"
        );
    }

    /// More than 2 s behind the newest `last packet` in the reply is stalled,
    /// with the lag; exactly 2 s is not, because the field is whole seconds
    /// and live sockets were measured trailing by 1.
    #[test]
    fn more_than_two_seconds_behind_is_stalled_and_two_is_not() {
        assert_eq!(
            media_verdict(&rtp(496, 130, true), Some(140)),
            (MediaVerdict::Stalled, Some(10)),
            "More than 2 s behind the newest `last packet` in the reply is stalled, with the lag"
        );
        assert_eq!(
            media_verdict(&rtp(496, 137, true), Some(140)),
            (MediaVerdict::Stalled, Some(3)),
            "More than 2 s behind the newest `last packet` in the reply is stalled, with the lag"
        );
        assert_eq!(
            media_verdict(&rtp(496, 138, true), Some(140)),
            (MediaVerdict::Flowing, None),
            "More than 2 s behind the newest `last packet` in the reply is stalled, with the lag"
        );
    }

    /// Missing counters, a missing `last packet` or missing flags are
    /// `not_reported`, never `flowing` and never `never_received`.
    #[test]
    fn what_the_relay_did_not_report_is_not_reported() {
        let mut no_packets = rtp(0, 100, false);
        no_packets.ingress.packets = None;
        let mut no_last = rtp(2250, 140, true);
        no_last.last_packet = None;
        let mut no_flags = rtp(0, 100, false);
        no_flags.flags = None;
        for facts in [no_packets, no_last, no_flags] {
            assert_eq!(
                media_verdict(&facts, Some(140)),
                (MediaVerdict::NotReported, None),
                "{facts:?}"
            );
        }
        assert_eq!(
            media_verdict(&rtp(2250, 140, true), None),
            (MediaVerdict::NotReported, None),
            "no newest packet in the reply to compare with"
        );
    }

    /// `kernelized` counts only without `no kernel support`; neither flag is
    /// userspace; no flags list is not reported.
    #[test]
    fn kernelized_counts_only_without_no_kernel_support() {
        let f = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            kernel_verdict(Some(&f(&["RTP", "confirmed", "kernelized"]))),
            KernelVerdict::Kernel,
            "`kernelized` counts only without `no kernel support`"
        );
        assert_eq!(
            kernel_verdict(Some(&f(&["RTP", "kernelized", "no kernel support"]))),
            KernelVerdict::Userspace,
            "`kernelized` counts only without `no kernel support`"
        );
        assert_eq!(
            kernel_verdict(Some(&f(&["RTP", "filled"]))),
            KernelVerdict::Userspace,
            "`kernelized` counts only without `no kernel support`"
        );
        assert_eq!(
            kernel_verdict(None),
            KernelVerdict::NotReported,
            "`kernelized` counts only without `no kernel support`"
        );
    }

    // ── One call ────────────────────────────────────────────────────────

    /// One direction per party RTP socket, named by the tag that sends it.
    /// RTCP sockets are counted and shown but give no direction.
    #[test]
    fn a_call_has_one_direction_per_party_rtp_socket() {
        let call = judge_call(
            &two_party(rtp(2250, 140, true), rtp(0, 101, false)),
            SipDialog::NotSeenEnded,
        );
        let got: Vec<(&str, u16, MediaVerdict)> = call
            .directions
            .iter()
            .map(|d| (d.from_tag.as_str(), d.local_port, d.verdict))
            .collect();
        assert_eq!(
            got,
            [
                ("caller-tag-1", 30000, MediaVerdict::Flowing),
                ("callee-tag-1", 30002, MediaVerdict::NeverReceived),
            ],
            "One direction per party RTP socket, named by the tag that sends it"
        );
        assert_eq!(
            call.unjudged, None,
            "One direction per party RTP socket, named by the tag that sends it"
        );
        let sockets: Vec<u16> = call
            .tags
            .iter()
            .flat_map(|t| t.sockets.iter().map(|s| s.local_port))
            .collect();
        assert_eq!(sockets, [30000, 30001, 30002, 30003], "every socket shown");
        assert_eq!(
            call.tags[0].sockets[1].kind, "rtcp",
            "One direction per party RTP socket, named by the tag that sends it"
        );
    }

    /// The newest `last packet` is taken over RTP sockets only: an RTCP
    /// socket's later packet does not make an RTP socket stalled.
    #[test]
    fn the_newest_packet_is_taken_over_rtp_sockets_only() {
        let mut view = two_party(rtp(2250, 140, true), rtp(2190, 140, true));
        view.tags[0].streams[1] = stream(30001, rtcp(3, 150));
        let call = judge_call(&view, SipDialog::NotSeenEnded);
        assert_eq!(call.directions.len(), 2, "{:?}", call.directions);
        assert!(
            call.directions
                .iter()
                .all(|d| d.verdict == MediaVerdict::Flowing),
            "{:?}",
            call.directions
        );
    }

    /// A stalled direction says for how long, from the same reply.
    #[test]
    fn a_stalled_direction_says_how_long() {
        let call = judge_call(
            &two_party(rtp(496, 130, true), rtp(714, 140, true)),
            SipDialog::NotSeenEnded,
        );
        assert_eq!(
            call.directions[0].verdict,
            MediaVerdict::Stalled,
            "A stalled direction says for how long, from the same reply"
        );
        assert_eq!(
            call.directions[0].no_packet_for_s,
            Some(10),
            "A stalled direction says for how long, from the same reply"
        );
        assert_eq!(
            call.directions[1].verdict,
            MediaVerdict::Flowing,
            "A stalled direction says for how long, from the same reply"
        );
        assert_eq!(
            call.directions[1].no_packet_for_s, None,
            "A stalled direction says for how long, from the same reply"
        );
    }

    /// A side that only receives another's media (a recorder) is not a
    /// direction: it sends nothing, and calling its 0 packets "never
    /// received" would be wrong.
    #[test]
    fn a_media_subscriber_gives_no_direction() {
        let mut view = two_party(rtp(2250, 140, true), rtp(2190, 140, true));
        view.tags.push(RelayTag {
            media_subscriptions: vec!["caller-tag-1".to_string()],
            ..party(
                "recorder-tag-1",
                &[],
                vec![stream(30004, rtp(0, 100, false))],
            )
        });
        let call = judge_call(&view, SipDialog::NotSeenEnded);
        assert_eq!(call.directions.len(), 2, "{:?}", call.directions);
        assert!(
            call.tags[2].is_media_subscriber,
            "A side that only receives another's media (a recorder) is not a direction"
        );
        assert_eq!(
            call.unjudged, None,
            "a recorder is not an early media branch"
        );
    }

    /// A call with an early media branch -- a third party outside the
    /// dialog -- is not judged per direction, and its counters are all kept.
    #[test]
    fn a_call_with_an_early_media_branch_is_shown_unjudged() {
        let mut view = two_party(rtp(2189, 140, true), rtp(0, 102, false));
        view.tags.push(party(
            "early-tag-1",
            &[],
            vec![stream(30022, rtp(2260, 140, true))],
        ));
        let call = judge_call(&view, SipDialog::NotSeenEnded);
        assert!(call.directions.is_empty(), "{:?}", call.directions);
        assert!(
            call.unjudged
                .as_deref()
                .is_some_and(|w| w.contains("early media branch")),
            "{:?}",
            call.unjudged
        );
        let early = call
            .tags
            .iter()
            .find(|t| t.tag == "early-tag-1")
            .map(|t| t.sockets[0].ingress.packets);
        assert_eq!(early, Some(Some(2260)), "the counters are shown unjudged");
    }

    // ── The snapshot ────────────────────────────────────────────────────

    /// A relay holding the three calls of `HELD`, each two-way and flowing.
    fn holding_three() -> ScriptedRelay {
        ScriptedRelay::new(|verb, call| match verb {
            "list" => Ok(listed(&HELD, false)),
            _ => Ok(ControlReply::Call(CallView {
                call_id: call.unwrap_or_default().to_string(),
                ..two_party(rtp(2250, 140, true), rtp(2190, 140, true))
            })),
        })
    }

    fn ask(selected: Option<&str>, scan: bool, cap: u32) -> SessionsAsk<'_> {
        SessionsAsk {
            selected,
            scan,
            cap,
            list_limit: 32,
            clamped: None,
        }
    }

    fn never(_: &str) -> bool {
        false
    }

    /// Nothing selected and no scan: one `list`, no `query`, and every listed
    /// Call-ID is in the answer as not queried -- a call never vanishes.
    #[test]
    fn with_nothing_selected_and_no_scan_only_list_is_sent() -> Result<(), TestError> {
        let relay = holding_three();
        let s = relay_sessions(&relay, &permit()?, &ask(None, false, 2), &never, &at);
        assert_eq!(relay.asked()?, ["list 32"], "Nothing selected and no scan");
        assert!(s.calls.is_empty(), "Nothing selected and no scan");
        let not: Vec<&str> = s.not_queried.iter().map(|n| n.call_id.as_str()).collect();
        assert_eq!(
            not,
            [
                "c-1@example.invalid",
                "c-2@example.invalid",
                "c-3@example.invalid"
            ],
            "Nothing selected and no scan"
        );
        assert_eq!(s.held, Some(3), "Nothing selected and no scan");
        assert_eq!(
            s.obtained_at, "2026-11-04T12:00:00+00:00",
            "Nothing selected and no scan"
        );
        assert_eq!(s.tier, "relay_reported", "Nothing selected and no scan");
        Ok(())
    }

    /// A scan queries up to `cap` held calls, in Call-ID order, and lists the
    /// rest as not queried; the text says how many of how many.
    #[test]
    fn a_scan_queries_up_to_the_cap_and_says_how_many_of_how_many() -> Result<(), TestError> {
        let relay = holding_three();
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 2), &never, &at);
        assert_eq!(
            relay.asked()?,
            [
                "list 32",
                "query c-1@example.invalid",
                "query c-2@example.invalid"
            ],
            "A scan queries up to `cap` held calls, in Call-ID order, and lists the rest as not queried"
        );
        let not: Vec<&str> = s.not_queried.iter().map(|n| n.call_id.as_str()).collect();
        assert_eq!(
            not,
            ["c-3@example.invalid"],
            "A scan queries up to `cap` held calls, in Call-ID order, and lists the rest as not queried"
        );
        let text = s.render(ReportFormat::Text);
        assert!(text.contains("queried 2 of 3"), "{text}");
        assert!(text.contains("c-3@example.invalid  not queried"), "{text}");
        Ok(())
    }

    /// The selected call is queried on every snapshot, scan or not, once, and
    /// even when the relay did not list it.
    #[test]
    fn the_selected_call_is_queried_once_even_when_not_listed() -> Result<(), TestError> {
        let relay = holding_three();
        let _first = relay_sessions(
            &relay,
            &permit()?,
            &ask(Some("c-2@example.invalid"), true, 2),
            &never,
            &at,
        );
        assert_eq!(
            relay.asked()?,
            [
                "list 32",
                "query c-2@example.invalid",
                "query c-1@example.invalid"
            ],
            "selected first, then the scan, and no call twice"
        );

        let relay = holding_three();
        let s = relay_sessions(
            &relay,
            &permit()?,
            &ask(Some("gone@example.invalid"), false, 2),
            &never,
            &at,
        );
        assert_eq!(
            relay.asked()?,
            ["list 32", "query gone@example.invalid"],
            "The selected call is queried on every snapshot, scan or not, once, and even when the relay did not list it"
        );
        assert_eq!(
            s.calls[0].call_id, "gone@example.invalid",
            "The selected call is queried on every snapshot, scan or not, once, and even when the relay did not list it"
        );
        assert_eq!(
            s.not_queried.len(),
            3,
            "The selected call is queried on every snapshot, scan or not, once, and even when the relay did not list it"
        );
        Ok(())
    }

    /// A selected call the relay does not hold is refused in the relay's own
    /// words; one whose query got no answer is unreachable. Neither is a call
    /// with no media.
    #[test]
    fn a_query_the_relay_declines_or_does_not_answer_is_said_so() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|verb, call| match (verb, call) {
            ("list", _) => Ok(listed(&HELD, false)),
            (_, Some("c-1@example.invalid")) => Ok(ControlReply::Refused {
                reason: "Unknown call-id".to_string(),
            }),
            _ => anyhow::bail!("timed out"),
        });
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 2), &never, &at);
        assert_eq!(
            s.calls[0].outcome, "refused",
            "A selected call the relay does not hold is refused in the relay's own words"
        );
        assert!(
            s.calls[0]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("Unknown call-id")),
            "{:?}",
            s.calls[0]
        );
        assert!(
            s.calls[0].directions.is_empty() && s.calls[0].tags.is_empty(),
            "A selected call the relay does not hold is refused in the relay's own words"
        );
        assert_eq!(
            s.calls[1].outcome, "unreachable",
            "A selected call the relay does not hold is refused in the relay's own words"
        );
        assert!(
            s.calls[1]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("timed out")),
            "{:?}",
            s.calls[1]
        );
        Ok(())
    }

    /// When `list` gets no answer, nothing else is sent and the snapshot says
    /// unreachable with the error; a declined `list` is refused in the
    /// relay's words; a reply that is not a call list is suspect.
    #[test]
    fn a_list_that_is_not_answered_sends_nothing_else() -> Result<(), TestError> {
        let silent = ScriptedRelay::new(|_, _| anyhow::bail!("timed out"));
        let s = relay_sessions(
            &silent,
            &permit()?,
            &ask(Some("c-1@example.invalid"), true, 2),
            &never,
            &at,
        );
        assert_eq!(
            silent.asked()?,
            ["list 32"],
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert_eq!(
            s.reach, "unreachable",
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert!(
            !s.answered(),
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert!(
            s.detail.as_deref().is_some_and(|d| d.contains("timed out")),
            "{s:?}"
        );
        let body = s.body();
        assert_eq!(
            body["outcome"], "unreachable",
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert_eq!(
            body["responsibility"], "relay_or_network",
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert!(body.get("calls").is_none(), "{body}");

        let refusing = ScriptedRelay::new(|_, _| {
            Ok(ControlReply::Refused {
                reason: "no list for you".to_string(),
            })
        });
        let s = relay_sessions(&refusing, &permit()?, &ask(None, true, 2), &never, &at);
        assert_eq!(
            s.reach, "refused",
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert!(
            s.detail
                .as_deref()
                .is_some_and(|d| d.contains("no list for you")),
            "{s:?}"
        );

        let odd = ScriptedRelay::new(|_, _| Ok(ControlReply::Statistics(Vec::new())));
        let s = relay_sessions(&odd, &permit()?, &ask(None, true, 2), &never, &at);
        assert_eq!(
            s.reach, "suspect",
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        assert_eq!(
            odd.asked()?,
            ["list 32"],
            "When `list` gets no answer, nothing else is sent and the snapshot says unreachable with the error"
        );
        Ok(())
    }

    /// `truncated` is the enumeration's own flag, carried; the text says the
    /// relay may hold more.
    #[test]
    fn a_full_list_says_the_relay_may_hold_more() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|_, _| Ok(listed(&HELD, true)));
        let s = relay_sessions(&relay, &permit()?, &ask(None, false, 2), &never, &at);
        assert_eq!(
            s.truncated,
            Some(true),
            "`truncated` is the enumeration's own flag, carried"
        );
        let text = s.render(ReportFormat::Text);
        assert!(text.contains("may hold more"), "{text}");
        Ok(())
    }

    /// A call sipnab saw end in SIP is marked `ended`, queried or not; the
    /// others say the relay may still list a call for about 30 s.
    #[test]
    fn a_call_sipnab_saw_end_is_marked_ended() -> Result<(), TestError> {
        let relay = holding_three();
        let ended = |c: &str| c == "c-1@example.invalid" || c == "c-3@example.invalid";
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 2), &ended, &at);
        assert_eq!(
            s.calls[0].sip_dialog,
            SipDialog::Ended,
            "A call sipnab saw end in SIP is marked `ended`, queried or not"
        );
        assert_eq!(
            s.calls[1].sip_dialog,
            SipDialog::NotSeenEnded,
            "A call sipnab saw end in SIP is marked `ended`, queried or not"
        );
        assert_eq!(
            s.not_queried[0].sip_dialog,
            SipDialog::Ended,
            "A call sipnab saw end in SIP is marked `ended`, queried or not"
        );
        assert!(
            s.notes.iter().any(|n| n == DELETE_DELAY_NOTE),
            "{:?}",
            s.notes
        );
        let text = s.render(ReportFormat::Text);
        assert!(text.contains("c-1@example.invalid  ended in SIP"), "{text}");
        assert!(text.contains("about 30 s"), "{text}");
        Ok(())
    }

    /// The body carries what the relay reported and nothing it did not: an
    /// absent counter is absent from the JSON, never a 0.
    #[test]
    fn the_body_leaves_out_what_the_relay_did_not_report() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|verb, call| match verb {
            "list" => Ok(listed(&["c-1@example.invalid"], false)),
            _ => {
                let mut caller = rtp(2250, 140, true);
                caller.ingress.errors = None;
                caller.egress = StreamCounters::default();
                Ok(ControlReply::Call(CallView {
                    call_id: call.unwrap_or_default().to_string(),
                    ..two_party(caller, rtp(2190, 140, true))
                }))
            }
        });
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 2), &never, &at);
        let body = s.body();
        assert_eq!(
            body["outcome"], "ok",
            "The body carries what the relay reported and nothing it did not"
        );
        let socket = &body["calls"][0]["tags"][0]["sockets"][0];
        assert_eq!(
            socket["ingress"]["packets"], 2250,
            "The body carries what the relay reported and nothing it did not"
        );
        assert!(socket["ingress"].get("errors").is_none(), "{socket}");
        assert_eq!(socket["egress"], json!({}), "{socket}");
        assert_eq!(
            body["calls"][0]["directions"][0]["verdict"], "flowing",
            "The body carries what the relay reported and nothing it did not"
        );
        Ok(())
    }

    /// The text names each direction's verdict in words: a stall says for
    /// how long, never "dead"; a never-received direction names the sender;
    /// an unjudged call says why.
    #[test]
    fn the_text_says_each_verdict_in_words() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|verb, call| match (verb, call) {
            ("list", _) => Ok(listed(
                &[
                    "a@example.invalid",
                    "b@example.invalid",
                    "c@example.invalid",
                ],
                false,
            )),
            (_, Some("a@example.invalid")) => Ok(ControlReply::Call(CallView {
                call_id: "a@example.invalid".to_string(),
                ..two_party(rtp(496, 130, true), rtp(714, 140, true))
            })),
            (_, Some("c@example.invalid")) => Ok(ControlReply::Call(CallView {
                call_id: "c@example.invalid".to_string(),
                ..two_party(rtp(2250, 140, true), rtp(0, 101, false))
            })),
            (_, c) => {
                let mut view = two_party(rtp(2189, 140, true), rtp(0, 102, false));
                view.call_id = c.unwrap_or_default().to_string();
                view.tags.push(party(
                    "early-tag-1",
                    &[],
                    vec![stream(30022, rtp(2260, 140, true))],
                ));
                Ok(ControlReply::Call(view))
            }
        });
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 3), &never, &at);
        let text = s.render(ReportFormat::Text);
        assert!(
            text.contains("from caller-tag-1: no packet for 10 s"),
            "{text}"
        );
        assert!(text.contains("from callee-tag-1: never received"), "{text}");
        assert!(!text.contains("dead"), "{text}");
        assert!(text.contains("early media branch"), "{text}");
        assert!(
            text.contains("2260"),
            "the unjudged counters are shown: {text}"
        );
        assert!(text.contains("relay_reported"), "{text}");
        Ok(())
    }

    /// A SIP request for `call_id`, parsed as it arrived from 192.0.2.10.
    fn sip(
        first_line: &str,
        method: &str,
        call_id: &str,
        ms: i64,
    ) -> Result<crate::sip::SipMessage, TestError> {
        let raw = crate::test_utils::build_sip_message(
            first_line,
            &[
                "From: <sip:alice@example.com>;tag=ft0100",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        Ok(crate::sip::parser::parse_sip(
            &raw,
            at() + chrono::TimeDelta::milliseconds(ms),
            std::net::IpAddr::from([192, 0, 2, 10]),
            std::net::IpAddr::from([192, 0, 2, 1]),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .map_err(|e| format!("parse: {e:?}"))?)
    }

    /// sipnab saw a call end when its dialog store holds it in a final state:
    /// a canceled INVITE has ended, one still trying has not, and a Call-ID
    /// the store never saw has not been seen ending.
    #[test]
    fn sipnab_saw_a_call_end_only_when_its_dialog_is_final() -> Result<(), TestError> {
        let mut store = crate::sip::dialog_store::DialogStore::new(100, false);
        store.process_message(sip(
            "INVITE sip:bob@example.com SIP/2.0",
            "INVITE",
            "up@example.invalid",
            0,
        )?);
        store.process_message(sip(
            "INVITE sip:bob@example.com SIP/2.0",
            "INVITE",
            "gone@example.invalid",
            1,
        )?);
        store.process_message(sip(
            "CANCEL sip:bob@example.com SIP/2.0",
            "CANCEL",
            "gone@example.invalid",
            2,
        )?);
        assert!(
            sip_saw_end(&store, "gone@example.invalid"),
            "sipnab saw a call end when its dialog store holds it in a final state"
        );
        assert!(
            !sip_saw_end(&store, "up@example.invalid"),
            "sipnab saw a call end when its dialog store holds it in a final state"
        );
        assert!(
            !sip_saw_end(&store, "never@example.invalid"),
            "sipnab saw a call end when its dialog store holds it in a final state"
        );
        Ok(())
    }

    /// A selected call the relay did not list is not counted among the
    /// listed calls queried; the status names it apart.
    #[test]
    fn a_selected_call_the_relay_did_not_list_is_counted_apart() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|verb, _| match verb {
            "list" => Ok(listed(&[], false)),
            _ => Ok(ControlReply::Refused {
                reason: "Unknown call-id".to_string(),
            }),
        });
        let s = relay_sessions(
            &relay,
            &permit()?,
            &ask(Some("gone@example.invalid"), false, 2),
            &never,
            &at,
        );
        let status = s.render_status();
        assert!(
            status.contains("reachable; 0 calls listed; queried 0 of 0; also asked about 1 call the relay did not list"),
            "the unlisted call is not one of the listed calls queried: {status}"
        );
        Ok(())
    }

    /// A relay holding nothing says so in words, and asks nothing else.
    #[test]
    fn a_relay_holding_nothing_says_so() -> Result<(), TestError> {
        let relay = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let s = relay_sessions(&relay, &permit()?, &ask(None, true, 2), &never, &at);
        assert_eq!(
            relay.asked()?,
            ["list 32"],
            "A relay holding nothing says so in words, and asks nothing else"
        );
        assert!(
            s.render(ReportFormat::Text)
                .contains("The relay holds no calls."),
            "{}",
            s.render(ReportFormat::Text)
        );
        Ok(())
    }

    // ── Several engines (engine selection) ──────────────────────────────

    /// One engine behind a scripted control address: the calls it lists, the
    /// calls it holds when queried, and every ask it received.
    struct EngineRelay {
        name: &'static str,
        lists: Vec<&'static str>,
        holds: Vec<&'static str>,
        down: bool,
        asked: Mutex<Vec<String>>,
    }

    impl EngineRelay {
        fn new(name: &'static str, lists: &[&'static str], holds: &[&'static str]) -> Arc<Self> {
            Arc::new(Self {
                name,
                lists: lists.to_vec(),
                holds: holds.to_vec(),
                down: false,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn down(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                lists: Vec::new(),
                holds: Vec::new(),
                down: true,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Result<Vec<String>, TestError> {
            Ok(self.asked.lock().map_err(|e| e.to_string())?.clone())
        }

        fn record(&self, what: String) -> anyhow::Result<()> {
            self.asked
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .push(what);
            Ok(())
        }
    }

    impl ReadOnlyRelay for EngineRelay {
        fn list(&self, _: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            self.record(format!("list {limit}"))?;
            if self.down {
                anyhow::bail!("no reply within 2s");
            }
            Ok(listed(&self.lists, false))
        }
        fn query(&self, _: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            self.record(format!("query {call_id}"))?;
            if self.holds.contains(&call_id) {
                Ok(ControlReply::Call(CallView {
                    call_id: call_id.to_string(),
                    ..two_party(rtp(2250, 140, true), rtp(2190, 140, true))
                }))
            } else {
                Ok(ControlReply::Refused {
                    reason: "Unknown call-id".to_string(),
                })
            }
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("a sessions snapshot never asks for statistics")
        }
        fn describe(&self) -> String {
            self.name.to_string()
        }
    }

    use crate::relay::engines::{
        Connect, EngineMap, EngineRouting, EngineRow, EngineRule, SdpSighting,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;

    const D: &str = "192.0.2.1:2223";
    const A: &str = "192.0.2.5:2223";
    const B: &str = "192.0.2.6:2223";

    /// The issue's NAT map, with `d` the default engine, and a connect that
    /// hands out `a` and `b` by control address.
    fn routing(
        engine_a: &Arc<EngineRelay>,
        engine_b: &Arc<EngineRelay>,
        previous: bool,
    ) -> Result<EngineRouting, TestError> {
        let rows = vec![
            "203.0.113.5 30000-39999 192.0.2.5:2223".parse::<EngineRow>()?,
            "203.0.113.5 40000-49999 192.0.2.6:2223".parse::<EngineRow>()?,
        ];
        let (engine_a, engine_b) = (Arc::clone(engine_a), Arc::clone(engine_b));
        let (a_addr, b_addr): (SocketAddr, SocketAddr) = (A.parse()?, B.parse()?);
        let connect: Connect = Arc::new(move |addr| -> Arc<dyn ReadOnlyRelay + Send + Sync> {
            if addr == a_addr {
                Arc::clone(&engine_a) as Arc<dyn ReadOnlyRelay + Send + Sync>
            } else if addr == b_addr {
                Arc::clone(&engine_b) as Arc<dyn ReadOnlyRelay + Send + Sync>
            } else {
                EngineRelay::down("an engine no test named")
            }
        });
        Ok(EngineRouting::new(
            EngineRule::Map(EngineMap::new(rows)?),
            D.parse()?,
            previous,
            connect,
        ))
    }

    fn sighting(secs: i64, from_request: bool, address: &str, port: u16) -> SdpSighting {
        SdpSighting {
            at: at() + chrono::TimeDelta::seconds(secs),
            from_request,
            address: address.to_string(),
            port,
        }
    }

    /// `m-1` moved from the engine at 30000-39999 to the one at 40000-49999;
    /// `u-1`'s SDP names media no row claims; every other call has no SDP.
    fn sdp_of(call_id: &str) -> crate::relay::engines::CallEvidence {
        sdp_sightings_of(call_id).into()
    }

    /// The SDP sightings [`sdp_of`] holds for `call_id`.
    fn sdp_sightings_of(call_id: &str) -> Vec<SdpSighting> {
        match call_id {
            "m-1@example.invalid" => vec![
                sighting(0, true, "203.0.113.5", 30010),
                sighting(1, false, "203.0.113.5", 30012),
                sighting(60, true, "203.0.113.5", 40010),
                sighting(61, false, "203.0.113.5", 40012),
            ],
            "u-1@example.invalid" => vec![
                sighting(0, true, "203.0.113.9", 50000),
                sighting(1, false, "203.0.113.9", 50002),
            ],
            _ => Vec::new(),
        }
    }

    /// The ng engine rows `2001 A`, `2002 B`, with `d` the default engine.
    fn ng_routing(
        engine_a: &Arc<EngineRelay>,
        engine_b: &Arc<EngineRelay>,
        previous: bool,
    ) -> Result<EngineRouting, TestError> {
        let (engine_a, engine_b) = (Arc::clone(engine_a), Arc::clone(engine_b));
        let (a_addr, b_addr): (SocketAddr, SocketAddr) = (A.parse()?, B.parse()?);
        let connect: Connect = Arc::new(move |addr| -> Arc<dyn ReadOnlyRelay + Send + Sync> {
            if addr == a_addr {
                Arc::clone(&engine_a) as Arc<dyn ReadOnlyRelay + Send + Sync>
            } else if addr == b_addr {
                Arc::clone(&engine_b) as Arc<dyn ReadOnlyRelay + Send + Sync>
            } else {
                EngineRelay::down("an engine no test named")
            }
        });
        let ng = crate::relay::engines::NgEngineMap::new(vec![
            format!("2001 {A}").parse()?,
            format!("2002 {B}").parse()?,
        ])?;
        Ok(EngineRouting::new(
            crate::relay::engines::EngineRules { sdp: None, ng },
            D.parse()?,
            previous,
            connect,
        ))
    }

    /// `l-1` was offered to homer-id `first`, then to 2002, with no delete.
    fn moved_by_ng(first: u32) -> impl Fn(&str) -> crate::relay::engines::CallEvidence {
        use crate::relay_vocab::{EngineIdentity, EngineSighting, EngineVerb};
        move |call_id: &str| {
            let offer = |secs: i64, id: u32| EngineSighting {
                at: at() + chrono::TimeDelta::seconds(secs),
                engine: EngineIdentity::HomerId(id),
                verb: EngineVerb::Offer,
                // What each unlisted engine's HEP copy reports: 2009 a
                // listen-ng another host can reach, 2008 its loopback.
                reported_listen_ng: match id {
                    2009 => Some(std::net::SocketAddr::from(([192, 0, 2, 9], 2223))),
                    2008 => Some(std::net::SocketAddr::from(([127, 0, 0, 1], 2223))),
                    _ => None,
                },
                frame: None,
            };
            crate::relay::engines::CallEvidence {
                sdp: Vec::new(),
                ng: if call_id == "l-1@example.invalid" {
                    vec![offer(0, first), offer(60, 2002)]
                } else {
                    Vec::new()
                },
            }
        }
    }

    /// The leftover snapshot of `l-1`: B lists it, A `holds` it or not.
    fn leftover_snapshot(
        a_holds: bool,
        previous: bool,
        first: u32,
    ) -> Result<(RelaySessions, Arc<EngineRelay>, Arc<EngineRelay>), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let held: &[&'static str] = if a_holds {
            &["l-1@example.invalid"]
        } else {
            &[]
        };
        let engine_a = EngineRelay::new("engine-a", &[], held);
        let engine_b = EngineRelay::new(
            "engine-b",
            &["l-1@example.invalid"],
            &["l-1@example.invalid"],
        );
        let rules = ng_routing(&engine_a, &engine_b, previous)?;
        let evidence = moved_by_ng(first);
        let routed = Routed {
            routing: &rules,
            sdp_of: &evidence,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        Ok((snap, engine_a, engine_b))
    }

    /// A call the ng traffic moved from 2001 to 2002 with no delete is asked
    /// of 2002; with `--relay-previous-engine`, 2001 is asked once and its
    /// answer confirms the leftover session.
    #[test]
    fn a_leftover_session_is_confirmed_by_asking_the_old_engine() -> Result<(), TestError> {
        let (snap, engine_a, engine_b) = leftover_snapshot(true, true, 2001)?;
        assert_eq!(
            engine_b.asked()?,
            ["list 32", "query l-1@example.invalid"],
            "the call is asked of the engine the newest offer reached"
        );
        assert_eq!(
            engine_a.asked()?,
            ["list 32", "query l-1@example.invalid"],
            "the old engine is asked once, for the previous engine and the leftover alike"
        );
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(engine.chosen_by, "ng_offer", "the offer chose it");
        assert_eq!(
            engine.leftovers,
            vec![LeftoverSession {
                engine: "homer-id 2001".to_string(),
                relay: Some("relay (engine-a)".to_string()),
                status: "confirmed".to_string(),
                detail: None,
            }],
            "the leftover is confirmed"
        );
        assert!(engine.held_by_several_engines, "both engines hold it");
        let text = snap.render(ReportFormat::Text);
        assert!(
            text.contains(
                "Leftover session on homer-id 2001 (relay (engine-a)): confirmed, it still \
                 holds this call."
            ),
            "{text}"
        );
        Ok(())
    }

    /// The old engine that no longer holds the call releases the flag; with
    /// no `--relay-previous-engine` it is flagged and not asked.
    #[test]
    fn a_leftover_is_released_by_its_answer_and_not_asked_without_the_option()
    -> Result<(), TestError> {
        let (snap, _, _) = leftover_snapshot(false, true, 2001)?;
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(
            engine.leftovers.first().map(|l| l.status.as_str()),
            Some("released"),
            "the old engine does not hold it"
        );
        let (snap, engine_a, _) = leftover_snapshot(true, false, 2001)?;
        assert_eq!(
            engine_a.asked()?,
            ["list 32"],
            "not asked without the option"
        );
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(
            engine
                .leftovers
                .first()
                .map(|l| (l.status.as_str(), l.detail.as_deref())),
            Some(("not_asked", Some("add --relay-previous-engine to ask it"))),
            "flagged, not asked"
        );
        let text = snap.render(ReportFormat::Text);
        assert!(
            text.contains(
                "Leftover session on homer-id 2001: not confirmed (not_asked: add \
                 --relay-previous-engine to ask it)."
            ),
            "{text}"
        );
        Ok(())
    }

    /// A leftover on an engine no row names is flagged and never asked, even
    /// with `--relay-previous-engine`.
    #[test]
    fn a_leftover_on_an_unlisted_engine_is_never_asked() -> Result<(), TestError> {
        let (snap, engine_a, _) = leftover_snapshot(true, true, 2009)?;
        assert_eq!(engine_a.asked()?, ["list 32"], "nothing else asked");
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(
            engine.leftovers,
            vec![LeftoverSession {
                engine: "homer-id 2009".to_string(),
                relay: None,
                status: "not_asked".to_string(),
                detail: Some(format!(
                    "no {flag} row names it. To list it, add {flag} '2009 192.0.2.9:2223', \
                     or ng_engines = [\"2009 192.0.2.9:2223\"] in the config file's [relay] \
                     section",
                    flag = crate::cli::RELAY_NG_ENGINE_FLAG
                )),
            }],
            "flagged, not asked, and given the row its HEP copy names"
        );
        Ok(())
    }

    /// A leftover on an address a captured offer reached and no row names is
    /// given the row that would list it, and is never asked.
    #[test]
    fn a_leftover_at_a_captured_address_is_given_its_row() -> Result<(), TestError> {
        use crate::relay_vocab::{EngineIdentity, EngineSighting, EngineVerb};
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let engine_a = EngineRelay::new("engine-a", &[], &[]);
        let engine_b = EngineRelay::new(
            "engine-b",
            &["l-1@example.invalid"],
            &["l-1@example.invalid"],
        );
        let rules = ng_routing(&engine_a, &engine_b, true)?;
        let evidence = |call_id: &str| crate::relay::engines::CallEvidence {
            sdp: Vec::new(),
            ng: if call_id == "l-1@example.invalid" {
                vec![
                    EngineSighting {
                        at: at(),
                        engine: EngineIdentity::ListenNg(std::net::SocketAddr::from((
                            [192, 0, 2, 99],
                            2223,
                        ))),
                        verb: EngineVerb::Offer,
                        reported_listen_ng: None,
                        frame: None,
                    },
                    EngineSighting {
                        at: at() + chrono::TimeDelta::seconds(60),
                        engine: EngineIdentity::HomerId(2002),
                        verb: EngineVerb::Offer,
                        reported_listen_ng: None,
                        frame: None,
                    },
                ]
            } else {
                Vec::new()
            },
        };
        let routed = Routed {
            routing: &rules,
            sdp_of: &evidence,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(
            engine
                .leftovers
                .iter()
                .map(|l| l.detail.clone())
                .collect::<Vec<_>>(),
            vec![Some(format!(
                "no {flag} row names it. To list it, add {flag} '192.0.2.99:2223', or \
                 ng_engines = [\"192.0.2.99:2223\"] in the config file's [relay] section",
                flag = crate::cli::RELAY_NG_ENGINE_FLAG
            ))],
            "flagged, given its row, and not asked"
        );
        assert_eq!(engine_a.asked()?, ["list 32"], "nothing else asked");
        Ok(())
    }

    /// A leftover on an unlisted engine whose HEP copy reported its loopback
    /// is given no row: no other host can reach that address. Nothing is
    /// asked of it either.
    #[test]
    fn a_leftover_reporting_loopback_is_given_no_row() -> Result<(), TestError> {
        let (snap, engine_a, _) = leftover_snapshot(true, true, 2008)?;
        assert_eq!(engine_a.asked()?, ["list 32"], "nothing else asked");
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("an engine")?;
        assert_eq!(
            engine
                .leftovers
                .iter()
                .map(|l| l.detail.clone())
                .collect::<Vec<_>>(),
            vec![Some(format!(
                "no {} row names it",
                crate::cli::RELAY_NG_ENGINE_FLAG
            ))],
            "flagged and not asked, with no row"
        );
        Ok(())
    }

    /// The moved call: listed by both engines, queried on the engine its
    /// newest SDP names and on the previous one, and flagged because both
    /// still hold it. The default engine is listed and never queried for it.
    #[test]
    fn a_moved_call_both_engines_hold_is_flagged() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let engine_a = EngineRelay::new(
            "engine-a",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let engine_b = EngineRelay::new(
            "engine-b",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert_eq!(
            default_engine.asked()?,
            ["list 32"],
            "the default engine is listed only"
        );
        assert_eq!(
            engine_a.asked()?,
            ["list 32", "query m-1@example.invalid"],
            "a moved call both engines hold is flagged"
        );
        assert_eq!(
            engine_b.asked()?,
            ["list 32", "query m-1@example.invalid"],
            "a moved call both engines hold is flagged"
        );
        assert_eq!(
            snap.reach, "ok",
            "a moved call both engines hold is flagged"
        );
        assert_eq!(
            snap.held,
            Some(1),
            "one distinct Call-ID across the engines"
        );
        let engines = snap.engines.as_ref().ok_or("several engines are listed")?;
        assert_eq!(
            engines.len(),
            3,
            "a moved call both engines hold is flagged"
        );
        let call = snap.calls.first().ok_or("the moved call is queried")?;
        assert_eq!(
            call.outcome, "ok",
            "a moved call both engines hold is flagged"
        );
        let engine = call.engine.as_ref().ok_or("the call names its engine")?;
        assert_eq!(
            engine.asked.as_deref(),
            Some("relay (engine-b)"),
            "a moved call both engines hold is flagged"
        );
        assert_eq!(
            engine.chosen_by, "map_row",
            "a moved call both engines hold is flagged"
        );
        assert_eq!(
            engine.listed_by,
            ["relay (engine-a)", "relay (engine-b)"],
            "a moved call both engines hold is flagged"
        );
        assert!(
            engine.held_by_several_engines,
            "a moved call both engines hold is flagged"
        );
        let previous = engine.previous.as_ref().ok_or("the previous engine")?;
        assert_eq!(
            previous.relay, "relay (engine-a)",
            "a moved call both engines hold is flagged"
        );
        assert!(previous.holds, "the old engine still holds the call");
        let text = snap.render(ReportFormat::Text);
        assert!(
            text.contains("held by several engines"),
            "the row is flagged: {text}"
        );
        assert!(
            text.contains("Previous engine relay (engine-a)")
                && text.contains("still holds this call"),
            "the call says which engine was left holding it: {text}"
        );
        Ok(())
    }

    /// Without the previous-engine option only the current engine is
    /// queried; the lists still show both engines hold the call.
    #[test]
    fn without_the_option_the_previous_engine_is_not_queried() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let engine_a = EngineRelay::new(
            "engine-a",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let engine_b = EngineRelay::new(
            "engine-b",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let rules = routing(&engine_a, &engine_b, false)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(Some("m-1@example.invalid"), false, 8),
            &never,
            &at,
        );
        assert_eq!(
            engine_a.asked()?,
            ["list 32"],
            "the previous engine is only listed"
        );
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("the call names its engine")?;
        assert!(
            engine.previous.is_none(),
            "without the option the previous engine is not queried"
        );
        assert!(engine.held_by_several_engines, "both lists name it");
        Ok(())
    }

    /// A call whose SDP names media no row claims is not queried anywhere,
    /// and says why.
    #[test]
    fn a_call_with_no_map_row_is_asked_of_no_engine() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&["u-1@example.invalid"], false)));
        let engine_a = EngineRelay::new("engine-a", &[], &[]);
        let engine_b = EngineRelay::new("engine-b", &[], &[]);
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert_eq!(
            default_engine.asked()?,
            ["list 32"],
            "no query to the default engine"
        );
        assert_eq!(
            engine_a.asked()?,
            ["list 32"],
            "a call with no map row is asked of no engine"
        );
        assert_eq!(
            engine_b.asked()?,
            ["list 32"],
            "a call with no map row is asked of no engine"
        );
        let call = snap.calls.first().ok_or("the listed call has an entry")?;
        assert_eq!(
            call.outcome, "not_configured",
            "a call with no map row is asked of no engine"
        );
        assert!(
            call.detail
                .as_deref()
                .is_some_and(|d| d.starts_with("engine unknown (no map row)")),
            "{:?}",
            call.detail
        );
        let engine = call.engine.as_ref().ok_or("the call names why")?;
        assert_eq!(
            engine.asked, None,
            "a call with no map row is asked of no engine"
        );
        assert_eq!(
            engine.chosen_by, "unknown",
            "a call with no map row is asked of no engine"
        );
        Ok(())
    }

    /// A call with no SDP seen is asked of the engine whose list names it,
    /// here the default; a selected call no engine lists is asked of the
    /// default. Each answer says why.
    #[test]
    fn a_call_with_no_sdp_is_asked_of_the_default_engine() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|verb, call| match (verb, call) {
            ("list", _) => Ok(listed(&["c-1@example.invalid"], false)),
            (_, call) => Ok(ControlReply::Call(CallView {
                call_id: call.unwrap_or_default().to_string(),
                ..two_party(rtp(10, 140, true), rtp(10, 140, true))
            })),
        });
        let engine_a = EngineRelay::new("engine-a", &[], &[]);
        let engine_b = EngineRelay::new("engine-b", &[], &[]);
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(Some("gone@example.invalid"), true, 8),
            &never,
            &at,
        );
        assert_eq!(
            default_engine.asked()?,
            [
                "list 32",
                "query gone@example.invalid",
                "query c-1@example.invalid"
            ],
            "a call with no sdp is asked of the default engine"
        );
        let chosen: Vec<(&str, &str, Option<&str>)> = snap
            .calls
            .iter()
            .filter_map(|c| {
                c.engine
                    .as_ref()
                    .map(|e| (c.call_id.as_str(), e.chosen_by.as_str(), e.asked.as_deref()))
            })
            .collect();
        assert_eq!(
            chosen,
            [
                (
                    "gone@example.invalid",
                    "default",
                    Some("relay (scripted at 192.0.2.10:22222)")
                ),
                (
                    "c-1@example.invalid",
                    "listed",
                    Some("relay (scripted at 192.0.2.10:22222)")
                ),
            ],
            "a call with no sdp is asked of the default engine"
        );
        Ok(())
    }

    /// A call with no SDP seen that only another engine lists is asked of
    /// that engine, not the default, which does not hold it.
    #[test]
    fn a_call_with_no_sdp_is_asked_of_the_engine_that_lists_it() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let engine_a = EngineRelay::new("engine-a", &[], &[]);
        let engine_b = EngineRelay::new(
            "engine-b",
            &["b-1@example.invalid"],
            &["b-1@example.invalid"],
        );
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert_eq!(
            default_engine.asked()?,
            ["list 32"],
            "the default engine is not queried"
        );
        assert_eq!(
            engine_b.asked()?,
            ["list 32", "query b-1@example.invalid"],
            "a call with no sdp is asked of the engine that lists it"
        );
        let engine = snap
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("the call names its engine")?;
        assert_eq!(
            engine.chosen_by, "listed",
            "a call with no sdp is asked of the engine that lists it"
        );
        assert_eq!(
            snap.calls.first().map(|c| c.outcome.as_str()),
            Some("ok"),
            "a call with no sdp is asked of the engine that lists it"
        );
        Ok(())
    }

    /// One engine down does not hide what the others hold; the answer names
    /// the engine that did not answer.
    #[test]
    fn one_engine_down_leaves_the_others_answer() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| Ok(listed(&[], false)));
        let engine_a = EngineRelay::down("engine-a");
        let engine_b = EngineRelay::new(
            "engine-b",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert_eq!(snap.reach, "ok", "one engine down leaves the others answer");
        let engines = snap.engines.as_ref().ok_or("the engines")?;
        let down = engines
            .iter()
            .find(|e| e.relay == "relay (engine-a)")
            .ok_or("engine-a is named")?;
        assert_eq!(
            down.reach, "unreachable",
            "one engine down leaves the others answer"
        );
        assert!(
            snap.render_status()
                .contains("relay (engine-a): unreachable"),
            "{}",
            snap.render_status()
        );
        Ok(())
    }

    /// The default engine down and another engine up is still an answer:
    /// the snapshot is answered when any engine answered its `list`.
    #[test]
    fn the_default_engine_down_leaves_the_others_answer() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| anyhow::bail!("no reply within 2s"));
        let engine_a = EngineRelay::new("engine-a", &[], &[]);
        let engine_b = EngineRelay::new(
            "engine-b",
            &["m-1@example.invalid"],
            &["m-1@example.invalid"],
        );
        let rules = routing(&engine_a, &engine_b, false)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert!(snap.answered(), "{snap:?}");
        assert_eq!(
            snap.held,
            Some(1),
            "the default engine down leaves the others answer"
        );
        assert_eq!(
            engine_b.asked()?,
            ["list 32", "query m-1@example.invalid"],
            "the default engine down leaves the others answer"
        );
        Ok(())
    }

    /// Every engine down is a snapshot that was not answered.
    #[test]
    fn every_engine_down_is_unanswered() -> Result<(), TestError> {
        let default_engine = ScriptedRelay::new(|_, _| anyhow::bail!("no reply within 2s"));
        let engine_a = EngineRelay::down("engine-a");
        let engine_b = EngineRelay::down("engine-b");
        let rules = routing(&engine_a, &engine_b, true)?;
        let routed = Routed {
            routing: &rules,
            sdp_of: &sdp_of,
        };
        let snap = relay_sessions_routed(
            &default_engine,
            Some(&routed),
            &permit()?,
            &ask(None, true, 8),
            &never,
            &at,
        );
        assert!(!snap.answered(), "every engine down is unanswered");
        assert_eq!(snap.reach, "unreachable", "every engine down is unanswered");
        Ok(())
    }

    /// Without engine selection the answer carries no engine fields, so a
    /// single-relay run reads exactly as it did.
    #[test]
    fn a_single_relay_answer_carries_no_engine_fields() -> Result<(), TestError> {
        let relay = holding_three();
        let snap =
            relay_sessions_routed(&relay, None, &permit()?, &ask(None, true, 2), &never, &at);
        let body = snap.body();
        assert!(body.get("engines").is_none(), "{body}");
        let calls = body["calls"].as_array().ok_or("calls")?;
        assert!(calls.iter().all(|c| c.get("engine").is_none()), "{body}");
        let nq = body["not_queried"].as_array().ok_or("not_queried")?;
        assert!(nq.iter().all(|c| c.get("engine").is_none()), "{body}");
        Ok(())
    }

    /// A routed snapshot of fake engines, the first being the default, and
    /// how long it took.
    fn udp_snapshot(
        fakes: &[crate::test_engines::FakeEngine],
    ) -> Result<(RelaySessions, std::time::Duration), TestError> {
        use crate::test_engines::{TIMEOUT, client, routing};
        let rules = routing(&fakes.iter().collect::<Vec<_>>(), TIMEOUT)?;
        let default = client(rules.default_engine(), TIMEOUT);
        let evidence = |_: &str| crate::relay::engines::CallEvidence::default();
        let routed = Routed {
            routing: &rules,
            sdp_of: &evidence,
        };
        let started = std::time::Instant::now();
        let snap = relay_sessions_routed(
            default.as_ref(),
            Some(&routed),
            &permit()?,
            &ask(None, false, 8),
            &never,
            &at,
        );
        Ok((snap, started.elapsed()))
    }

    /// Each engine's listing, as `relay reach`.
    fn reaches(snap: &RelaySessions) -> Vec<String> {
        snap.engines
            .iter()
            .flatten()
            .map(|l| format!("{} {}", l.relay, l.reach))
            .collect()
    }

    /// Dead engines cost one timeout, and each engine's listing is in its
    /// configured place.
    #[test]
    fn sessions_with_dead_engines_cost_one_timeout() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, one_timeout};
        let fakes = [
            FakeEngine::live()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let (snap, took) = udp_snapshot(&fakes)?;
        assert!(
            one_timeout(took),
            "one timeout, not three: {took:?}: {:?}",
            snap.engines
        );
        let want: Vec<String> = fakes
            .iter()
            .zip(["ok", "unreachable", "unreachable", "unreachable"])
            .map(|(f, r)| format!("relay ({}) {r}", f.describe()))
            .collect();
        assert_eq!(
            reaches(&snap),
            want,
            "each engine's listing in its own place"
        );
        assert_eq!(snap.held, Some(1), "the live engine's call is held");
        Ok(())
    }

    /// A listing cut short reads suspect in its own place, after a prompt
    /// one and before a late one.
    #[test]
    fn a_cut_listing_is_suspect_in_its_own_place() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, LIST_BODY};
        let fakes = [
            FakeEngine::live()?,
            FakeEngine::cut()?,
            FakeEngine::answering(LIST_BODY, std::time::Duration::from_millis(300))?,
        ];
        let (snap, _) = udp_snapshot(&fakes)?;
        let got: Vec<String> = reaches(&snap)
            .iter()
            .filter_map(|r| r.rsplit(' ').next().map(str::to_owned))
            .collect();
        assert_eq!(
            got,
            vec!["ok", "suspect", "ok"],
            "the cut listing is suspect between two that answered"
        );
        Ok(())
    }

    /// A snapshot asked with a clamped cap carries the clamp and states it
    /// in its status line; one asked without states nothing.
    #[test]
    fn a_clamped_scan_states_the_clamp() -> Result<(), TestError> {
        let cap = crate::relay::scan_cap::ScanCap {
            cap: 1024,
            clamped: Some(crate::relay::scan_cap::CapClamp {
                requested: 9000,
                ceiling: 1024,
            }),
        };
        let s = relay_sessions(
            &holding_three(),
            &permit()?,
            &SessionsAsk::capped(None, true, cap),
            &never,
            &at,
        );
        assert_eq!(
            (s.cap, s.list_limit),
            (1024, 1024),
            "A snapshot asked with a clamped cap carries the clamp and states it in its status line; one asked without states nothing"
        );
        let status = s.render_status();
        assert!(
            status.contains("Asked for 9000 calls; the ceiling is 1024"),
            "{status}"
        );
        let plain = relay_sessions(
            &holding_three(),
            &permit()?,
            &ask(None, true, 32),
            &never,
            &at,
        );
        assert!(
            !plain.render_status().contains("ceiling"),
            "{}",
            plain.render_status()
        );
        Ok(())
    }
}
