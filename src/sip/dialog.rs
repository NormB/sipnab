// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP dialog type and state machine.
//!
//! A [`SipDialog`] tracks the lifecycle of a SIP conversation identified by
//! its Call-ID. The [`DialogState`] enum models the state machine transitions
//! for INVITE, REGISTER, and SUBSCRIBE dialogs, driven by incoming SIP
//! messages.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::SipMessage;
use super::method::SipMethod;
use super::sdp_timeline::SdpExchange;
use super::timing::DialogTiming;

/// Dialog lifecycle state, covering INVITE, REGISTER, and SUBSCRIBE flows.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub enum DialogState {
    /// INVITE sent, no provisional response yet.
    Trying,
    /// 180 Ringing or 183 Session Progress received.
    Ringing,
    /// 200 OK to INVITE received; media session active.
    InCall,
    /// BYE completed; dialog terminated normally.
    Completed,
    /// The INVITE transaction was terminated: a CANCEL was seen, a 487 came
    /// back, or both. Either alone is enough — the CANCEL can take a different
    /// path from the response, and a capture can begin mid-dialog.
    Cancelled,
    /// Final error response received (4xx, 5xx, or 6xx).
    Failed,
    /// REGISTER 200 OK received; registration active.
    Registered,
    /// Registration expired or de-registered.
    Expired,
    /// SUBSCRIBE pending (no 200 OK yet).
    Pending,
    /// SUBSCRIBE active (200 OK received or NOTIFY in-dialog).
    Active,
    /// Subscription terminated.
    Terminated,
    /// REFER sent; transfer in progress.
    Transferring,
}

impl std::fmt::Display for DialogState {
    /// Write the state's canonical name (e.g. "InCall") to `f`; matches the
    /// spellings the filter DSL compares against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Trying => "Trying",
            Self::Ringing => "Ringing",
            Self::InCall => "InCall",
            Self::Completed => "Completed",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
            Self::Registered => "Registered",
            Self::Expired => "Expired",
            Self::Pending => "Pending",
            Self::Active => "Active",
            Self::Terminated => "Terminated",
            Self::Transferring => "Transferring",
        })
    }
}

/// A tracked SIP dialog (call, registration, or subscription).
///
/// Created when the first message for a given Call-ID is processed.
/// Updated by subsequent messages via [`update_state`].
#[derive(Debug)]
pub struct SipDialog {
    /// Call-ID that uniquely identifies this dialog.
    pub call_id: String,
    /// User part extracted from the From URI.
    pub from_user: Option<String>,
    /// User part extracted from the To URI.
    pub to_user: Option<String>,
    /// Host (with optional `:port`) extracted from the From URI.
    pub from_host: Option<String>,
    /// Host (with optional `:port`) extracted from the To URI.
    pub to_host: Option<String>,
    /// Tag parameter from the From header.
    pub from_tag: Option<String>,
    /// Tag parameter from the To header.
    pub to_tag: Option<String>,
    /// Display name from the From header.
    pub from_display: Option<String>,
    /// Display name from the To header.
    pub to_display: Option<String>,
    /// Current dialog state (private — use `state()` accessor and `update_state()` mutator).
    state: DialogState,
    /// Initial SIP method that created this dialog (e.g., `SipMethod::Invite`).
    pub method: SipMethod,
    /// All SIP messages seen in this dialog, in order.
    pub messages: Vec<SipMessage>,
    /// Timestamp when this dialog was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the most recent message update.
    pub updated_at: DateTime<Utc>,
    /// User-supplied tags (from `--tag` CLI flag).
    pub tags: Vec<String>,
    /// Source IP address of the initial message.
    pub src_addr: IpAddr,
    /// Destination IP address of the initial message.
    pub dst_addr: IpAddr,
    /// Source port of the initial message (stable across message
    /// compaction, unlike `messages.first()`).
    pub src_port: u16,
    /// Destination port of the initial message.
    pub dst_port: u16,
    /// Transaction timing measurements.
    pub timing: DialogTiming,
    /// SDP offer/answer timeline.
    pub sdp_timeline: Vec<SdpExchange>,
    /// REFER transfer target URI, if a REFER has been received in this dialog.
    pub refer_to: Option<String>,
    /// SIPREC recording metadata, if present.
    pub siprec_metadata: Option<super::siprec::SirecMetadata>,
    /// CSeq identities seen in this dialog, for O(1) retransmission
    /// detection independent of message retention (capped; see
    /// [`MAX_SEEN_CSEQ_PER_DIALOG`]). Key format:
    /// `"<R|r><status> <seq> <method>"`.
    pub(crate) seen_cseq: std::collections::HashSet<String>,
}

/// Cap on per-dialog seen-CSeq entries: a hostile peer cycling CSeq
/// numbers must not grow memory without bound. Past the cap, new CSeq
/// identities are no longer remembered (their later retransmissions go
/// undetected — same degraded mode the old stored-message scan had past
/// the message cap).
pub const MAX_SEEN_CSEQ_PER_DIALOG: usize = 4096;

/// Build the seen-set key identifying a message for retransmission
/// purposes: direction, status code (responses), CSeq number, method, and
/// the top-Via branch (the RFC 3261 transaction ID). Without the branch,
/// distinct transactions that reuse Call-ID + CSeq — e.g. OPTIONS or
/// REGISTER keepalives — would be misclassified as retransmissions.
/// Messages lacking a branch (RFC 2543 peers) fall back to CSeq identity.
/// `\n` separates the branch because header values cannot contain one
/// after parsing, so a crafted CSeq method can't collide with a branch.
///
/// # Arguments
///
/// * `msg` — The parsed SIP message to derive an identity key for.
///
/// # Returns
///
/// The identity key string, or `None` when the message has no parseable
/// CSeq header (such a message cannot be tracked for retransmission).
pub(crate) fn seen_cseq_key(msg: &SipMessage) -> Option<String> {
    let (seq, method) = msg.cseq()?;
    let branch = msg.top_via_branch().unwrap_or("");
    Some(if msg.is_request {
        format!("R {seq} {method}\n{branch}")
    } else {
        format!("r{} {seq} {method}\n{branch}", msg.status_code.unwrap_or(0))
    })
}

impl SipDialog {
    /// Returns a reference to the current dialog state.
    pub fn state(&self) -> &DialogState {
        &self.state
    }

    /// The final SIP response code of the call's INVITE transaction — the code
    /// that determined the outcome behind the [`DialogState`] word: 200 for an
    /// answered call (`InCall`/`Completed`), the 4xx/5xx/6xx for a `Failed` one
    /// (486 busy vs 503 unavailable vs 404 …), 487 for `Cancelled`. Returns
    /// `None` while the call is still in progress (no final response yet), so a
    /// `Ringing`/`Trying` dialog shows no code.
    ///
    /// Considers final (`>= 200`) responses carrying a CSeq method of `INVITE`
    /// (responses to CANCEL/BYE — their own CSeq — are excluded, so a cancelled
    /// call reports 487, not the 200 that acknowledged its CANCEL). Auth
    /// challenges (401/407) are *intermediate* — a call challenged then answered
    /// reports its real outcome (200), not the 407 — so they are ignored unless
    /// the call was *only* ever challenged (never authenticated), in which case
    /// the challenge is the outcome.
    pub fn final_status_code(&self) -> Option<u16> {
        // Single scan, no intermediate Vec: track the max final INVITE code
        // both excluding and including the 401/407 auth challenges. The
        // non-auth max is the answer when any non-challenge final exists;
        // otherwise (challenged but never authenticated) the challenge itself
        // is the outcome.
        let mut max_non_auth: Option<u16> = None;
        let mut max_any: Option<u16> = None;
        for m in &self.messages {
            if m.is_request {
                continue;
            }
            if m.cseq().map(|(_, method)| method) != Some("INVITE") {
                continue;
            }
            let Some(code) = m.status_code else { continue };
            if code < 200 {
                continue;
            }
            max_any = max_any.max(Some(code));
            if code != 401 && code != 407 {
                max_non_auth = max_non_auth.max(Some(code));
            }
        }
        max_non_auth.or(max_any)
    }

    /// Create a new dialog from the first message in a conversation.
    ///
    /// Initializes the dialog state based on the message's method:
    /// - INVITE → `Trying`
    /// - REGISTER → `Trying`
    /// - SUBSCRIBE → `Pending`
    /// - All others → `Trying`
    ///
    /// For a response, the dialog method is derived from the CSeq header.
    ///
    /// # Arguments
    ///
    /// * `msg` — The first message of the conversation; cloned into the
    ///   dialog's message list and mined for From/To identity, addresses,
    ///   timestamps, and the initial seen-CSeq entry.
    ///
    /// # Returns
    ///
    /// The new dialog, or `None` when the message carries no Call-ID (no
    /// dialog identity exists without one) or when its method cannot be
    /// determined.
    ///
    /// The second case used to fabricate `SipMethod::Custom("UNKNOWN")`, and
    /// that was not a cosmetic placeholder. `method` is set once here and never
    /// corrected: a malformed response — Call-ID present, CSeq absent or
    /// unparseable — arriving BEFORE the INVITE created a dialog under that
    /// Call-ID labelled `UNKNOWN`, and the real INVITE then matched the
    /// existing entry and left the label wrong for the rest of the capture.
    /// `dialog_store`'s INVITE-specific matching (`candidate.method ==
    /// SipMethod::Invite`) stops working on that dialog, and every per-method
    /// count and filter reports it under a method nothing sent.
    ///
    /// Declining to create it is what keeps the later INVITE able to create it
    /// correctly, and matches the rule already applied one line above: a
    /// message that cannot supply a dialog identity does not get a dialog. The
    /// message itself is still captured, counted and searchable — only the
    /// dialog correlation is withheld, which is the thing that could not be
    /// established.
    pub fn new(msg: &SipMessage) -> Option<Self> {
        let call_id = msg.call_id()?.to_string();
        let method = if msg.is_request {
            msg.method.clone()?
        } else {
            // For responses, derive the method from CSeq.
            msg.cseq().map(|(_, m)| SipMethod::parse(m))?
        };

        let initial_state = match method {
            SipMethod::Subscribe => DialogState::Pending,
            _ => DialogState::Trying,
        };

        Some(SipDialog {
            call_id,
            from_user: msg.from_user(),
            to_user: msg.to_user(),
            from_host: msg.from_host(),
            to_host: msg.to_host(),
            from_tag: msg.from_tag().map(str::to_string),
            to_tag: msg.to_tag().map(str::to_string),
            from_display: msg.from_display(),
            to_display: msg.to_display(),
            state: initial_state,
            method,
            messages: vec![msg.clone()],
            created_at: msg.timestamp,
            updated_at: msg.timestamp,
            src_addr: msg.src_addr,
            dst_addr: msg.dst_addr,
            src_port: msg.src_port,
            dst_port: msg.dst_port,
            tags: Vec::new(),
            timing: DialogTiming::default(),
            sdp_timeline: Vec::new(),
            refer_to: None,
            siprec_metadata: None,
            seen_cseq: seen_cseq_key(msg).into_iter().collect(),
        })
    }
}

/// Transition the dialog state based on a new SIP message.
///
/// Applies the state machine rules for the dialog's initial method:
/// - **INVITE**: 100→Trying, 180/183→Ringing, 2xx→InCall,
///   4xx/5xx/6xx→Failed, CANCEL or 487→Cancelled, BYE→Completed
/// - **REGISTER**: 2xx→Registered, 4xx/5xx/6xx→Failed
/// - **SUBSCRIBE**: 2xx→Active, NOTIFY→Active, 4xx/5xx/6xx→Terminated
/// - **all other methods**: 2xx→Completed, 4xx/5xx/6xx→Failed
///
/// ACK messages are recorded but do not cause state transitions.
///
/// # Arguments
///
/// * `dialog` — The dialog whose state machine is advanced.
/// * `msg` — The incoming SIP message driving the transition.
///
/// # Side effects
///
/// May rewrite `dialog.state`, and captures the remote tag into
/// `dialog.to_tag` the first time a To tag appears (typically in the
/// first response from the far end). No other fields are touched.
pub fn update_state(dialog: &mut SipDialog, msg: &SipMessage) {
    match dialog.method {
        SipMethod::Invite => update_invite_state(dialog, msg),
        SipMethod::Register => update_register_state(dialog, msg),
        SipMethod::Subscribe => update_subscribe_state(dialog, msg),
        _ => {
            // For unknown methods, apply basic response code logic
            update_generic_state(dialog, msg);
        }
    }

    // Always capture the to_tag if we haven't yet (remote tag arrives in responses)
    if dialog.to_tag.is_none()
        && let Some(tag) = msg.to_tag()
    {
        dialog.to_tag = Some(tag.to_string());
    }
}

/// State transitions for INVITE dialogs, driven by `msg`.
///
/// Requests: CANCEL→Cancelled, BYE→Completed, REFER while
/// InCall→Transferring, NOTIFY with `Subscription-State: terminated`
/// while Transferring→InCall (the transfer subscription ended); ACK and
/// other in-dialog requests (re-INVITE, UPDATE, …) leave the state
/// unchanged. Responses: 180/183 while Trying/Ringing→Ringing; 2xx whose
/// CSeq method is INVITE while Trying/Ringing→InCall; 4xx–6xx whose CSeq
/// method is INVITE while Trying/Ringing→Failed; 487 whose CSeq method is
/// INVITE while Trying/Ringing/Cancelled→Cancelled; 100 confirms the current
/// state without changing it.
///
/// # Side effects
///
/// May rewrite `dialog.state`; no other fields are touched.
fn update_invite_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if msg.is_request {
        match msg.method.as_ref() {
            Some(SipMethod::Cancel) => {
                dialog.state = DialogState::Cancelled;
            }
            Some(SipMethod::Bye) => {
                dialog.state = DialogState::Completed;
            }
            Some(SipMethod::Ack) => {
                // ACK doesn't change state
            }
            Some(SipMethod::Refer) => {
                if dialog.state == DialogState::InCall {
                    dialog.state = DialogState::Transferring;
                }
            }
            Some(SipMethod::Notify) => {
                // Match the exact Subscription-State value token (RFC 6665
                // §8.4: `substate-value *(";" subexp-params)`), not a prefix —
                // `starts_with("terminated")` would also fire on
                // `terminatedfoo`. Same fix as timing.rs.
                if dialog.state == DialogState::Transferring
                    && let Some(sub_state) = msg.header("Subscription-State")
                    && sub_state.split(';').next().unwrap_or("").trim() == "terminated"
                {
                    dialog.state = DialogState::InCall;
                }
            }
            _ => {
                // Re-INVITE, UPDATE, etc. don't change top-level dialog state
            }
        }
    } else if let Some(code) = msg.status_code {
        // Only process responses to the dialog's CSeq method context
        match code {
            100 => {
                if dialog.state == DialogState::Trying {
                    // Stay in Trying (100 confirms server received it)
                }
            }
            180 | 183 => {
                if dialog.state == DialogState::Trying || dialog.state == DialogState::Ringing {
                    dialog.state = DialogState::Ringing;
                }
            }
            200..=299 => {
                let cseq_method = msg.cseq().map(|(_, m)| m).unwrap_or_default();
                // A 2xx to INVITE establishes the call. It also wins a race
                // with a CANCEL (RFC 3261 §9/§15: once the UAS has sent a
                // final 2xx the CANCEL has no effect), so Cancelled → InCall.
                if cseq_method == "INVITE"
                    && matches!(
                        dialog.state,
                        DialogState::Trying | DialogState::Ringing | DialogState::Cancelled
                    )
                {
                    dialog.state = DialogState::InCall;
                }
                // 200 OK to BYE doesn't further change state (already Completed)
            }
            487 => {
                // 487 Request Terminated: the INVITE transaction was ended by a
                // CANCEL or BYE (RFC 3261 §21.4.25). The 487 is itself the
                // proof, so having seen the CANCEL is NOT a precondition — it
                // can take a different path from the response, and a capture can
                // start mid-dialog or drop it under sampling.
                //
                // Guarded on the pre-answer states for the same reason the 2xx
                // arm is: once a final 2xx has established the call the CANCEL
                // has no effect (§9, §15), so a late 487 must not un-answer it.
                let cseq_method = msg.cseq().map(|(_, m)| m).unwrap_or_default();
                if cseq_method == "INVITE"
                    && matches!(
                        dialog.state,
                        DialogState::Trying | DialogState::Ringing | DialogState::Cancelled
                    )
                {
                    dialog.state = DialogState::Cancelled;
                }
            }
            400..=699 => {
                // Error responses to the initial INVITE
                let cseq_method = msg.cseq().map(|(_, m)| m).unwrap_or_default();
                if cseq_method == "INVITE"
                    && (dialog.state == DialogState::Trying || dialog.state == DialogState::Ringing)
                {
                    dialog.state = DialogState::Failed;
                }
            }
            _ => {}
        }
    }
}

/// State transitions for REGISTER dialogs: a 2xx response moves the
/// dialog to `Registered`, a 4xx–6xx response (including 401/407 auth
/// challenges) to `Failed`; requests and provisional responses are
/// ignored.
///
/// # Side effects
///
/// May rewrite `dialog.state`.
fn update_register_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if !msg.is_request
        && let Some(code) = msg.status_code
    {
        match code {
            200..=299 => {
                dialog.state = DialogState::Registered;
            }
            // 401/407 are auth challenges: the client re-registers with
            // credentials, so a challenge is intermediate, not a failure.
            // Leave the state unchanged (auth pending); a genuine 4xx-6xx
            // below marks Failed, and a later 2xx marks Registered.
            401 | 407 => {}
            400..=699 => {
                dialog.state = DialogState::Failed;
            }
            _ => {}
        }
    }
}

/// State transitions for SUBSCRIBE dialogs: an in-dialog NOTIFY request
/// or a 2xx response moves the dialog to `Active`; a 4xx–6xx response to
/// `Terminated`; other requests and provisional responses are ignored.
///
/// # Side effects
///
/// May rewrite `dialog.state`.
fn update_subscribe_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if msg.is_request {
        if msg.method.as_ref() == Some(&SipMethod::Notify) {
            dialog.state = DialogState::Active;
        }
    } else if let Some(code) = msg.status_code {
        match code {
            200..=299 => {
                dialog.state = DialogState::Active;
            }
            400..=699 => {
                dialog.state = DialogState::Terminated;
            }
            _ => {}
        }
    }
}

/// Generic state transitions for methods without a dedicated state
/// machine (OPTIONS, MESSAGE, standalone NOTIFY, …): a 2xx response moves
/// the dialog to `Completed`, a 4xx–6xx response to `Failed`; requests
/// and provisional responses are ignored.
///
/// # Side effects
///
/// May rewrite `dialog.state`.
fn update_generic_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if !msg.is_request
        && let Some(code) = msg.status_code
    {
        match code {
            200..=299 => {
                dialog.state = DialogState::Completed;
            }
            400..=699 => {
                dialog.state = DialogState::Failed;
            }
            _ => {}
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for dialog creation and the per-method state machines
/// (INVITE, REGISTER, SUBSCRIBE, and REFER-driven transfers).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed 127.0.0.1 address used as both source and destination of
    /// every test message.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed timestamp (2024-06-15 12:00:00 UTC) so tests are deterministic.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build and parse a minimal INVITE (CSeq 1, from-tag only) for the
    /// shared `dialog-test@example.com` Call-ID.
    fn make_invite() -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.com>",
                "Call-ID: dialog-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE")
    }

    /// Build and parse a response with the given status, reason phrase, and
    /// CSeq method, carrying both from- and to-tags.
    fn make_response(status: u16, reason: &str, cseq_method: &str) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.com>;tag=t2",
                "Call-ID: dialog-test@example.com",
                &format!("CSeq: 1 {cseq_method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse response")
    }

    /// Build and parse an in-dialog request (CSeq 2) for the given method.
    fn make_request(method: &str) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:bob@example.com SIP/2.0"),
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.com>;tag=t2",
                "Call-ID: dialog-test@example.com",
                &format!("CSeq: 2 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse request")
    }

    /// Full INVITE lifecycle: Trying → (100) Trying → (180) Ringing →
    /// (200) InCall → (BYE) Completed, with identity fields populated.
    #[test]
    fn invite_full_lifecycle() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        assert_eq!(dialog.state, DialogState::Trying);
        assert_eq!(dialog.method, SipMethod::Invite);
        assert_eq!(dialog.call_id, "dialog-test@example.com");
        assert_eq!(dialog.from_user.as_deref(), Some("alice"));
        assert_eq!(dialog.to_user.as_deref(), Some("bob"));
        assert_eq!(dialog.from_display.as_deref(), Some("Alice"));
        assert_eq!(dialog.to_display.as_deref(), Some("Bob"));
        assert_eq!(dialog.from_tag.as_deref(), Some("t1"));

        // 100 Trying
        let trying = make_response(100, "Trying", "INVITE");
        update_state(&mut dialog, &trying);
        assert_eq!(dialog.state, DialogState::Trying);

        // 180 Ringing
        let ringing = make_response(180, "Ringing", "INVITE");
        update_state(&mut dialog, &ringing);
        assert_eq!(dialog.state, DialogState::Ringing);
        assert_eq!(dialog.to_tag.as_deref(), Some("t2"));

        // 200 OK
        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::InCall);

        // BYE
        let bye = make_request("BYE");
        update_state(&mut dialog, &bye);
        assert_eq!(dialog.state, DialogState::Completed);
    }

    /// CANCEL during Ringing moves the dialog to Cancelled, and the 487
    /// confirmation keeps it there.
    #[test]
    fn invite_cancelled() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ringing = make_response(180, "Ringing", "INVITE");
        update_state(&mut dialog, &ringing);
        assert_eq!(dialog.state, DialogState::Ringing);

        let cancel = make_request("CANCEL");
        update_state(&mut dialog, &cancel);
        assert_eq!(dialog.state, DialogState::Cancelled);

        // 487 confirms the cancellation
        let terminated = make_response(487, "Request Terminated", "INVITE");
        update_state(&mut dialog, &terminated);
        assert_eq!(dialog.state, DialogState::Cancelled);
    }

    /// A 487 with no CANCEL in the capture still marks the dialog Cancelled.
    ///
    /// RFC 3261 §21.4.25: a 487 means the request "was terminated by a BYE or
    /// CANCEL request". The 487 alone is the proof; seeing the CANCEL is not a
    /// precondition for believing it. A CANCEL can take a different path from
    /// the response, a capture can start mid-dialog, and sampling can drop it.
    ///
    /// This arm previously did nothing at all unless the dialog was ALREADY
    /// Cancelled, and because `487` matches before the `400..=699` arm the
    /// response did not fall through to Failed either. A cancelled call whose
    /// CANCEL went uncaptured therefore sat in Ringing forever — reported as a
    /// call still waiting for an answer, which is a different diagnosis from
    /// the one the wire actually carried.
    #[test]
    fn invite_487_without_a_captured_cancel_is_cancelled() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ringing = make_response(180, "Ringing", "INVITE");
        update_state(&mut dialog, &ringing);
        assert_eq!(dialog.state, DialogState::Ringing);

        // No CANCEL is fed in: the 487 is the only evidence of termination.
        let terminated = make_response(487, "Request Terminated", "INVITE");
        update_state(&mut dialog, &terminated);
        assert_eq!(
            dialog.state,
            DialogState::Cancelled,
            "a 487 is proof the INVITE transaction was terminated, with or \
             without the CANCEL in the capture"
        );
    }

    /// A 487 arriving after the call was answered does NOT cancel it.
    ///
    /// The 2xx wins the race (RFC 3261 §9, §15): once a final 2xx is sent the
    /// CANCEL has no effect. Guarding the transition on Trying/Ringing/Cancelled
    /// is what keeps a late or duplicated 487 from rewriting an established
    /// call, and mirrors the guard the 2xx arm uses.
    #[test]
    fn invite_487_after_answer_does_not_cancel() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::InCall);

        let terminated = make_response(487, "Request Terminated", "INVITE");
        update_state(&mut dialog, &terminated);
        assert_eq!(
            dialog.state,
            DialogState::InCall,
            "a 487 after a 2xx must not un-answer an established call"
        );
    }

    /// A 503 error response to the initial INVITE moves the dialog to Failed.
    #[test]
    fn invite_failed() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let error = make_response(503, "Service Unavailable", "INVITE");
        update_state(&mut dialog, &error);
        assert_eq!(dialog.state, DialogState::Failed);
    }

    /// A REGISTER dialog starts in Trying and moves to Registered on 200 OK.
    #[test]
    fn register_success() {
        let raw = build_sip(
            "REGISTER sip:registrar.example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=r1",
                "To: <sip:alice@example.com>",
                "Call-ID: register-test@example.com",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let register = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse REGISTER");

        let mut dialog = SipDialog::new(&register).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Trying);
        assert_eq!(dialog.method, SipMethod::Register);

        let ok = make_response(200, "OK", "REGISTER");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::Registered);
    }

    /// A 200 OK to INVITE that races a CANCEL — the UAS answered before the
    /// CANCEL arrived — establishes the call per RFC 3261 (the CANCEL has no
    /// effect once a final 2xx exists), overriding the Cancelled state.
    #[test]
    fn invite_200_after_cancel_becomes_incall() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        update_state(&mut dialog, &make_response(180, "Ringing", "INVITE"));
        update_state(&mut dialog, &make_request("CANCEL"));
        assert_eq!(dialog.state, DialogState::Cancelled);

        // The 200 races the CANCEL and wins — the call was established.
        update_state(&mut dialog, &make_response(200, "OK", "INVITE"));
        assert_eq!(dialog.state, DialogState::InCall);
    }

    /// A 401/407 auth challenge to REGISTER is intermediate — the client
    /// re-registers with credentials — so it must not mark the dialog Failed.
    #[test]
    fn register_auth_challenge_is_not_failure() {
        let raw = build_sip(
            "REGISTER sip:registrar.example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=r1",
                "To: <sip:alice@example.com>",
                "Call-ID: register-chal@example.com",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let register = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse REGISTER");

        for code in [401u16, 407] {
            let mut dialog = SipDialog::new(&register).expect("should create dialog");
            update_state(
                &mut dialog,
                &make_response(code, "Auth Required", "REGISTER"),
            );
            assert_ne!(
                dialog.state,
                DialogState::Failed,
                "{code} auth challenge must not mark REGISTER Failed"
            );
        }
    }

    /// A genuine 4xx failure (403 Forbidden) moves a REGISTER dialog to
    /// Failed. (401/407 auth challenges are intermediate — see
    /// `register_auth_challenge_is_not_failure`.)
    #[test]
    fn register_failure() {
        let raw = build_sip(
            "REGISTER sip:registrar.example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=r1",
                "To: <sip:alice@example.com>",
                "Call-ID: register-fail@example.com",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let register = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse REGISTER");

        let mut dialog = SipDialog::new(&register).expect("should create dialog");

        let error = make_response(403, "Forbidden", "REGISTER");
        update_state(&mut dialog, &error);
        assert_eq!(dialog.state, DialogState::Failed);
    }

    /// A SUBSCRIBE dialog starts in Pending and moves to Active on 200 OK.
    #[test]
    fn subscribe_lifecycle() {
        let raw = build_sip(
            "SUBSCRIBE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=s1",
                "To: <sip:bob@example.com>",
                "Call-ID: subscribe-test@example.com",
                "CSeq: 1 SUBSCRIBE",
                "Event: presence",
                "Content-Length: 0",
            ],
            b"",
        );
        let subscribe = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse SUBSCRIBE");

        let mut dialog = SipDialog::new(&subscribe).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Pending);
        assert_eq!(dialog.method, SipMethod::Subscribe);

        let ok = make_response(200, "OK", "SUBSCRIBE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::Active);
    }

    /// An in-dialog NOTIFY activates a Pending SUBSCRIBE dialog even
    /// before any 200 OK arrives.
    #[test]
    fn subscribe_notify_activates() {
        let raw = build_sip(
            "SUBSCRIBE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=s1",
                "To: <sip:bob@example.com>",
                "Call-ID: sub-notify@example.com",
                "CSeq: 1 SUBSCRIBE",
                "Content-Length: 0",
            ],
            b"",
        );
        let subscribe = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse SUBSCRIBE");

        let mut dialog = SipDialog::new(&subscribe).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Pending);

        let notify = make_request("NOTIFY");
        update_state(&mut dialog, &notify);
        assert_eq!(dialog.state, DialogState::Active);
    }

    /// An ACK after the 200 OK leaves the dialog in InCall (no transition).
    #[test]
    fn ack_does_not_change_state() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::InCall);

        let ack = make_request("ACK");
        update_state(&mut dialog, &ack);
        assert_eq!(dialog.state, DialogState::InCall); // Unchanged
    }

    /// The remote To tag, absent on the initial INVITE, is captured from
    /// the first response that carries one (180 Ringing here).
    #[test]
    fn to_tag_captured_from_response() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");
        // Initial INVITE has no to_tag
        assert!(dialog.to_tag.is_none());

        let ringing = make_response(180, "Ringing", "INVITE");
        update_state(&mut dialog, &ringing);
        assert_eq!(dialog.to_tag.as_deref(), Some("t2"));
    }

    /// SipDialog::new returns None for a message without a Call-ID header.
    #[test]
    fn missing_call_id_returns_none() {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(SipDialog::new(&msg).is_none());
    }

    /// 183 Session Progress triggers the Ringing state just like 180.
    #[test]
    fn session_progress_triggers_ringing() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        // 183 Session Progress should also trigger Ringing state
        let progress = make_response(183, "Session Progress", "INVITE");
        update_state(&mut dialog, &progress);
        assert_eq!(dialog.state, DialogState::Ringing);
    }

    // ── Transfer detection tests ────────────────────────────────────────

    /// Build and parse an in-dialog REFER (CSeq 3) with a Refer-To header
    /// targeting carol.
    fn make_refer() -> SipMessage {
        let raw = build_sip(
            "REFER sip:bob@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.com>;tag=t2",
                "Call-ID: dialog-test@example.com",
                "CSeq: 3 REFER",
                "Refer-To: <sip:carol@example.com>",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse REFER")
    }

    /// Build and parse a NOTIFY with `Subscription-State: terminated`
    /// (signals the end of a REFER-initiated transfer subscription).
    fn make_notify_terminated() -> SipMessage {
        let raw = build_sip(
            "NOTIFY sip:alice@example.com SIP/2.0",
            &[
                "From: \"Bob\" <sip:bob@example.com>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
                "Call-ID: dialog-test@example.com",
                "CSeq: 4 NOTIFY",
                "Subscription-State: terminated;reason=noresource",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse NOTIFY")
    }

    /// Build and parse a NOTIFY with `Subscription-State: active` (transfer
    /// still in progress).
    fn make_notify_active() -> SipMessage {
        let raw = build_sip(
            "NOTIFY sip:alice@example.com SIP/2.0",
            &[
                "From: \"Bob\" <sip:bob@example.com>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
                "Call-ID: dialog-test@example.com",
                "CSeq: 4 NOTIFY",
                "Subscription-State: active",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse NOTIFY")
    }

    /// A REFER received while InCall moves the dialog to Transferring.
    #[test]
    fn refer_during_incall_transitions_to_transferring() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::InCall);

        let refer = make_refer();
        update_state(&mut dialog, &refer);
        assert_eq!(dialog.state, DialogState::Transferring);
    }

    /// A NOTIFY with `Subscription-State: terminated` while Transferring
    /// returns the dialog to InCall.
    #[test]
    fn notify_terminated_returns_to_incall() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        let refer = make_refer();
        update_state(&mut dialog, &refer);
        assert_eq!(dialog.state, DialogState::Transferring);

        let notify = make_notify_terminated();
        update_state(&mut dialog, &notify);
        assert_eq!(dialog.state, DialogState::InCall);
    }

    /// A REFER received while still Trying does not start a transfer —
    /// only InCall dialogs can transition to Transferring.
    #[test]
    fn refer_outside_incall_no_transition() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Trying);

        let refer = make_refer();
        update_state(&mut dialog, &refer);
        // Should remain Trying — REFER only triggers transfer from InCall
        assert_eq!(dialog.state, DialogState::Trying);
    }

    /// A NOTIFY with `Subscription-State: active` keeps a Transferring
    /// dialog in Transferring (only "terminated" ends the transfer).
    #[test]
    fn notify_active_does_not_change_transferring() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        let refer = make_refer();
        update_state(&mut dialog, &refer);
        assert_eq!(dialog.state, DialogState::Transferring);

        // NOTIFY with Subscription-State: active should NOT transition back
        let notify = make_notify_active();
        update_state(&mut dialog, &notify);
        assert_eq!(dialog.state, DialogState::Transferring);
    }

    /// Build a NOTIFY carrying an arbitrary `Subscription-State` value.
    fn make_notify_sub_state(value: &str) -> SipMessage {
        let sub_state = format!("Subscription-State: {value}");
        let raw = build_sip(
            "NOTIFY sip:alice@example.com SIP/2.0",
            &[
                "From: \"Bob\" <sip:bob@example.com>;tag=t2",
                "To: \"Alice\" <sip:alice@example.com>;tag=t1",
                "Call-ID: dialog-test@example.com",
                "CSeq: 4 NOTIFY",
                sub_state.as_str(),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse NOTIFY")
    }

    /// A NOTIFY whose `Subscription-State` merely *starts with* "terminated"
    /// (e.g. `terminatedfoo`) must NOT end the transfer — only the exact
    /// `terminated` value token does (RFC 6665 §8.4).
    #[test]
    fn notify_terminatedfoo_does_not_return_to_incall() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let ok = make_response(200, "OK", "INVITE");
        update_state(&mut dialog, &ok);
        let refer = make_refer();
        update_state(&mut dialog, &refer);
        assert_eq!(dialog.state, DialogState::Transferring);

        let notify = make_notify_sub_state("terminatedfoo");
        update_state(&mut dialog, &notify);
        assert_eq!(
            dialog.state,
            DialogState::Transferring,
            "a Subscription-State prefixed with 'terminated' must not end the transfer"
        );
    }

    /// A response with no CSeq creates no dialog, and — the point of the change
    /// — the real INVITE that follows still creates one with the RIGHT method.
    ///
    /// `method` is set once in `new()` and never corrected afterwards, so
    /// fabricating `UNKNOWN` here did not merely mislabel one malformed
    /// message: the dialog it created was keyed by Call-ID, so the genuine
    /// INVITE arriving later matched that entry instead of creating its own,
    /// and the wrong method survived for the rest of the capture. The second
    /// half of this test is what distinguishes a fix from a rename.
    #[test]
    fn a_response_without_cseq_does_not_poison_the_dialog_its_invite_creates() {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: \"Alice\" <sip:alice@example.com>;tag=t1",
                "To: \"Bob\" <sip:bob@example.com>;tag=t2",
                "Call-ID: dialog-test@example.com",
                "Content-Length: 0",
            ],
            b"",
        );
        let orphan = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse response");
        assert!(orphan.cseq().is_none(), "fixture must have no CSeq");

        assert!(
            SipDialog::new(&orphan).is_none(),
            "a response whose method cannot be determined must not create a \
             dialog — it would be keyed by Call-ID and permanently labelled"
        );

        // The genuine INVITE, same Call-ID, is unaffected and correct.
        let invite = make_request("INVITE");
        let dialog = SipDialog::new(&invite).expect("INVITE creates a dialog");
        assert_eq!(
            dialog.method,
            SipMethod::Invite,
            "the INVITE's own method must be recorded, not inherited from an \
             earlier malformed message"
        );
    }
}
