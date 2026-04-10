//! SIP dialog type and state machine.
//!
//! A [`SipDialog`] tracks the lifecycle of a SIP conversation identified by
//! its Call-ID. The [`DialogState`] enum models the state machine transitions
//! for INVITE, REGISTER, and SUBSCRIBE dialogs, driven by incoming SIP
//! messages.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::SipMessage;
use super::sdp_timeline::SdpExchange;
use super::timing::DialogTiming;

/// Dialog lifecycle state, covering INVITE, REGISTER, and SUBSCRIBE flows.
#[derive(Debug, Clone, PartialEq)]
pub enum DialogState {
    /// INVITE sent, no provisional response yet.
    Trying,
    /// 180 Ringing or 183 Session Progress received.
    Ringing,
    /// 200 OK to INVITE received; media session active.
    InCall,
    /// BYE completed; dialog terminated normally.
    Completed,
    /// CANCEL sent and confirmed (487 received).
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
}

/// A tracked SIP dialog (call, registration, or subscription).
///
/// Created when the first message for a given Call-ID is processed.
/// Updated by subsequent messages via [`update_state`].
pub struct SipDialog {
    /// Call-ID that uniquely identifies this dialog.
    pub call_id: String,
    /// User part extracted from the From URI.
    pub from_user: Option<String>,
    /// User part extracted from the To URI.
    pub to_user: Option<String>,
    /// Tag parameter from the From header.
    pub from_tag: Option<String>,
    /// Tag parameter from the To header.
    pub to_tag: Option<String>,
    /// Display name from the From header.
    pub from_display: Option<String>,
    /// Display name from the To header.
    pub to_display: Option<String>,
    /// Current dialog state.
    pub state: DialogState,
    /// Initial SIP method that created this dialog (e.g., `"INVITE"`, `"REGISTER"`).
    pub method: String,
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
    /// Transaction timing measurements.
    pub timing: DialogTiming,
    /// SDP offer/answer timeline.
    pub sdp_timeline: Vec<SdpExchange>,
}

impl SipDialog {
    /// Create a new dialog from the first message in a conversation.
    ///
    /// Initializes the dialog state based on the message's method:
    /// - INVITE → `Trying`
    /// - REGISTER → `Trying`
    /// - SUBSCRIBE → `Pending`
    /// - All others → `Trying`
    pub fn new(msg: &SipMessage) -> Option<Self> {
        let call_id = msg.call_id()?.to_string();
        let method = if msg.is_request {
            msg.method.as_deref().unwrap_or("UNKNOWN").to_string()
        } else {
            // For responses, derive the method from CSeq
            msg.cseq()
                .map(|(_, m)| m)
                .unwrap_or_else(|| "UNKNOWN".to_string())
        };

        let initial_state = match method.as_str() {
            "SUBSCRIBE" => DialogState::Pending,
            _ => DialogState::Trying,
        };

        Some(SipDialog {
            call_id,
            from_user: msg.from_user(),
            to_user: msg.to_user(),
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
            tags: Vec::new(),
            timing: DialogTiming::default(),
            sdp_timeline: Vec::new(),
        })
    }
}

/// Transition the dialog state based on a new SIP message.
///
/// Applies the state machine rules for the dialog's initial method:
/// - **INVITE**: 100→Trying, 180/183→Ringing, 200→InCall,
///   4xx/5xx/6xx→Failed, CANCEL→Cancelled, BYE→Completed
/// - **REGISTER**: 200→Registered, 4xx/5xx→Failed
/// - **SUBSCRIBE**: 200→Active, NOTIFY→Active, terminal→Terminated
///
/// ACK messages are recorded but do not cause state transitions.
pub fn update_state(dialog: &mut SipDialog, msg: &SipMessage) {
    match dialog.method.as_str() {
        "INVITE" => update_invite_state(dialog, msg),
        "REGISTER" => update_register_state(dialog, msg),
        "SUBSCRIBE" => update_subscribe_state(dialog, msg),
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

/// State transitions for INVITE dialogs.
fn update_invite_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if msg.is_request {
        let method = msg.method.as_deref().unwrap_or("");
        match method {
            "CANCEL" => {
                dialog.state = DialogState::Cancelled;
            }
            "BYE" => {
                dialog.state = DialogState::Completed;
            }
            "ACK" => {
                // ACK doesn't change state
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
                if cseq_method == "INVITE"
                    && (dialog.state == DialogState::Trying || dialog.state == DialogState::Ringing)
                {
                    dialog.state = DialogState::InCall;
                }
                // 200 OK to BYE doesn't further change state (already Completed)
            }
            487 => {
                // 487 Request Terminated (response to CANCEL)
                if dialog.state == DialogState::Cancelled {
                    // Stay cancelled; this confirms the cancellation
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

/// State transitions for REGISTER dialogs.
fn update_register_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if !msg.is_request
        && let Some(code) = msg.status_code
    {
        match code {
            200..=299 => {
                dialog.state = DialogState::Registered;
            }
            400..=699 => {
                dialog.state = DialogState::Failed;
            }
            _ => {}
        }
    }
}

/// State transitions for SUBSCRIBE dialogs.
fn update_subscribe_state(dialog: &mut SipDialog, msg: &SipMessage) {
    if msg.is_request {
        let method = msg.method.as_deref().unwrap_or("");
        if method == "NOTIFY" {
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

/// Generic state transitions for methods without specific state machines.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse INVITE")
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse response")
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse request")
    }

    #[test]
    fn invite_full_lifecycle() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        assert_eq!(dialog.state, DialogState::Trying);
        assert_eq!(dialog.method, "INVITE");
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

    #[test]
    fn invite_failed() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        let error = make_response(503, "Service Unavailable", "INVITE");
        update_state(&mut dialog, &error);
        assert_eq!(dialog.state, DialogState::Failed);
    }

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
        let register = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse REGISTER");

        let mut dialog = SipDialog::new(&register).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Trying);
        assert_eq!(dialog.method, "REGISTER");

        let ok = make_response(200, "OK", "REGISTER");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::Registered);
    }

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
        let register = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse REGISTER");

        let mut dialog = SipDialog::new(&register).expect("should create dialog");

        let error = make_response(401, "Unauthorized", "REGISTER");
        update_state(&mut dialog, &error);
        assert_eq!(dialog.state, DialogState::Failed);
    }

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
        let subscribe = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse SUBSCRIBE");

        let mut dialog = SipDialog::new(&subscribe).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Pending);
        assert_eq!(dialog.method, "SUBSCRIBE");

        let ok = make_response(200, "OK", "SUBSCRIBE");
        update_state(&mut dialog, &ok);
        assert_eq!(dialog.state, DialogState::Active);
    }

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
        let subscribe = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse SUBSCRIBE");

        let mut dialog = SipDialog::new(&subscribe).expect("should create dialog");
        assert_eq!(dialog.state, DialogState::Pending);

        let notify = make_request("NOTIFY");
        update_state(&mut dialog, &notify);
        assert_eq!(dialog.state, DialogState::Active);
    }

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        assert!(SipDialog::new(&msg).is_none());
    }

    #[test]
    fn session_progress_triggers_ringing() {
        let invite = make_invite();
        let mut dialog = SipDialog::new(&invite).expect("should create dialog");

        // 183 Session Progress should also trigger Ringing state
        let progress = make_response(183, "Session Progress", "INVITE");
        update_state(&mut dialog, &progress);
        assert_eq!(dialog.state, DialogState::Ringing);
    }
}
