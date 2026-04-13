//! Dialog store for tracking concurrent SIP conversations.
//!
//! [`DialogStore`] is the central data structure that receives parsed SIP
//! messages and routes them to the appropriate [`SipDialog`]. It handles
//! dialog creation, state machine updates, timing, SDP tracking,
//! retransmission detection, and capacity-based eviction.

use std::collections::HashMap;

use super::SipMessage;
use super::dialog::{DialogState, SipDialog, update_state};
use super::sdp_timeline::track_sdp;
use super::timing::update_timing;

/// In-memory store of active and completed SIP dialogs.
///
/// Dialogs are indexed by Call-ID for O(1) lookup. When the store reaches
/// its capacity limit and `rotate` is enabled, the oldest dialog is evicted
/// to make room for new ones.
pub struct DialogStore {
    /// All tracked dialogs, in insertion order.
    dialogs: Vec<SipDialog>,
    /// Call-ID to index mapping for fast lookup.
    index: HashMap<String, usize>,
    /// Maximum number of dialogs to retain.
    max_dialogs: usize,
    /// Whether to evict the oldest dialog when at capacity.
    rotate: bool,
}

impl DialogStore {
    /// Create a new dialog store with the given capacity limit.
    ///
    /// # Arguments
    ///
    /// * `max_dialogs` — Maximum number of dialogs to track simultaneously.
    /// * `rotate` — If `true`, evict the oldest dialog when at capacity.
    ///   If `false`, new messages for unknown Call-IDs are silently dropped
    ///   when at capacity.
    pub fn new(max_dialogs: usize, rotate: bool) -> Self {
        Self {
            dialogs: Vec::with_capacity(max_dialogs.min(1024)),
            index: HashMap::with_capacity(max_dialogs.min(1024)),
            max_dialogs,
            rotate,
        }
    }

    /// Process an incoming SIP message.
    ///
    /// This is the main entry point. It:
    /// 1. Extracts the Call-ID from the message
    /// 2. Looks up an existing dialog or creates a new one
    /// 3. Detects retransmissions (same CSeq + method already seen)
    /// 4. Updates the dialog state machine
    /// 5. Updates transaction timing
    /// 6. Tracks SDP if present
    /// 7. Evicts the oldest dialog if at capacity and `rotate` is enabled
    ///
    /// Messages without a Call-ID header are silently dropped.
    pub fn process_message(&mut self, msg: SipMessage) {
        let call_id = match msg.call_id() {
            Some(id) => id.to_string(),
            None => return,
        };

        if let Some(&idx) = self.index.get(&call_id) {
            // Existing dialog
            let dialog = &mut self.dialogs[idx];

            // Retransmission detection: same CSeq number + method already seen
            if is_retransmission(dialog, &msg) {
                let cseq_key = cseq_key(&msg);
                if let Some(key) = cseq_key {
                    *dialog.timing.retransmit_counts.entry(key).or_insert(0) += 1;
                }
                dialog.updated_at = msg.timestamp;
                return;
            }

            // Update state machine
            update_state(dialog, &msg);

            // Update timing
            update_timing(&mut dialog.timing, &msg, &dialog.method);

            // Track SDP
            track_sdp(&mut dialog.sdp_timeline, &msg);

            // Record the message
            dialog.messages.push(msg.clone());
            dialog.updated_at = msg.timestamp;
        } else {
            // New dialog — check capacity
            if self.dialogs.len() >= self.max_dialogs {
                if self.rotate {
                    self.evict_oldest();
                } else {
                    return;
                }
            }

            // Create the new dialog
            if let Some(mut dialog) = SipDialog::new(&msg) {
                // Update timing for the initial message
                update_timing(&mut dialog.timing, &msg, &dialog.method);

                // Track SDP for the initial message
                track_sdp(&mut dialog.sdp_timeline, &msg);

                let idx = self.dialogs.len();
                self.index.insert(call_id, idx);
                self.dialogs.push(dialog);
            }
        }
    }

    /// Look up a dialog by Call-ID.
    pub fn get(&self, call_id: &str) -> Option<&SipDialog> {
        self.index.get(call_id).map(|&idx| &self.dialogs[idx])
    }

    /// Look up a dialog by Call-ID, returning a mutable reference.
    pub fn get_mut(&mut self, call_id: &str) -> Option<&mut SipDialog> {
        self.index.get(call_id).map(|&idx| &mut self.dialogs[idx])
    }

    /// Iterate over all tracked dialogs.
    pub fn iter(&self) -> impl Iterator<Item = &SipDialog> {
        self.dialogs.iter()
    }

    /// Return the total number of tracked dialogs.
    pub fn len(&self) -> usize {
        self.dialogs.len()
    }

    /// Return `true` if the store contains no dialogs.
    pub fn is_empty(&self) -> bool {
        self.dialogs.is_empty()
    }

    /// Remove all dialogs from the store.
    pub fn clear(&mut self) {
        self.dialogs.clear();
        self.index.clear();
    }

    /// Retain only dialogs for which `predicate` returns `true`.
    ///
    /// Dialogs that do not satisfy the predicate are removed and the
    /// internal index is rebuilt.
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&SipDialog) -> bool,
    {
        self.dialogs.retain(|d| predicate(d));
        self.index.clear();
        for (idx, dialog) in self.dialogs.iter().enumerate() {
            self.index.insert(dialog.call_id.clone(), idx);
        }
    }

    /// Count dialogs in an active state (Trying, Ringing, InCall, Pending, Active).
    pub fn active_count(&self) -> usize {
        self.dialogs
            .iter()
            .filter(|d| {
                matches!(
                    d.state,
                    DialogState::Trying
                        | DialogState::Ringing
                        | DialogState::InCall
                        | DialogState::Pending
                        | DialogState::Active
                )
            })
            .count()
    }

    /// Find dialogs correlated to the given Call-ID via X-Call-ID headers.
    ///
    /// A B-leg dialog is correlated if its Call-ID matches an X-Call-ID header
    /// value in the given dialog, or if any of its messages carry an X-Call-ID
    /// header whose value matches the given Call-ID.
    pub fn find_correlated(&self, call_id: &str) -> Vec<&SipDialog> {
        let dialog = match self.get(call_id) {
            Some(d) => d,
            None => return Vec::new(),
        };

        // Collect X-Call-ID values from the given dialog
        let x_call_ids: Vec<&str> = dialog
            .messages
            .iter()
            .filter_map(|m| m.header("X-Call-ID"))
            .collect();

        self.dialogs
            .iter()
            .filter(|d| {
                if d.call_id == call_id {
                    return false;
                }

                // Check if this dialog's Call-ID matches an X-Call-ID from the source dialog
                if x_call_ids.iter().any(|&xid| xid == d.call_id) {
                    return true;
                }

                // Check if this dialog has an X-Call-ID pointing back to the source
                d.messages
                    .iter()
                    .any(|m| m.header("X-Call-ID").is_some_and(|v| v == call_id))
            })
            .collect()
    }

    /// Evict the oldest dialog (first in the vector) to make room.
    ///
    /// Uses swap_remove for O(1) deletion instead of O(n) shift + full
    /// index rebuild.
    fn evict_oldest(&mut self) {
        if self.dialogs.is_empty() {
            return;
        }

        self.index.remove(&self.dialogs[0].call_id);
        self.dialogs.swap_remove(0);

        // If we swapped an element into index 0, update its index entry
        if !self.dialogs.is_empty() {
            self.index.insert(self.dialogs[0].call_id.clone(), 0);
        }
    }
}

/// Detect whether `msg` is a retransmission of an already-seen message
/// in the dialog.
///
/// A message is considered a retransmission if another message with the
/// same CSeq number, CSeq method, and request/response type already
/// exists in the dialog's message list. For responses, the status code
/// must also match.
fn is_retransmission(dialog: &SipDialog, msg: &SipMessage) -> bool {
    let (new_seq, new_method) = match msg.cseq() {
        Some(cseq) => cseq,
        None => return false,
    };

    dialog.messages.iter().any(|existing| {
        if existing.is_request != msg.is_request {
            return false;
        }
        // For responses, also match by status code
        if !msg.is_request && existing.status_code != msg.status_code {
            return false;
        }
        if let Some((seq, method)) = existing.cseq() {
            seq == new_seq && method == new_method
        } else {
            false
        }
    })
}

/// Build a CSeq key string (`"<num> <method>"`) from a SIP message for
/// retransmission counting.
fn cseq_key(msg: &SipMessage) -> Option<String> {
    let (num, method) = msg.cseq()?;
    Some(format!("{num} {method}"))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_invite_msg(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse INVITE")
    }

    fn make_200_ok(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse 200 OK")
    }

    fn make_bye_msg(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, TransportProto::Udp).expect("should parse BYE")
    }

    #[test]
    fn invite_and_200_creates_incall_dialog() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);

        store.process_message(make_invite_msg("call-1@test", t0));
        store.process_message(make_200_ok("call-1@test", t1));

        assert_eq!(store.len(), 1);
        let dialog = store.get("call-1@test").expect("dialog should exist");
        assert_eq!(dialog.state, DialogState::InCall);
        assert_eq!(dialog.messages.len(), 2);
    }

    #[test]
    fn max_dialogs_with_rotate_evicts_oldest() {
        let mut store = DialogStore::new(2, true);
        let t0 = base_ts();

        store.process_message(make_invite_msg("call-1@test", t0));
        store.process_message(make_invite_msg("call-2@test", t0 + TimeDelta::seconds(1)));

        assert_eq!(store.len(), 2);

        // Third dialog should evict "call-1@test"
        store.process_message(make_invite_msg("call-3@test", t0 + TimeDelta::seconds(2)));

        assert_eq!(store.len(), 2);
        assert!(store.get("call-1@test").is_none());
        assert!(store.get("call-2@test").is_some());
        assert!(store.get("call-3@test").is_some());
    }

    #[test]
    fn max_dialogs_without_rotate_drops_new() {
        let mut store = DialogStore::new(2, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("call-1@test", t0));
        store.process_message(make_invite_msg("call-2@test", t0 + TimeDelta::seconds(1)));

        // Third dialog should be dropped silently
        store.process_message(make_invite_msg("call-3@test", t0 + TimeDelta::seconds(2)));

        assert_eq!(store.len(), 2);
        assert!(store.get("call-3@test").is_none());
    }

    #[test]
    fn retransmission_dedup() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(500);
        let t2 = t0 + TimeDelta::milliseconds(1000);

        // Send INVITE three times (same CSeq)
        store.process_message(make_invite_msg("retrans@test", t0));
        store.process_message(make_invite_msg("retrans@test", t1));
        store.process_message(make_invite_msg("retrans@test", t2));

        let dialog = store.get("retrans@test").expect("dialog should exist");
        // Only the first INVITE should be in the messages list
        assert_eq!(dialog.messages.len(), 1);
        // Retransmit count should be 2 (second and third are retransmissions)
        assert_eq!(dialog.timing.total_retransmits(), 2);
    }

    #[test]
    fn multiple_dialogs_independent() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("call-a@test", t0));
        store.process_message(make_invite_msg("call-b@test", t0));
        store.process_message(make_invite_msg("call-c@test", t0));

        assert_eq!(store.len(), 3);
        assert!(store.get("call-a@test").is_some());
        assert!(store.get("call-b@test").is_some());
        assert!(store.get("call-c@test").is_some());
    }

    #[test]
    fn full_call_lifecycle() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("lifecycle@test", t0));
        store.process_message(make_200_ok("lifecycle@test", t0 + TimeDelta::seconds(2)));
        store.process_message(make_bye_msg("lifecycle@test", t0 + TimeDelta::seconds(60)));

        let dialog = store.get("lifecycle@test").expect("dialog should exist");
        assert_eq!(dialog.state, DialogState::Completed);
        assert_eq!(dialog.messages.len(), 3);
    }

    #[test]
    fn active_count_tracks_live_dialogs() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Two active calls
        store.process_message(make_invite_msg("active-1@test", t0));
        store.process_message(make_invite_msg("active-2@test", t0));

        assert_eq!(store.active_count(), 2);

        // Complete one
        store.process_message(make_200_ok("active-1@test", t0 + TimeDelta::seconds(1)));
        store.process_message(make_bye_msg("active-1@test", t0 + TimeDelta::seconds(10)));

        assert_eq!(store.active_count(), 1);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn message_without_call_id_is_dropped() {
        let mut store = DialogStore::new(100, false);

        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(&raw, base_ts(), localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse");

        store.process_message(msg);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn is_empty_on_new_store() {
        let store = DialogStore::new(100, false);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn iter_returns_all_dialogs() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("iter-1@test", t0));
        store.process_message(make_invite_msg("iter-2@test", t0));

        let call_ids: Vec<&str> = store.iter().map(|d| d.call_id.as_str()).collect();
        assert_eq!(call_ids.len(), 2);
        assert!(call_ids.contains(&"iter-1@test"));
        assert!(call_ids.contains(&"iter-2@test"));
    }

    #[test]
    fn timing_populated_through_store() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1500);

        store.process_message(make_invite_msg("timed@test", t0));
        store.process_message(make_200_ok("timed@test", t1));

        let dialog = store.get("timed@test").expect("dialog should exist");
        assert_eq!(dialog.timing.setup_ms(), Some(1500));
    }

    #[test]
    fn different_response_codes_not_retransmission() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(100);
        let t2 = t0 + TimeDelta::milliseconds(500);

        store.process_message(make_invite_msg("multi-resp@test", t0));

        // 100 Trying
        let trying = {
            let raw = build_sip(
                "SIP/2.0 100 Trying",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>",
                    "Call-ID: multi-resp@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(&raw, t1, localhost(), localhost(), 5060, 5060, TransportProto::Udp).expect("should parse")
        };
        store.process_message(trying);

        // 180 Ringing (different status code, same CSeq — NOT a retransmission)
        let ringing = {
            let raw = build_sip(
                "SIP/2.0 180 Ringing",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: multi-resp@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(&raw, t2, localhost(), localhost(), 5060, 5060, TransportProto::Udp).expect("should parse")
        };
        store.process_message(ringing);

        let dialog = store.get("multi-resp@test").expect("dialog should exist");
        assert_eq!(dialog.messages.len(), 3); // INVITE + 100 + 180
        assert_eq!(dialog.timing.total_retransmits(), 0);
    }

    /// Build an INVITE message with an X-Call-ID header (for multi-leg correlation).
    fn make_invite_with_x_call_id(call_id: &str, x_call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("X-Call-ID: {x_call_id}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse INVITE with X-Call-ID")
    }

    #[test]
    fn find_correlated_via_x_call_id() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // A-leg: normal INVITE
        store.process_message(make_invite_msg("a-leg@test", t0));

        // B-leg: INVITE with X-Call-ID pointing to A-leg
        store.process_message(make_invite_with_x_call_id(
            "b-leg@test",
            "a-leg@test",
            t0 + TimeDelta::seconds(1),
        ));

        // A-leg should find B-leg as correlated
        let correlated = store.find_correlated("a-leg@test");
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].call_id, "b-leg@test");

        // B-leg should also find A-leg as correlated
        let correlated = store.find_correlated("b-leg@test");
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].call_id, "a-leg@test");
    }

    #[test]
    fn find_correlated_returns_empty_for_unlinked() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("standalone@test", t0));
        store.process_message(make_invite_msg("another@test", t0));

        assert!(store.find_correlated("standalone@test").is_empty());
        assert!(store.find_correlated("another@test").is_empty());
    }

    #[test]
    fn find_correlated_unknown_call_id_returns_empty() {
        let store = DialogStore::new(100, false);
        assert!(store.find_correlated("nonexistent@test").is_empty());
    }

    #[test]
    fn find_correlated_bidirectional_x_call_id() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Both legs have X-Call-ID pointing to each other
        store.process_message(make_invite_with_x_call_id("leg-1@test", "leg-2@test", t0));
        store.process_message(make_invite_with_x_call_id(
            "leg-2@test",
            "leg-1@test",
            t0 + TimeDelta::seconds(1),
        ));

        let correlated = store.find_correlated("leg-1@test");
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].call_id, "leg-2@test");
    }
}
