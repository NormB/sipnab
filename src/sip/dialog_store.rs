//! Dialog store for tracking concurrent SIP conversations.
//!
//! [`DialogStore`] is the central data structure that receives parsed SIP
//! messages and routes them to the appropriate [`SipDialog`]. It handles
//! dialog creation, state machine updates, timing, SDP tracking,
//! retransmission detection, and capacity-based eviction.

use indexmap::IndexMap;

use super::SipMessage;
use super::dialog::{DialogState, SipDialog, update_state};
use super::method::SipMethod;
use super::sdp_timeline::{track_sdp, track_transfer};
use super::timing::update_timing;

/// Default maximum messages stored per dialog (D17 defense-in-depth).
pub const DEFAULT_MAX_MESSAGES_PER_DIALOG: usize = 500;

/// Runtime-configurable limit (set once at startup from config).
static MAX_MESSAGES_PER_DIALOG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_MESSAGES_PER_DIALOG);

/// Set the per-dialog message limit from configuration. Call once at startup.
pub fn set_max_messages_per_dialog(limit: usize) {
    MAX_MESSAGES_PER_DIALOG.store(limit, std::sync::atomic::Ordering::Relaxed);
}

/// Reason a dialog was correlated to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationReason {
    /// Matched via X-Call-ID header.
    XCallId,
    /// Matched via shared Via branch parameter.
    ViaBranch,
    /// Matched via endpoint overlap + timing heuristic.
    TimingHeuristic,
}

/// A correlated dialog with a confidence score.
#[derive(Debug, Clone)]
pub struct CorrelationResult<'a> {
    /// The correlated dialog.
    pub dialog: &'a SipDialog,
    /// Confidence score (0-100).
    pub score: u8,
    /// Why this dialog was considered correlated.
    pub reason: CorrelationReason,
}

/// In-memory store of active and completed SIP dialogs.
///
/// # Lock Ordering
///
/// When both `DialogStore` and `StreamStore` are held under `RwLock`,
/// always acquire `DialogStore` first, then `StreamStore`. This prevents
/// deadlocks between the capture/processing thread and the API/TUI threads.
///
/// Dialogs are indexed by Call-ID for O(1) lookup. When the store reaches
/// its capacity limit and `rotate` is enabled, the oldest dialog is evicted
/// to make room for new ones.
pub struct DialogStore {
    /// All tracked dialogs, keyed by Call-ID in insertion order.
    dialogs: IndexMap<String, SipDialog>,
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
            dialogs: IndexMap::with_capacity(max_dialogs.min(1024)),
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
    pub fn process_message(&mut self, mut msg: SipMessage) {
        // Look up by the borrowed Call-ID (str is Equivalent<String> for
        // IndexMap); the owned key is allocated only when a new dialog is
        // actually inserted — not once per message on the hot path.
        let dialog_idx = match msg.call_id() {
            Some(id) => self.dialogs.get_index_of(id),
            None => return,
        };

        if let Some(idx) = dialog_idx {
            let Some((_, dialog)) = self.dialogs.get_index_mut(idx) else {
                return; // unreachable: idx came from get_index_of
            };
            // Retransmission detection: same CSeq number + method already seen
            if is_retransmission(dialog, &msg) {
                let cseq_key = cseq_key(&msg);
                if let Some(key) = cseq_key {
                    *dialog.timing.retransmit_counts.entry(key).or_insert(0) += 1;
                }
                // Mark as retransmission but store it for ladder display (capped)
                msg.is_retransmission = true;
                if dialog.messages.len()
                    < MAX_MESSAGES_PER_DIALOG.load(std::sync::atomic::Ordering::Relaxed)
                {
                    dialog.messages.push(msg);
                }
                dialog.updated_at = dialog
                    .messages
                    .last()
                    .map(|m| m.timestamp)
                    .unwrap_or(dialog.updated_at);
                return;
            }

            // Update state machine
            update_state(dialog, &msg);

            // Update timing
            update_timing(&mut dialog.timing, &msg, &dialog.method);

            // Track SDP
            track_sdp(&mut dialog.sdp_timeline, &msg);

            // Track REFER-based transfers
            if msg.is_request && msg.method.as_ref() == Some(&SipMethod::Refer) {
                if let Some(refer_to) = msg.header("Refer-To") {
                    dialog.refer_to = Some(refer_to.to_string());
                }
                track_transfer(&mut dialog.sdp_timeline, &msg);
            }

            // Parse SIPREC metadata from multipart/mixed bodies
            if let Some(ct) = msg.content_type()
                && ct.contains("multipart/mixed")
                && let Ok(metadata) = crate::sip::siprec::parse_siprec_body(ct, &msg.body)
            {
                dialog.siprec_metadata = Some(metadata);
            }

            // Record the message (move instead of clone, capped per D17)
            let ts = msg.timestamp;
            if dialog.messages.len()
                < MAX_MESSAGES_PER_DIALOG.load(std::sync::atomic::Ordering::Relaxed)
            {
                dialog.messages.push(msg);
            }
            dialog.updated_at = ts;
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

                let call_id = match msg.call_id() {
                    Some(id) => id.to_string(),
                    None => return, // unreachable: checked at function entry
                };
                self.dialogs.insert(call_id, dialog);
            }
        }
    }

    /// Look up a dialog by Call-ID.
    pub fn get(&self, call_id: &str) -> Option<&SipDialog> {
        self.dialogs.get(call_id)
    }

    /// Look up a dialog by Call-ID, returning a mutable reference.
    pub fn get_mut(&mut self, call_id: &str) -> Option<&mut SipDialog> {
        self.dialogs.get_mut(call_id)
    }

    /// Iterate over all tracked dialogs.
    pub fn iter(&self) -> impl Iterator<Item = &SipDialog> {
        self.dialogs.values()
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
    }

    /// Retain only dialogs for which `predicate` returns `true`.
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&SipDialog) -> bool,
    {
        self.dialogs.retain(|_, d| predicate(d));
    }

    /// Count dialogs in an active state (Trying, Ringing, InCall, Transferring, Pending, Active).
    pub fn active_count(&self) -> usize {
        self.dialogs
            .values()
            .filter(|d| {
                matches!(
                    d.state(),
                    DialogState::Trying
                        | DialogState::Ringing
                        | DialogState::InCall
                        | DialogState::Transferring
                        | DialogState::Pending
                        | DialogState::Active
                )
            })
            .count()
    }

    /// Find dialogs correlated to the given Call-ID with confidence scores.
    ///
    /// Checks three correlation strategies per candidate dialog (first match wins):
    /// 1. **X-Call-ID** (score=100): B-leg carries X-Call-ID pointing to source, or vice versa.
    /// 2. **Via branch** (score=80): INVITE messages share a Via branch parameter.
    /// 3. **Timing heuristic** (score=50): both INVITE dialogs share an endpoint IP
    ///    and were created within 2 seconds of each other.
    ///
    /// Results are deduplicated (highest score wins) and sorted by score descending.
    pub fn find_correlated_scored(&self, call_id: &str) -> Vec<CorrelationResult<'_>> {
        let dialog = match self.get(call_id) {
            Some(d) => d,
            None => return Vec::new(),
        };

        // Strategy 1 data: X-Call-ID values from the source dialog
        let x_call_ids: Vec<&str> = dialog
            .messages
            .iter()
            .filter_map(|m| m.header("X-Call-ID"))
            .collect();

        // Strategy 2 data: Via branches from INVITE messages in the source dialog
        let src_branches: std::collections::HashSet<&str> = dialog
            .messages
            .iter()
            .filter(|m| m.is_request && m.method.as_ref() == Some(&SipMethod::Invite))
            .flat_map(|m| m.via_headers())
            .filter_map(|v| extract_via_branch(v))
            .collect();

        // Strategy 3 data: endpoint IPs and creation time
        let src_ips = [dialog.src_addr, dialog.dst_addr];
        let is_invite = dialog.method == SipMethod::Invite;

        let mut results: Vec<CorrelationResult<'_>> = Vec::new();

        for candidate in self.dialogs.values() {
            if candidate.call_id == call_id {
                continue;
            }

            // Strategy 1: X-Call-ID match (score=100)
            let xcid_match = x_call_ids.iter().any(|&xid| xid == candidate.call_id)
                || candidate
                    .messages
                    .iter()
                    .any(|m| m.header("X-Call-ID").is_some_and(|v| v == call_id));

            if xcid_match {
                results.push(CorrelationResult {
                    dialog: candidate,
                    score: 100,
                    reason: CorrelationReason::XCallId,
                });
                continue;
            }

            // Strategy 2: Via branch overlap (score=80)
            if !src_branches.is_empty() {
                let candidate_branches: Vec<&str> = candidate
                    .messages
                    .iter()
                    .filter(|m| m.is_request && m.method.as_ref() == Some(&SipMethod::Invite))
                    .flat_map(|m| m.via_headers())
                    .filter_map(|v| extract_via_branch(v))
                    .collect();

                let branch_overlap = candidate_branches.iter().any(|b| src_branches.contains(b));

                if branch_overlap {
                    results.push(CorrelationResult {
                        dialog: candidate,
                        score: 80,
                        reason: CorrelationReason::ViaBranch,
                    });
                    continue;
                }
            }

            // Strategy 3: Timing heuristic (score=50)
            if is_invite && candidate.method == SipMethod::Invite {
                let candidate_ips = [candidate.src_addr, candidate.dst_addr];
                let ip_overlap = src_ips.iter().any(|ip| candidate_ips.contains(ip));
                if ip_overlap {
                    let time_diff = (dialog.created_at - candidate.created_at)
                        .num_milliseconds()
                        .unsigned_abs();
                    if time_diff <= 2000 {
                        results.push(CorrelationResult {
                            dialog: candidate,
                            score: 50,
                            reason: CorrelationReason::TimingHeuristic,
                        });
                    }
                }
            }
        }

        // Sort by score descending
        results.sort_by(|a, b| b.score.cmp(&a.score));
        results
    }

    /// Find dialogs correlated to the given Call-ID via X-Call-ID headers,
    /// Via branch overlap, or timing heuristics.
    ///
    /// Returns dialogs with a correlation score of at least 50.
    pub fn find_correlated(&self, call_id: &str) -> Vec<&SipDialog> {
        self.find_correlated_scored(call_id)
            .into_iter()
            .filter(|r| r.score >= 50)
            .map(|r| r.dialog)
            .collect()
    }

    /// Evict the oldest dialog (first entry in insertion order).
    fn evict_oldest(&mut self) {
        self.dialogs.shift_remove_index(0);
    }
}

/// Extract the `branch=` parameter value from a Via header.
fn extract_via_branch(via_header: &str) -> Option<&str> {
    via_header
        .split(';')
        .find_map(|param| param.trim().strip_prefix("branch="))
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE")
    }

    /// A message for an EXISTING dialog must be processed even when the
    /// store is at capacity — capacity only gates NEW dialogs. Guards the
    /// lookup-before-capacity-check ordering in process_message.
    #[test]
    fn existing_dialog_updated_at_capacity() {
        let mut store = DialogStore::new(2, false);
        store.process_message(make_invite_msg("at-cap-1", base_ts()));
        store.process_message(make_invite_msg("at-cap-2", base_ts()));
        assert_eq!(store.len(), 2);

        // Store is full; an update to dialog 1 must still land.
        store.process_message(make_200_ok("at-cap-1", base_ts()));
        let d = store.get("at-cap-1").expect("dialog must exist");
        assert_eq!(
            d.messages.len(),
            2,
            "200 OK for an existing dialog must be stored even at capacity"
        );
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse BYE")
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
        assert_eq!(*dialog.state(), DialogState::InCall);
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
    fn retransmission_stored_with_flag() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(500);
        let t2 = t0 + TimeDelta::milliseconds(1000);

        // Send INVITE three times (same CSeq)
        store.process_message(make_invite_msg("retrans@test", t0));
        store.process_message(make_invite_msg("retrans@test", t1));
        store.process_message(make_invite_msg("retrans@test", t2));

        let dialog = store.get("retrans@test").expect("dialog should exist");
        // All three INVITEs stored: original + 2 retransmissions
        assert_eq!(dialog.messages.len(), 3);
        // Retransmit count should be 2 (second and third are retransmissions)
        assert_eq!(dialog.timing.total_retransmits(), 2);
        // First message is NOT a retransmission
        assert!(!dialog.messages[0].is_retransmission);
        // Second and third ARE retransmissions
        assert!(dialog.messages[1].is_retransmission);
        assert!(dialog.messages[2].is_retransmission);
    }

    #[test]
    fn retransmissions_do_not_update_state() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);
        let t2 = t0 + TimeDelta::seconds(2);

        // INVITE, then 200 OK, then retransmitted INVITE
        store.process_message(make_invite_msg("state-test@test", t0));
        store.process_message(make_200_ok("state-test@test", t1));

        let dialog = store.get("state-test@test").expect("dialog should exist");
        assert_eq!(*dialog.state(), DialogState::InCall);

        // Now process a retransmitted INVITE (same CSeq)
        store.process_message(make_invite_msg("state-test@test", t2));

        let dialog = store.get("state-test@test").expect("dialog should exist");
        // State should still be InCall — the retransmission should not change it
        assert_eq!(*dialog.state(), DialogState::InCall);
        // Should have 3 messages now (original INVITE + 200 OK + retransmitted INVITE)
        assert_eq!(dialog.messages.len(), 3);
        assert!(dialog.messages[2].is_retransmission);
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
        assert_eq!(*dialog.state(), DialogState::Completed);
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
        let msg = parse_sip(
            &raw,
            base_ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
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
            parse_sip(
                &raw,
                t1,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse")
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
            parse_sip(
                &raw,
                t2,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse")
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
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
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

        // Use timestamps > 2s apart so the timing heuristic doesn't match
        store.process_message(make_invite_msg("standalone@test", t0));
        store.process_message(make_invite_msg("another@test", t0 + TimeDelta::seconds(5)));

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

    // ── Step 4: Scored correlation tests ────────────────────────────────

    #[test]
    fn scored_x_call_id_returns_100() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("scored-a@test", t0));
        store.process_message(make_invite_with_x_call_id(
            "scored-b@test",
            "scored-a@test",
            t0 + TimeDelta::seconds(1),
        ));

        let results = store.find_correlated_scored("scored-a@test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dialog.call_id, "scored-b@test");
        assert_eq!(results[0].score, 100);
        assert_eq!(results[0].reason, CorrelationReason::XCallId);
    }

    /// Build an INVITE with a Via header containing a specific branch parameter.
    fn make_invite_with_via_branch(call_id: &str, branch: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"),
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE with Via branch")
    }

    #[test]
    fn scored_via_branch_returns_80() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_with_via_branch(
            "via-a@test",
            "z9hG4bK-shared-branch",
            t0,
        ));
        store.process_message(make_invite_with_via_branch(
            "via-b@test",
            "z9hG4bK-shared-branch",
            t0 + TimeDelta::seconds(1),
        ));

        let results = store.find_correlated_scored("via-a@test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dialog.call_id, "via-b@test");
        assert_eq!(results[0].score, 80);
        assert_eq!(results[0].reason, CorrelationReason::ViaBranch);
    }

    #[test]
    fn scored_timing_heuristic_returns_50() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Two INVITEs from same IP within 2 seconds, no other correlation signal
        store.process_message(make_invite_msg("timing-a@test", t0));
        store.process_message(make_invite_msg("timing-b@test", t0 + TimeDelta::seconds(1)));

        let results = store.find_correlated_scored("timing-a@test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dialog.call_id, "timing-b@test");
        assert_eq!(results[0].score, 50);
        assert_eq!(results[0].reason, CorrelationReason::TimingHeuristic);
    }

    #[test]
    fn timing_heuristic_excluded_beyond_2s() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("gap-a@test", t0));
        store.process_message(make_invite_msg("gap-b@test", t0 + TimeDelta::seconds(3)));

        let results = store.find_correlated_scored("gap-a@test");
        assert!(results.is_empty());
    }

    #[test]
    fn scored_dedup_highest_score_wins() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // A-leg: INVITE with a Via branch
        store.process_message(make_invite_with_via_branch(
            "dedup-a@test",
            "z9hG4bK-shared",
            t0,
        ));

        // B-leg: INVITE with X-Call-ID AND matching Via branch
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-shared",
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: dedup-b@test",
                "CSeq: 1 INVITE",
                "X-Call-ID: dedup-a@test",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            t0 + TimeDelta::seconds(1),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        store.process_message(msg);

        // X-Call-ID is checked first and wins (score=100), Via is skipped (dedup)
        let results = store.find_correlated_scored("dedup-a@test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].score, 100);
        assert_eq!(results[0].reason, CorrelationReason::XCallId);
    }

    // ── Eviction with max_dialogs=3 ──────────────────────────────────

    #[test]
    fn eviction_max3_rotate() {
        let mut store = DialogStore::new(3, true);
        let t0 = base_ts();

        // Add 4 dialogs — the first should be evicted
        store.process_message(make_invite_msg("evict-1@test", t0));
        store.process_message(make_invite_msg("evict-2@test", t0 + TimeDelta::seconds(1)));
        store.process_message(make_invite_msg("evict-3@test", t0 + TimeDelta::seconds(2)));
        assert_eq!(store.len(), 3);

        store.process_message(make_invite_msg("evict-4@test", t0 + TimeDelta::seconds(3)));
        assert_eq!(store.len(), 3);

        // First dialog evicted
        assert!(
            store.get("evict-1@test").is_none(),
            "evict-1 should have been evicted"
        );

        // Remaining 3 accessible by Call-ID
        assert!(
            store.get("evict-2@test").is_some(),
            "evict-2 should still be present"
        );
        assert!(
            store.get("evict-3@test").is_some(),
            "evict-3 should still be present"
        );
        assert!(
            store.get("evict-4@test").is_some(),
            "evict-4 should still be present"
        );

        // Verify index correctness: get_mut also works (proves indices are correct)
        let d2 = store
            .get_mut("evict-2@test")
            .expect("evict-2 should be mutable");
        assert_eq!(d2.call_id, "evict-2@test");
        let d3 = store
            .get_mut("evict-3@test")
            .expect("evict-3 should be mutable");
        assert_eq!(d3.call_id, "evict-3@test");
        let d4 = store
            .get_mut("evict-4@test")
            .expect("evict-4 should be mutable");
        assert_eq!(d4.call_id, "evict-4@test");

        // Verify iteration order: oldest-remaining first
        let call_ids: Vec<&str> = store.iter().map(|d| d.call_id.as_str()).collect();
        assert_eq!(
            call_ids,
            vec!["evict-2@test", "evict-3@test", "evict-4@test"]
        );
    }

    // ── Message cap per dialog ─────────────────────────────────────────

    #[test]
    fn message_cap_at_max_messages_per_dialog() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Create a dialog with the initial INVITE
        store.process_message(make_invite_msg("capped@test", t0));

        // Push 600 additional messages (200 OK with incrementing CSeq to avoid
        // retransmission detection). The first message is the INVITE (CSeq 1),
        // so start CSeq at 2.
        for i in 2..602u32 {
            let raw = build_sip(
                "SIP/2.0 200 OK",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: capped@test",
                    &format!("CSeq: {i} INVITE"),
                    "Content-Length: 0",
                ],
                b"",
            );
            let msg = parse_sip(
                &raw,
                t0 + TimeDelta::milliseconds(i as i64),
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse");
            store.process_message(msg);
        }

        let dialog = store.get("capped@test").expect("dialog should exist");
        assert_eq!(
            dialog.messages.len(),
            DEFAULT_MAX_MESSAGES_PER_DIALOG,
            "messages should be capped at {DEFAULT_MAX_MESSAGES_PER_DIALOG}"
        );
    }

    // ── Via branch HashSet correlation smoke test ───────────────────────

    #[test]
    fn via_branch_correlation_smoke_test() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Two dialogs sharing a Via branch
        store.process_message(make_invite_with_via_branch(
            "smoke-a@test",
            "z9hG4bK-smoke-branch",
            t0,
        ));
        store.process_message(make_invite_with_via_branch(
            "smoke-b@test",
            "z9hG4bK-smoke-branch",
            t0 + TimeDelta::seconds(1),
        ));

        // A third dialog with a DIFFERENT branch — should NOT correlate
        store.process_message(make_invite_with_via_branch(
            "smoke-c@test",
            "z9hG4bK-different-branch",
            t0 + TimeDelta::seconds(5), // >2s apart to avoid timing heuristic
        ));

        // smoke-a should correlate with smoke-b (branch overlap) and smoke-b (timing),
        // but NOT with smoke-c
        let results = store.find_correlated_scored("smoke-a@test");
        let correlated_ids: Vec<&str> = results.iter().map(|r| r.dialog.call_id.as_str()).collect();
        assert!(
            correlated_ids.contains(&"smoke-b@test"),
            "smoke-b should be correlated via branch"
        );
        assert!(
            !correlated_ids.contains(&"smoke-c@test"),
            "smoke-c should NOT be correlated (different branch, >2s apart)"
        );

        // Verify the branch match produces score=80
        let branch_result = results.iter().find(|r| r.dialog.call_id == "smoke-b@test");
        assert!(branch_result.is_some());
        // Score could be 80 (branch) — timing heuristic is also eligible but branch wins first
        assert_eq!(branch_result.unwrap().score, 80);
        assert_eq!(branch_result.unwrap().reason, CorrelationReason::ViaBranch);
    }

    // ── REFER transfer tracking tests ─────────────────────────────────

    #[test]
    fn refer_stores_refer_to_header() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);
        let t2 = t0 + TimeDelta::seconds(2);

        // Establish call: INVITE -> 200 OK -> InCall
        store.process_message(make_invite_msg("refer-track@test", t0));
        store.process_message(make_200_ok("refer-track@test", t1));

        let dialog = store.get("refer-track@test").expect("dialog should exist");
        assert_eq!(*dialog.state(), DialogState::InCall);
        assert!(
            dialog.refer_to.is_none(),
            "refer_to should be None before REFER"
        );

        // Send REFER with Refer-To header
        let refer = {
            let raw = build_sip(
                "REFER sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: refer-track@test",
                    "CSeq: 2 REFER",
                    "Refer-To: <sip:1003@example.com>",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(
                &raw,
                t2,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse REFER")
        };
        store.process_message(refer);

        let dialog = store.get("refer-track@test").expect("dialog should exist");
        assert_eq!(*dialog.state(), DialogState::Transferring);
        assert!(
            dialog.refer_to.is_some(),
            "refer_to should be populated after REFER"
        );
        let refer_to = dialog.refer_to.as_deref().unwrap();
        assert!(
            refer_to.contains("sip:1003@example.com"),
            "refer_to should contain the target URI, got: {refer_to}"
        );
    }

    #[test]
    fn refer_without_header_leaves_none() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);
        let t2 = t0 + TimeDelta::seconds(2);

        // Establish call
        store.process_message(make_invite_msg("refer-none@test", t0));
        store.process_message(make_200_ok("refer-none@test", t1));

        // Send REFER without Refer-To header
        let refer = {
            let raw = build_sip(
                "REFER sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: refer-none@test",
                    "CSeq: 2 REFER",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(
                &raw,
                t2,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse REFER")
        };
        store.process_message(refer);

        let dialog = store.get("refer-none@test").expect("dialog should exist");
        assert!(
            dialog.refer_to.is_none(),
            "refer_to should remain None when no Refer-To header present"
        );
    }

    // ── SIPREC metadata parsing test ──────────────────────────────────

    #[test]
    fn siprec_metadata_parsed_from_multipart() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);

        // Create dialog with initial INVITE
        store.process_message(make_invite_msg("siprec@test", t0));

        let dialog = store.get("siprec@test").expect("dialog should exist");
        assert!(dialog.siprec_metadata.is_none(), "no SIPREC metadata yet");

        // Build a multipart/mixed message with SIPREC metadata
        let siprec_body = b"--unique-boundary\r\n\
Content-Type: application/sdp\r\n\r\n\
v=0\r\n\
--unique-boundary\r\n\
Content-Type: application/rs-metadata+xml\r\n\r\n\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n\
  <session session_id=\"siprec-sess-001\">\n\
    <participant participant_id=\"p1\">\n\
      <nameID><aor>sip:alice@example.com</aor></nameID>\n\
      <name>Alice</name>\n\
    </participant>\n\
    <stream stream_id=\"s1\">\n\
      <label>audio</label>\n\
    </stream>\n\
  </session>\n\
</recording>\n\
--unique-boundary--";

        let content_len = siprec_body.len();
        let raw = build_sip(
            "INVITE sip:recorder@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: siprec@test",
                "CSeq: 2 INVITE",
                "Content-Type: multipart/mixed; boundary=unique-boundary",
                &format!("Content-Length: {content_len}"),
            ],
            siprec_body,
        );
        let msg = parse_sip(
            &raw,
            t1,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse SIPREC INVITE");
        store.process_message(msg);

        let dialog = store.get("siprec@test").expect("dialog should exist");
        assert!(
            dialog.siprec_metadata.is_some(),
            "SIPREC metadata should be parsed and stored"
        );
        let metadata = dialog.siprec_metadata.as_ref().unwrap();
        assert_eq!(metadata.session_id.as_deref(), Some("siprec-sess-001"));
        assert_eq!(metadata.participants.len(), 1);
        assert_eq!(metadata.participants[0].name.as_deref(), Some("Alice"));
        assert_eq!(metadata.streams.len(), 1);
        assert_eq!(metadata.streams[0].label.as_deref(), Some("audio"));
    }
}
