// SPDX-License-Identifier: MIT OR Apache-2.0

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
///
/// # Arguments
///
/// * `limit` — Maximum number of messages retained per dialog.
///
/// # Side effects
///
/// Stores `limit` into the process-wide `MAX_MESSAGES_PER_DIALOG` atomic
/// (relaxed ordering), affecting every `DialogStore` in the process from
/// the next message onward.
pub fn set_max_messages_per_dialog(limit: usize) {
    MAX_MESSAGES_PER_DIALOG.store(limit, std::sync::atomic::Ordering::Relaxed);
}

/// Reason a dialog was correlated to another.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorrelationReason {
    /// Matched via the RFC 7989 `Session-ID` header.
    ///
    /// The strongest of the three, and the only one that crosses a B2BUA by
    /// design: an SBC rewrites Call-ID and Via branch, and RFC 7989 exists so
    /// the session identifier survives that. Scored the same 100 as
    /// [`Self::XCallId`] because both are identifier matches rather than
    /// guesses, but reported separately — one is a standard, the other a vendor
    /// convention, and a reader deciding how much to trust a call tree needs to
    /// know which they have.
    SessionId,
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
/// How messages are grouped into tracked units (`--dialog-track`).
///
/// See `docs/design/dialog-tracking-modes.md`. The short version: `CallId` is
/// RFC 3261 dialog identity and is right for ordinary traffic; `Branch` groups
/// by transaction instead, which is what load generators and proxies-under-test
/// need when one Call-ID is reused across many transactions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DialogTracking {
    /// Group by Call-ID — one tracked unit per dialog.
    #[default]
    CallId,
    /// Group by Call-ID + top-Via branch — one tracked unit per transaction.
    ///
    /// A single call becomes several units: RFC 3261 gives the ACK to a 2xx a
    /// new branch (§17.1.1.3) and the BYE another. That is the transaction view
    /// working as intended, not a bug.
    Branch,
}

impl std::str::FromStr for DialogTracking {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "call-id" | "callid" | "call_id" => Ok(Self::CallId),
            "branch" => Ok(Self::Branch),
            other => Err(format!(
                "unknown dialog-tracking method '{other}' (expected 'call-id' or 'branch')"
            )),
        }
    }
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
///
/// # Examples
///
/// ```
/// use sipnab::{DialogStore, DialogState};
/// use sipnab::net::TransportProto;
/// use sipnab::sip::parser::parse_sip;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
///     Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n\
///     From: <sip:alice@example.com>;tag=a1\r\n\
///     To: <sip:bob@example.com>\r\n\
///     Call-ID: demo@example.com\r\n\
///     CSeq: 1 INVITE\r\n\
///     Content-Length: 0\r\n\r\n";
/// let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
/// let msg = parse_sip(raw, chrono::Utc::now(), ip, ip, 5060, 5060, TransportProto::Udp)?;
///
/// let mut store = DialogStore::new(10_000, false);
/// store.process_message(msg);
/// assert_eq!(store.len(), 1);
///
/// let dialog = store.get("demo@example.com").expect("dialog tracked by Call-ID");
/// assert_eq!(*dialog.state(), DialogState::Trying);
/// # Ok::<(), sipnab::ParseError>(())
/// ```
#[derive(Debug)]
pub struct DialogStore {
    /// All tracked dialogs, keyed by Call-ID in insertion order.
    dialogs: IndexMap<String, SipDialog, ahash::RandomState>,
    /// How messages are grouped into tracked units.
    tracking: DialogTracking,
    /// Maximum number of dialogs to retain.
    max_dialogs: usize,
    /// Whether to evict the oldest dialog when at capacity.
    rotate: bool,
    /// Lifetime count of messages dropped by [`compact_idle`]
    /// (DialogStore::compact_idle) — observability for long-run memory
    /// behaviour.
    idle_messages_evicted: u64,
    /// Lifetime count of NEW dialogs REJECTED because the store was at
    /// capacity with `rotate` disabled — the observability sibling of
    /// `idle_messages_evicted`. In rotate mode nothing is rejected (the
    /// oldest is evicted instead), so this stays zero there and
    /// `capacity_dialogs_evicted` moves instead.
    capacity_dialogs_dropped: u64,
    /// Lifetime count of dialogs DISCARDED by drop-oldest rotation — the
    /// default disposal policy, and until this field existed the only one
    /// that counted nothing.
    ///
    /// Kept separate from `capacity_dialogs_dropped` because the two losses
    /// are not interchangeable: rejecting the newest keeps a complete record
    /// of the earliest calls, while evicting the oldest keeps a complete
    /// record of the latest. An operator reading "5000 dialogs lost to
    /// capacity" needs to know which end of the capture is missing.
    capacity_dialogs_evicted: u64,
    /// Mutation counter for cache invalidation — see [`Self::generation`].
    generation: u64,
    /// Header names used for B2BUA leg correlation (sngrep `sip.xcid`). A
    /// candidate dialog whose message carries one of these headers pointing at
    /// another dialog's Call-ID (or vice versa) is correlated at score 100.
    /// Defaults to `["X-Call-ID"]`.
    xcid_headers: Vec<String>,
}

/// A dialog idle longer than this has its stored messages compacted.
///
/// Per-dialog message Vecs are capped in *count* but never shrank: a
/// weeks-long capture accumulates idle dialogs each pinning up to
/// `MAX_MESSAGES_PER_DIALOG` full messages (raw bytes + bodies) forever.
/// Ten minutes of silence on a dialog means the call is over or stale; the
/// message tail is enough context. (Dialog *count* is separately bounded by
/// the store capacity, which evicts the oldest dialog when `rotate` is on —
/// the default since SNB-0004.)
pub const IDLE_COMPACT_AFTER: chrono::TimeDelta = chrono::TimeDelta::minutes(10);

/// How many messages an idle dialog keeps. A hard cap: compaction never
/// leaves more than this, whatever the retention rule decides is worth
/// keeping.
pub const KEEP_MESSAGES_PER_IDLE_DIALOG: usize = 20;

/// Whether a message states something about the dialog that its POSITION in
/// the ladder does not.
///
/// # Why position is the wrong question
///
/// Compaction used to keep the last N messages, which treats a dialog as a
/// log. It is a state machine. On an `INVITE` dialog the `200 OK` arrives
/// second or third, so it was among the FIRST messages evicted, and
/// [`SipDialog::final_status_code`](crate::sip::dialog::SipDialog::final_status_code)
/// then returned `None` on a call that had completed normally. That is worse
/// than a shortened ladder: a shortened ladder loses detail, this loses the
/// outcome — and "no final response" is a diagnosis sipnab emits in its own
/// right (`NoFinalResponse`, Timer C), so the loss did not read as missing
/// data. It read as a specific fault that never happened.
///
/// # What counts
///
/// * The dialog's opening request (`INVITE`, `REGISTER`, `SUBSCRIBE` …) —
///   the thing the call *was*, and the message every evidence index and the
///   report header are anchored on.
/// * `BYE` and `CANCEL` — deliberate teardown. A `CANCEL` sits early in a
///   long ladder and would otherwise go the same way as the `200`.
/// * Every final (`>= 200`) response, and the `401`/`407` challenges, since
///   `final_status_code` falls back to a challenge for a dialog that was only
///   ever challenged.
///
/// Retransmissions of an anchor are not themselves anchors: the caller keeps
/// the first occurrence of each distinct `(status, CSeq method)` pair, so a
/// `200` sent eight times pins one message rather than eight.
///
/// Everything else — provisionals, `ACK`, in-dialog `OPTIONS`/`INFO`/`UPDATE`
/// — is mid-call detail whose value really is positional, and the most recent
/// of those fill whatever budget the anchors leave.
fn carries_dialog_outcome(msg: &SipMessage, dialog_method: &SipMethod) -> bool {
    if msg.is_request {
        return matches!(msg.method, Some(SipMethod::Bye | SipMethod::Cancel))
            || msg.method.as_ref() == Some(dialog_method);
    }
    matches!(msg.status_code, Some(c) if c >= 200 || c == 401 || c == 407)
}

/// The indices of `messages` to keep when compacting an idle dialog, in
/// capture order.
///
/// Anchors ([`carries_dialog_outcome`], de-duplicated) take the budget first;
/// the remainder goes to the most recent non-anchor messages. Returns `None`
/// when nothing would be dropped, so the caller can skip the dialog and stay
/// idempotent.
///
/// # Arguments
///
/// * `messages` — the dialog's stored messages, in capture order.
/// * `dialog_method` — the method the dialog was opened with.
/// * `budget` — the hard maximum to keep ([`KEEP_MESSAGES_PER_IDLE_DIALOG`]).
///
/// # Returns
///
/// `Some(indices)` — strictly ascending, at most `budget` long, strictly
/// shorter than `messages` — or `None` when `messages` already fits.
fn retained_indices(
    messages: &[SipMessage],
    dialog_method: &SipMethod,
    budget: usize,
) -> Option<Vec<usize>> {
    if messages.len() <= budget {
        return None;
    }

    let mut anchors: Vec<usize> = Vec::new();
    let mut seen_responses: Vec<(u16, String)> = Vec::new();
    let mut seen_opening_request = false;
    let mut seen_request_methods: Vec<&SipMethod> = Vec::new();

    for (idx, msg) in messages.iter().enumerate() {
        if !carries_dialog_outcome(msg, dialog_method) {
            continue;
        }
        if msg.is_request {
            let Some(method) = msg.method.as_ref() else {
                continue;
            };
            // One INVITE anchor, not one per re-INVITE or retransmission;
            // one BYE, one CANCEL.
            if method == dialog_method {
                if seen_opening_request {
                    continue;
                }
                seen_opening_request = true;
            } else if seen_request_methods.contains(&method) {
                continue;
            } else {
                seen_request_methods.push(method);
            }
        } else {
            let key = (
                msg.status_code.unwrap_or_default(),
                msg.cseq().map(|(_, m)| m.to_string()).unwrap_or_default(),
            );
            if seen_responses.contains(&key) {
                continue;
            }
            seen_responses.push(key);
        }
        anchors.push(idx);
    }

    // A peer that answers one request with hundreds of DISTINCT status codes
    // could otherwise use the anchor rule to defeat the bound. The budget is
    // a memory guarantee, so it wins: the earliest anchors and the last one
    // survive, which keeps both ends of the exchange.
    //
    // `budget == 0` is not reachable from `KEEP_MESSAGES_PER_IDLE_DIALOG`, but
    // it is reachable from the signature, and `budget - 1` on it would panic
    // in debug and wrap in release — the shape of bug this module exists to
    // stop shipping.
    if anchors.len() > budget {
        let Some(last) = anchors.last().copied() else {
            return Some(Vec::new());
        };
        anchors.truncate(budget.saturating_sub(1));
        if anchors.len() < budget {
            anchors.push(last);
        }
        return Some(anchors);
    }

    // Whatever the anchors leave goes to the most recent messages, which is
    // what the old rule did with the whole budget.
    let mut keep: std::collections::BTreeSet<usize> = anchors.iter().copied().collect();
    for idx in (0..messages.len()).rev() {
        if keep.len() >= budget {
            break;
        }
        keep.insert(idx);
    }
    Some(keep.into_iter().collect())
}

/// What one [`DialogStore::compact_idle`] sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompactStats {
    /// Dialogs that had messages evicted this sweep.
    pub dialogs_compacted: usize,
    /// Messages evicted this sweep.
    pub messages_evicted: usize,
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
    ///
    /// # Returns
    ///
    /// An empty store (generation 0) with the default `X-Call-ID`
    /// correlation header configured.
    pub fn new(max_dialogs: usize, rotate: bool) -> Self {
        Self {
            dialogs: IndexMap::with_capacity_and_hasher(
                max_dialogs.min(1024),
                ahash::RandomState::default(),
            ),
            max_dialogs,
            rotate,
            tracking: DialogTracking::default(),
            idle_messages_evicted: 0,
            capacity_dialogs_dropped: 0,
            capacity_dialogs_evicted: 0,
            generation: 0,
            xcid_headers: vec!["X-Call-ID".to_string()],
        }
    }

    /// Override the correlation header names (sngrep `sip.xcid`). An empty list
    /// is ignored so the default `["X-Call-ID"]` is preserved. Builder-style:
    /// returns `self` for chaining after [`new`](Self::new).
    #[must_use]
    pub fn with_xcid_headers(mut self, headers: Vec<String>) -> Self {
        if !headers.is_empty() {
            self.xcid_headers = headers;
        }
        self
    }

    /// Monotonic mutation counter: bumped by every operation that can
    /// change what an observer would derive from the store (new dialog,
    /// in-place message, merge, clear, retain, idle compaction, and any
    /// `get_mut` hand-out). The TUI keys its per-frame displayed-dialogs
    /// cache on this, so staleness is impossible by construction.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Compact dialogs that have been idle longer than
    /// [`IDLE_COMPACT_AFTER`] down to at most
    /// [`KEEP_MESSAGES_PER_IDLE_DIALOG`] messages each, keeping the ones that
    /// say what the dialog DID and compacting the middle. Bounds long-run
    /// memory: an idle dialog can otherwise pin hundreds of full SIP messages
    /// forever.
    ///
    /// # Retention, not truncation
    ///
    /// This kept the last N messages until it was caught reporting a
    /// completed call as having no final response: on an `INVITE` dialog the
    /// `200 OK` arrives early, so position-based eviction took the OUTCOME
    /// first and left the mid-call filler. See `carries_dialog_outcome` for
    /// what survives regardless of where it sits and why.
    ///
    /// Intended to be called from the existing periodic sweep. Idempotent: a
    /// compacted dialog is skipped until it grows past the keep limit again.
    ///
    /// # Arguments
    ///
    /// * `now` — Current time; dialogs whose `updated_at` is more than
    ///   `IDLE_COMPACT_AFTER` before `now` are considered idle.
    ///
    /// # Returns
    ///
    /// A `CompactStats` with the dialogs touched and messages evicted by
    /// this sweep (all zero when nothing was idle or over the keep limit).
    ///
    /// # Side effects
    ///
    /// Rewrites the message list of each over-limit idle dialog, releases the
    /// Vec's excess capacity, adds to the lifetime `idle_messages_evicted`
    /// counter, and bumps the generation counter (unconditionally, even when
    /// nothing is compacted).
    pub fn compact_idle(&mut self, now: chrono::DateTime<chrono::Utc>) -> CompactStats {
        self.generation += 1;
        let mut stats = CompactStats::default();
        for dialog in self.dialogs.values_mut() {
            if now - dialog.updated_at <= IDLE_COMPACT_AFTER {
                continue;
            }
            let Some(keep) = retained_indices(
                &dialog.messages,
                &dialog.method,
                KEEP_MESSAGES_PER_IDLE_DIALOG,
            ) else {
                continue;
            };
            let before = dialog.messages.len();
            // Ascending indices, consumed in order: retain_mut walks the Vec
            // once and moves survivors down in place, so a long dialog costs
            // one pass rather than a removal per evicted message.
            let mut next = keep.iter().copied().peekable();
            let mut idx = 0usize;
            dialog.messages.retain_mut(|_| {
                let keep_this = next.peek() == Some(&idx);
                if keep_this {
                    next.next();
                }
                idx += 1;
                keep_this
            });
            dialog.messages.shrink_to_fit();
            let evicted = before - dialog.messages.len();
            if evicted == 0 {
                continue;
            }
            stats.dialogs_compacted += 1;
            stats.messages_evicted += evicted;
        }
        self.idle_messages_evicted += stats.messages_evicted as u64;
        stats
    }

    /// Lifetime count of messages evicted by [`DialogStore::compact_idle`].
    pub fn total_idle_messages_evicted(&self) -> u64 {
        self.idle_messages_evicted
    }

    /// Lifetime count of new dialogs REJECTED at capacity in no-rotate mode.
    ///
    /// The counterpart to [`DialogStore::total_idle_messages_evicted`] for
    /// one of the two ways the store sheds dialogs: when `rotate` is disabled
    /// and a message for an unknown Call-ID arrives at capacity, the dialog is
    /// rejected rather than created, so the EARLIEST calls are the ones kept.
    /// Zero in rotate mode — see
    /// [`total_capacity_dialogs_evicted`](Self::total_capacity_dialogs_evicted)
    /// for the default path.
    pub fn total_capacity_dialogs_dropped(&self) -> u64 {
        self.capacity_dialogs_dropped
    }

    /// Lifetime count of dialogs DISCARDED by drop-oldest rotation — the
    /// default disposal policy (`--rotate`, on unless `--no-rotate`).
    ///
    /// The sibling of
    /// [`total_capacity_dialogs_dropped`](Self::total_capacity_dialogs_dropped),
    /// and the one that moves on the path almost every run takes. Both are
    /// capacity loss; they differ in which end of the capture survives, so a
    /// caller reporting either must say which it is.
    pub fn total_capacity_dialogs_evicted(&self) -> u64 {
        self.capacity_dialogs_evicted
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
    ///
    /// # Arguments
    ///
    /// * `msg` — The parsed SIP message to route (consumed; moved into the
    ///   dialog's message list when under the per-dialog cap).
    ///
    /// # Side effects
    ///
    /// Bumps the generation counter unconditionally, then either mutates
    /// the matched dialog in place (seen-CSeq set, retransmit counts,
    /// state machine, timing, SDP timeline, REFER target, SIPREC
    /// metadata, message list, `updated_at`) or inserts a new dialog —
    /// possibly evicting the oldest batch first when at capacity with
    /// `rotate` enabled. At capacity without `rotate`, messages for
    /// unknown Call-IDs are dropped (bumping the capacity-drop counter);
    /// updates to existing dialogs still land.
    pub fn process_message(&mut self, mut msg: SipMessage) {
        self.generation += 1;
        // Look up by the borrowed Call-ID (str is Equivalent<String> for
        // IndexMap); the owned key is allocated only when a new dialog is
        // actually inserted — not once per message on the hot path.
        // CallId mode keeps the original no-allocation lookup: `str` is
        // Equivalent<String> for IndexMap, so the owned key is built only when
        // a dialog is actually inserted. Branch mode has to compose a key, so
        // it allocates — but only when the mode is switched on, leaving the
        // default hot path exactly as it was.
        let composed = match self.tracking {
            DialogTracking::CallId => None,
            DialogTracking::Branch => self.tracking_key(&msg),
        };
        let lookup: &str = match (composed.as_deref(), msg.call_id()) {
            (Some(k), _) => k,
            (None, Some(id)) => id,
            (None, None) => return,
        };
        let dialog_idx = self.dialogs.get_index_of(lookup);

        if let Some(idx) = dialog_idx {
            let Some((_, dialog)) = self.dialogs.get_index_mut(idx) else {
                return; // unreachable: idx came from get_index_of
            };
            // Retransmission detection: same CSeq identity already seen.
            // O(1) set probe that survives message capping and compaction
            // (the old stored-message scan went amnesiac past the cap).
            // First sighting is remembered, capped against CSeq cycling.
            let seen_key = crate::sip::dialog::seen_cseq_key(&msg);
            let retransmission = seen_key
                .as_ref()
                .is_some_and(|k| dialog.seen_cseq.contains(k));
            if !retransmission
                && dialog.seen_cseq.len() < crate::sip::dialog::MAX_SEEN_CSEQ_PER_DIALOG
                && let Some(key) = seen_key
            {
                dialog.seen_cseq.insert(key);
            }
            if retransmission {
                let cseq_key = cseq_key(&msg);
                if let Some(key) = cseq_key {
                    *dialog.timing.retransmit_counts.entry(key).or_insert(0) += 1;
                }
                // Mark as retransmission but store it for ladder display (capped)
                msg.is_retransmission = true;
                let ts = msg.timestamp;
                if dialog.messages.len()
                    < MAX_MESSAGES_PER_DIALOG.load(std::sync::atomic::Ordering::Relaxed)
                {
                    dialog.messages.push(msg);
                }
                // Even a dropped (at-cap) retransmission is activity: use the
                // arriving message's timestamp, not the stored tail's, so a
                // retransmission flood keeps the dialog out of compact_idle.
                dialog.updated_at = ts;
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
                    // Full and not rotating: this new Call-ID is dropped.
                    // Count it — the observability sibling of idle eviction.
                    self.capacity_dialogs_dropped += 1;
                    return;
                }
            }

            // Create the new dialog
            if let Some(mut dialog) = SipDialog::new(&msg) {
                // Update timing for the initial message
                update_timing(&mut dialog.timing, &msg, &dialog.method);

                // Track SDP for the initial message
                track_sdp(&mut dialog.sdp_timeline, &msg);

                // Insert under the SAME key the lookup used, or the next
                // message for this unit would miss and create a duplicate.
                let key = match composed {
                    Some(k) => k,
                    None => match msg.call_id() {
                        Some(id) => id.to_string(),
                        None => return, // unreachable: checked at function entry
                    },
                };
                self.dialogs.insert(key, dialog);
            }
        }
    }

    /// Select how messages are grouped. Must be set before any message is
    /// processed; changing it mid-capture would strand already-keyed entries.
    pub fn set_tracking(&mut self, tracking: DialogTracking) {
        self.tracking = tracking;
    }

    /// The key `msg` groups under, given the configured mode.
    ///
    /// `\n` separates Call-ID from branch because a parsed header value cannot
    /// contain one, so no crafted Call-ID can forge a different unit's key.
    /// `seen_cseq_key` uses the same separator for the same reason.
    ///
    /// A message with no branch (RFC 2543 peers) falls back to Call-ID alone,
    /// so it groups exactly as it does today rather than collecting in one
    /// empty-branch bucket.
    fn tracking_key(&self, msg: &SipMessage) -> Option<String> {
        let call_id = msg.call_id()?;
        Ok::<String, ()>(match (self.tracking, msg.top_via_branch()) {
            (DialogTracking::Branch, Some(branch)) if !branch.is_empty() => {
                format!("{call_id}\n{branch}")
            }
            _ => call_id.to_string(),
        })
        .ok()
    }

    /// Look up a dialog by Call-ID; returns `None` when no dialog with
    /// that Call-ID is tracked.
    ///
    /// In `Branch` mode a Call-ID can name several tracked units (one per
    /// transaction), and this returns the FIRST in insertion order. That keeps
    /// `--call-report`, the REST API, the MCP tools and the TUI working on a
    /// Call-ID as they always have; `get_by_key` addresses one specific unit.
    pub fn get(&self, call_id: &str) -> Option<&SipDialog> {
        if let Some(d) = self.dialogs.get(call_id) {
            return Some(d);
        }
        if self.tracking == DialogTracking::Branch {
            let prefix = format!("{call_id}\n");
            return self
                .dialogs
                .iter()
                .find(|(k, _)| k.starts_with(&prefix))
                .map(|(_, d)| d);
        }
        None
    }

    /// Look up one specific tracked unit by its full tracking key.
    pub fn get_by_key(&self, key: &str) -> Option<&SipDialog> {
        self.dialogs.get(key)
    }

    /// Look up a dialog by Call-ID, returning a mutable reference, or
    /// `None` when the Call-ID is unknown.
    ///
    /// # Side effects
    ///
    /// Bumps the generation counter — even on a miss — because the
    /// handed-out reference may be used to mutate the dialog behind the
    /// store's back.
    pub fn get_mut(&mut self, call_id: &str) -> Option<&mut SipDialog> {
        self.generation += 1;
        self.dialogs.get_mut(call_id)
    }

    /// Iterate over all tracked dialogs in insertion order (the TUI call
    /// list's default sort order).
    pub fn iter(&self) -> impl Iterator<Item = &SipDialog> {
        self.dialogs.values()
    }

    /// Fold another worker's dialogs into this one (multi-core merge, `--cores N`).
    ///
    /// # Same-Call-ID collisions are the normal case, not the rare one
    ///
    /// `crate::parallel` shards packets by host pair, which keeps an RTP stream
    /// and both directions of a flow on one worker. It does NOT keep a call's
    /// SIP on one worker: a call through a proxy or SBC is captured on two host
    /// pairs (access side and trunk side) and therefore reconstructs as two
    /// fragments on two workers. On a carrier capture that is most of the
    /// traffic, not an edge case — measured at 1173 of 2311 dialogs in one
    /// 100 MB file.
    ///
    /// So a collision is not a contest to be won. The fragments are disjoint
    /// observations of one call and the merged dialog is their SUM: the message
    /// lists are concatenated in capture-timestamp order and the state machine
    /// is re-run over the result, reproducing what the single-threaded path
    /// built from the same packets. Picking the longer fragment as a "base" —
    /// which is what this used to do — discarded the other leg's signalling
    /// outright, and because `merge` is Call-ID-keyed the loss was invisible in
    /// every dialog *count* the tool prints.
    ///
    /// # Arguments
    ///
    /// * `other` — The worker store to fold in (consumed).
    ///
    /// # Side effects
    ///
    /// Inserts `other`'s distinct-Call-ID dialogs into `self`, subject to
    /// `self`'s capacity (see below); on a collision concatenates the message
    /// lists, unions the seen-CSeq set, retransmit counts and timing milestones
    /// (`union_dialog_state`), and recomputes the message-derived state
    /// (`replay_message_derived_state`); accumulates `other`'s lifetime
    /// idle-eviction, capacity-rejection and capacity-eviction counters; and
    /// bumps the generation counter.
    ///
    /// # Capacity
    ///
    /// The cap is enforced here as it is in `process_message`, because each
    /// worker enforces `--limit` only on its own shard: an unconditional insert
    /// let `--cores N` hold up to N × the cap, silently multiplying by the core
    /// count the one number an operator sets to bound memory. Rotating stores
    /// evict the oldest to make room, non-rotating stores reject the incoming
    /// Call-ID, and either way the loss is counted.
    pub fn merge(&mut self, other: DialogStore) {
        self.generation += 1;
        for (cid, mut dialog) in other.dialogs {
            match self.dialogs.get_index_of(&cid) {
                Some(idx) => {
                    let existing = &mut self.dialogs[idx];
                    // The fragment that saw the call FIRST supplies the
                    // identity the single-threaded path would have derived:
                    // `SipDialog::new` mines From/To, the addresses and the
                    // dialog `method` from the first message seen, and the
                    // state machine dispatches on that method. Ordering by
                    // message count instead would let a busier later leg
                    // rename the call.
                    if dialog.created_at < existing.created_at {
                        std::mem::swap(existing, &mut dialog);
                    }
                    union_dialog_state(existing, &dialog);
                    absorb_messages(existing, dialog.messages);
                    replay_message_derived_state(existing);
                }
                None => {
                    if self.dialogs.len() >= self.max_dialogs {
                        if self.rotate {
                            self.evict_oldest();
                        } else {
                            self.capacity_dialogs_dropped += 1;
                            continue;
                        }
                    }
                    self.dialogs.insert(cid, dialog);
                }
            }
        }
        self.idle_messages_evicted += other.idle_messages_evicted;
        self.capacity_dialogs_dropped += other.capacity_dialogs_dropped;
        self.capacity_dialogs_evicted += other.capacity_dialogs_evicted;
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
    ///
    /// # Side effects
    ///
    /// Drops every tracked dialog and bumps the generation counter. The
    /// lifetime idle-eviction counter is NOT reset.
    pub fn clear(&mut self) {
        self.generation += 1;
        self.dialogs.clear();
    }

    /// Retain only dialogs for which `predicate` returns `true`.
    ///
    /// # Arguments
    ///
    /// * `predicate` — Keep-function evaluated once per dialog.
    ///
    /// # Side effects
    ///
    /// Removes non-matching dialogs (preserving insertion order of the
    /// rest) and bumps the generation counter, even when nothing is
    /// removed.
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&SipDialog) -> bool,
    {
        self.generation += 1;
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
    ///
    /// # Arguments
    ///
    /// * `call_id` — Call-ID of the source dialog to correlate from.
    ///
    /// # Returns
    ///
    /// Borrowed correlation results, one per matching dialog; empty when
    /// the Call-ID is unknown or nothing correlates.
    pub fn find_correlated_scored(&self, call_id: &str) -> Vec<CorrelationResult<'_>> {
        let dialog = match self.get(call_id) {
            Some(d) => d,
            None => return Vec::new(),
        };

        // Strategy 1 data: correlation-header values from the source dialog,
        // across every configured xcid header name. A set gives O(1)
        // membership per candidate instead of a linear scan.
        let x_call_ids: std::collections::HashSet<&str> = dialog
            .messages
            .iter()
            .flat_map(|m| self.xcid_headers.iter().filter_map(move |h| m.header(h)))
            .collect();

        // Strategy 0 data: every RFC 7989 Session-ID the source dialog carried.
        // Parsed once here rather than per candidate, and kept as a list
        // because a dialog can legitimately show the pair converging — `nil`
        // on the first INVITE, then both halves once the far end answers.
        let src_session_ids: Vec<crate::sip::session_id::SessionId> = dialog
            .messages
            .iter()
            .filter_map(|m| m.header("Session-ID"))
            .filter_map(crate::sip::session_id::SessionId::parse)
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

            // Strategy 0: RFC 7989 Session-ID (score=100). Checked first
            // because it is the only strategy that survives a B2BUA, so where
            // it applies it is the answer and the rest are noise.
            //
            // `same_session_as` is set intersection, NOT string equality: the
            // two halves swap perspective across the SBC, so the header VALUES
            // differ on either side of it while describing one call.
            if !src_session_ids.is_empty() {
                let session_match = candidate
                    .messages
                    .iter()
                    .filter_map(|m| m.header("Session-ID"))
                    .filter_map(crate::sip::session_id::SessionId::parse)
                    .any(|cand| src_session_ids.iter().any(|src| src.same_session_as(&cand)));
                if session_match {
                    results.push(CorrelationResult {
                        dialog: candidate,
                        score: 100,
                        reason: CorrelationReason::SessionId,
                    });
                    continue;
                }
            }

            // Strategy 1: correlation-header match (score=100)
            let xcid_match = x_call_ids.contains(candidate.call_id.as_str())
                || candidate.messages.iter().any(|m| {
                    self.xcid_headers
                        .iter()
                        .any(|h| m.header(h).is_some_and(|v| v == call_id))
                });

            if xcid_match {
                results.push(CorrelationResult {
                    dialog: candidate,
                    score: 100,
                    reason: CorrelationReason::XCallId,
                });
                continue;
            }

            // Strategy 2: Via branch overlap (score=80). Scan the candidate's
            // INVITE branches directly, short-circuiting on the first hit —
            // no per-candidate Vec allocation.
            if !src_branches.is_empty() {
                let branch_overlap = candidate
                    .messages
                    .iter()
                    .filter(|m| m.is_request && m.method.as_ref() == Some(&SipMethod::Invite))
                    .flat_map(|m| m.via_headers())
                    .filter_map(|v| extract_via_branch(v))
                    .any(|b| src_branches.contains(b));

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
        results.sort_by_key(|r| std::cmp::Reverse(r.score));
        results
    }

    /// Find dialogs correlated to the given Call-ID via X-Call-ID headers,
    /// Via branch overlap, or timing heuristics.
    ///
    /// Returns every correlated dialog, regardless of score. All three
    /// correlation strategies emit a score of at least 50 (X-Call-ID=100,
    /// Via-branch=80, timing=50), so there is no sub-threshold tier to
    /// discard here; empty when the Call-ID is unknown or nothing correlates.
    pub fn find_correlated(&self, call_id: &str) -> Vec<&SipDialog> {
        self.find_correlated_scored(call_id)
            .into_iter()
            .map(|r| r.dialog)
            .collect()
    }

    /// Evict the oldest dialogs (front of insertion order) in a batch.
    ///
    /// `shift_remove_index(0)` is O(n) — under cap pressure (a unique
    /// Call-ID flood) that made EVERY insert pay a full-store shift,
    /// a CPU-DoS ceiling of a few thousand inserts/sec at the 10k cap.
    /// Draining ~1% of capacity at once pays one O(n) shift per batch:
    /// amortized O(100) per insert, insertion-order iteration preserved
    /// (the TUI call list's default sort is store order). The store may
    /// briefly sit up to cap/100 below the cap; the cap remains a hard
    /// upper bound.
    ///
    /// # Side effects
    ///
    /// Removes up to `max_dialogs / 100` (at least 1) dialogs from the
    /// front of the map, dropping their messages, and adds them to the
    /// lifetime `capacity_dialogs_evicted` counter. Callers bump the
    /// generation counter; this helper does not.
    ///
    /// The counting lives HERE rather than at the call sites so every path
    /// that rotates is instrumented by construction. It previously lived in
    /// the `--no-rotate` branch of `process_message` alone, which meant the
    /// default policy — this one — discarded the oldest calls and counted
    /// nothing at all.
    fn evict_oldest(&mut self) {
        let batch = (self.max_dialogs / 100).max(1).min(self.dialogs.len());
        self.dialogs.drain(0..batch);
        self.capacity_dialogs_evicted += batch as u64;
    }
}

/// Identity of ONE captured observation of a SIP message.
///
/// Deliberately the whole capture event — when it was seen, between which two
/// endpoints, and the exact bytes — and *not* the SIP-level identity
/// (Call-ID + CSeq + branch). The distinction is the whole point of
/// [`absorb_messages`]: when a message crosses a proxy the capture records it
/// twice, once per host pair, and the single-threaded path stores both. Those
/// two rows are the same *message* but different *observations*, and collapsing
/// them would delete exactly the leg this merge exists to recover.
///
/// Cloning is cheap: `Bytes` is a refcounted view of the packet buffer, so the
/// key never copies message bytes.
#[derive(PartialEq, Eq, Hash)]
struct CapturedObservation {
    /// Capture timestamp of the packet that carried the message.
    timestamp: chrono::DateTime<chrono::Utc>,
    /// Network-layer source address.
    src_addr: std::net::IpAddr,
    /// Transport source port.
    src_port: u16,
    /// Network-layer destination address.
    dst_addr: std::net::IpAddr,
    /// Transport destination port.
    dst_port: u16,
    /// Raw message bytes exactly as captured.
    raw: bytes::Bytes,
}

impl CapturedObservation {
    /// The observation identity of `msg`.
    fn of(msg: &SipMessage) -> Self {
        Self {
            timestamp: msg.timestamp,
            src_addr: msg.src_addr,
            src_port: msg.src_port,
            dst_addr: msg.dst_addr,
            dst_port: msg.dst_port,
            raw: msg.raw.clone(),
        }
    }
}

/// Append another fragment's messages to `base`'s, in capture-timestamp order.
///
/// # Why concatenate
///
/// The two fragments are one call seen on two host pairs, so their message
/// lists are disjoint halves of the same reconstruction. Keeping one and
/// dropping the other loses real signalling.
///
/// # What counts as a duplicate
///
/// Only a message `base` has already observed *identically* — same timestamp,
/// same 5-tuple, same bytes (see [`CapturedObservation`]). A proxy's forwarded
/// copy differs in source and destination address and so is kept, which is what
/// the single-threaded path does with the same packets.
///
/// Two properties make that narrow rule the right one:
///
/// * `crate::parallel` routes each packet to exactly ONE worker, so on the
///   `--cores` path no observation can appear in two fragments and the filter
///   never fires. It cannot therefore change `--cores` output — it is a
///   correctness guard for any caller that merges overlapping stores.
/// * Only `incoming` is filtered, never `base`'s existing messages. A capture
///   can legitimately contain the identical packet twice (a SPAN port mirroring
///   both directions), the single-threaded path stores both, and both land on
///   the same worker — so they must survive here too.
///
/// # Side effects
///
/// Extends, sorts and truncates `base.messages` to `MAX_MESSAGES_PER_DIALOG`.
/// The truncation keeps the EARLIEST messages, matching `process_message`,
/// which pushes until the cap is reached and then drops what arrives after.
fn absorb_messages(base: &mut SipDialog, incoming: Vec<SipMessage>) {
    if incoming.is_empty() {
        return;
    }
    let fresh: Vec<SipMessage> = {
        let seen: std::collections::HashSet<CapturedObservation> =
            base.messages.iter().map(CapturedObservation::of).collect();
        incoming
            .into_iter()
            .filter(|m| !seen.contains(&CapturedObservation::of(m)))
            .collect()
    };
    base.messages.extend(fresh);
    // Stable, so equal timestamps keep base-then-incoming order.
    base.messages.sort_by_key(|m| m.timestamp);
    base.messages
        .truncate(MAX_MESSAGES_PER_DIALOG.load(std::sync::atomic::Ordering::Relaxed));
}

/// Re-derive the per-message state of a merged dialog by replaying its whole
/// message list, the way `process_message` derived it one message at a time.
///
/// Everything here is a pure function of the ordered message list, so after a
/// merge it is stale by definition: the base fragment's state reflects only the
/// base fragment's messages. The dialog `state` is the visible one — a worker
/// that saw the INVITE and the ringing reports `Ringing` while the worker
/// holding the 200 OK and the BYE saw the call complete — but the SDP timeline
/// and the REFER/SIPREC fields have the same defect, and a merged dialog whose
/// messages show an SDP exchange that its timeline does not is worse than
/// either fragment alone.
///
/// State replay starts from the base fragment's current state rather than from
/// scratch (`SipDialog::state` is private to the dialog module and only the
/// state machine may write it). That is sound because the base is the fragment
/// that saw the call FIRST, so it is the least advanced, and because every
/// transition that could regress a call is guarded on the pre-answer states —
/// a late 180 cannot un-answer a call, and a re-applied message is idempotent.
///
/// # Side effects
///
/// Rewrites `dialog.state`, `dialog.to_tag`, `dialog.sdp_timeline`,
/// `dialog.refer_to` and `dialog.siprec_metadata` from `dialog.messages`.
fn replay_message_derived_state(dialog: &mut SipDialog) {
    let messages = std::mem::take(&mut dialog.messages);
    dialog.sdp_timeline.clear();
    dialog.refer_to = None;
    dialog.siprec_metadata = None;
    for msg in &messages {
        update_state(dialog, msg);
        track_sdp(&mut dialog.sdp_timeline, msg);
        if msg.is_request && msg.method.as_ref() == Some(&SipMethod::Refer) {
            if let Some(refer_to) = msg.header("Refer-To") {
                dialog.refer_to = Some(refer_to.to_string());
            }
            track_transfer(&mut dialog.sdp_timeline, msg);
        }
        if let Some(ct) = msg.content_type()
            && ct.contains("multipart/mixed")
            && let Ok(metadata) = crate::sip::siprec::parse_siprec_body(ct, &msg.body)
        {
            dialog.siprec_metadata = Some(metadata);
        }
    }
    dialog.messages = messages;
}

/// Fold the other fragment's COUNTED and MEASURED state into the `winner` on a
/// same-Call-ID merge collision — the part that cannot simply be replayed.
///
/// The message-derived fields are rebuilt from the concatenated message list by
/// [`replay_message_derived_state`]; what is left here is state a fragment
/// accumulated but did not store: retransmit tallies whose messages were capped
/// away, seen-CSeq identities that survive compaction, and milestones recorded
/// on first sighting (`update_timing` writes each one only while it is `None`,
/// so replaying cannot correct an out-of-order first observation — taking the
/// earlier of the two can).
///
/// `winner` names the base fragment, not a contest result: the two copies are
/// disjoint host-pair observations of the same call, so their state is
/// combined, never one dropped:
///
/// * **seen-CSeq set** — set union (deduped by the `HashSet`), bounded by
///   [`MAX_SEEN_CSEQ_PER_DIALOG`](crate::sip::dialog::MAX_SEEN_CSEQ_PER_DIALOG)
///   so the union cannot exceed the per-dialog cap.
/// * **retransmit counts** — summed per `"CSeq METHOD"` key: each worker
///   counted retransmissions on its own leg, so the totals add.
/// * **timing milestones** (`invite_sent`, `trying_at`, `ringing_at`,
///   `answered_at`, `bye_sent`, `bye_answered`, `refer_sent_at`,
///   `transfer_completed_at`) — earliest non-`None` wins: each records the
///   *first* time that event was seen, so the true first is the earlier of
///   the two observations.
/// * **`invite_cseq`** — keep the base's if set, otherwise adopt the other's
///   (it pins responses to the initial INVITE; either copy's value identifies
///   the same transaction).
/// * **`created_at`** — earliest (dialog began at the earlier sighting);
///   **`updated_at`** — latest (most recent activity across both legs).
fn union_dialog_state(winner: &mut SipDialog, loser: &SipDialog) {
    // seen-CSeq set union, respecting the per-dialog cap.
    for key in &loser.seen_cseq {
        if winner.seen_cseq.contains(key) {
            continue;
        }
        if winner.seen_cseq.len() >= crate::sip::dialog::MAX_SEEN_CSEQ_PER_DIALOG {
            break;
        }
        winner.seen_cseq.insert(key.clone());
    }

    // Retransmit counts: sum per transaction key.
    for (key, count) in &loser.timing.retransmit_counts {
        *winner
            .timing
            .retransmit_counts
            .entry(key.clone())
            .or_insert(0) += count;
    }

    // Timing milestones: the earliest observation of each event survives.
    fn take_earliest(
        dst: &mut Option<chrono::DateTime<chrono::Utc>>,
        src: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        *dst = match (*dst, src) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    take_earliest(&mut winner.timing.invite_sent, loser.timing.invite_sent);
    take_earliest(&mut winner.timing.trying_at, loser.timing.trying_at);
    take_earliest(&mut winner.timing.ringing_at, loser.timing.ringing_at);
    take_earliest(&mut winner.timing.answered_at, loser.timing.answered_at);
    take_earliest(&mut winner.timing.bye_sent, loser.timing.bye_sent);
    take_earliest(&mut winner.timing.bye_answered, loser.timing.bye_answered);
    take_earliest(&mut winner.timing.refer_sent_at, loser.timing.refer_sent_at);
    take_earliest(
        &mut winner.timing.transfer_completed_at,
        loser.timing.transfer_completed_at,
    );
    winner.timing.invite_cseq = winner.timing.invite_cseq.or(loser.timing.invite_cseq);

    // Dialog lifetime bounds: earliest start, latest activity.
    winner.created_at = winner.created_at.min(loser.created_at);
    winner.updated_at = winner.updated_at.max(loser.updated_at);
}

/// Extract the `branch=` parameter value from a Via header value
/// `via_header`; returns `None` when no `branch=` parameter is present.
fn extract_via_branch(via_header: &str) -> Option<&str> {
    via_header
        .split(';')
        .find_map(|param| param.trim().strip_prefix("branch="))
}

/// Build a CSeq key string (`"<num> <method>"`) from a SIP message, used
/// as the map key for per-transaction retransmit counting in
/// `DialogTiming::retransmit_counts`.
///
/// Retransmission *detection* itself is keyed on `seen_cseq_key` in the
/// dialog module, which additionally includes the direction, status code,
/// and top-Via branch.
///
/// # Returns
///
/// The key string, or `None` when the message has no parseable CSeq
/// header.
fn cseq_key(msg: &SipMessage) -> Option<String> {
    let (num, method) = msg.cseq()?;
    Some(format!("{num} {method}"))
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for `DialogStore`: dialog creation and lookup, branch-aware
/// retransmission detection, capacity eviction (single and batched), idle
/// compaction, multi-core merge, correlation scoring, REFER/SIPREC
/// tracking, and the generation counter.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed 127.0.0.1 address used as both source and destination of
    /// every test message.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) so tests are
    /// deterministic.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// An IPv4 `IpAddr` from four octets, for building proxy legs.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Re-observe `msg` on a different host pair at `ts` — the second copy a
    /// capture takes of one message when it crosses a proxy.
    ///
    /// The bytes are reused verbatim. A real proxy also rewrites Via and
    /// Max-Forwards, so identical bytes is the *harder* case: only the
    /// capture 5-tuple distinguishes the two observations, which is exactly
    /// the distinction the merge de-duplication must respect.
    fn observed_on_leg(
        msg: &SipMessage,
        src: IpAddr,
        dst: IpAddr,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        parse_sip(&msg.raw, ts, src, dst, 5060, 5060, TransportProto::Udp)
            .expect("re-parse on another leg")
    }

    // Multi-core (--cores): each worker reconstructs the calls sharded to it; the
    // merge unions distinct Call-IDs and CONCATENATES the message lists of a
    // same-Call-ID collision, because a proxied call is sharded across workers.
    /// Merging two stores unions distinct Call-IDs; a same-Call-ID collision
    /// concatenates both fragments' messages in timestamp order.
    #[test]
    fn merge_unions_dialogs_and_concatenates_colliding_message_lists() {
        let t0 = base_ts();
        let mut a = DialogStore::new(1000, true);
        a.process_message(make_invite_msg("call-a@h", t0));
        let mut b = DialogStore::new(1000, true);
        b.process_message(make_invite_msg("call-b@h", t0));
        a.merge(b);
        assert_eq!(a.len(), 2, "distinct Call-IDs unioned");
        assert!(a.get("call-a@h").is_some() && a.get("call-b@h").is_some());

        // Collision: the other fragment's messages are ADDED, not weighed
        // against the base's and thrown away.
        let mut c = DialogStore::new(1000, true);
        c.process_message(make_200_ok("call-a@h", t0 + TimeDelta::seconds(1)));
        c.process_message(make_bye_msg("call-a@h", t0 + TimeDelta::seconds(2)));
        a.merge(c);
        assert_eq!(a.len(), 2, "collision is not double-counted");
        let d = a.get("call-a@h").expect("collided dialog");
        assert_eq!(
            d.messages.len(),
            3,
            "both fragments' messages survive the merge (1 + 2), rather than \
             the shorter list being discarded"
        );
        let ts: Vec<_> = d.messages.iter().map(|m| m.timestamp).collect();
        assert!(
            ts.windows(2).all(|w| w[0] <= w[1]),
            "merged messages are ordered by capture timestamp: {ts:?}"
        );
    }

    /// A proxied call is sharded across workers by host pair, and the merge
    /// must reconstruct it from EVERY leg.
    ///
    /// `src/parallel.rs` shards on the direction-independent host pair, which
    /// keeps an RTP stream whole but says nothing about SIP: a call through a
    /// proxy is captured on two host pairs and lands on two workers. The merge
    /// used to keep whichever fragment had more messages, so the other leg's
    /// signalling was discarded — on a 100 MB carrier capture that halved the
    /// message count of 1173 of 2311 dialogs, with the Call-ID set unchanged.
    #[test]
    fn merge_reconstructs_a_proxied_call_from_both_legs() {
        let (t0, t1) = (base_ts(), base_ts() + TimeDelta::seconds(1));
        let (uac, proxy, uas) = (ip(10, 33, 6, 100), ip(10, 33, 6, 101), ip(10, 33, 6, 102));

        // Leg 1 (uac ↔ proxy): the INVITE and its 200 OK as the capture saw
        // them on the access side.
        let invite = make_invite_msg("proxied@h", t0);
        let ok = make_200_ok("proxied@h", t1);
        let mut near = DialogStore::new(1000, true);
        near.process_message(observed_on_leg(&invite, uac, proxy, t0));
        near.process_message(observed_on_leg(&ok, proxy, uac, t1));

        // Leg 2 (proxy ↔ uas): the same two messages forwarded — a different
        // host pair, so a different worker.
        let mut far = DialogStore::new(1000, true);
        far.process_message(observed_on_leg(&invite, proxy, uas, t0));
        far.process_message(observed_on_leg(&ok, uas, proxy, t1));

        near.merge(far);
        assert_eq!(near.len(), 1, "one Call-ID, one dialog");
        assert_eq!(
            near.get("proxied@h").expect("dialog").messages.len(),
            4,
            "all four captured observations survive: a proxy leg's copy of a \
             message is a distinct observation, not a duplicate to discard"
        );
    }

    /// The same captured observation appearing in both fragments is folded to
    /// one — the guard against merging overlapping inputs.
    ///
    /// Sharding sends each packet to exactly one worker, so this cannot happen
    /// on the `--cores` path; it is what makes the concatenation safe for any
    /// other caller. The identity is the whole capture observation (timestamp,
    /// both addresses, both ports and the raw bytes), which is why the proxy
    /// copies in `merge_reconstructs_a_proxied_call_from_both_legs` survive
    /// while a byte-for-byte re-merge of the same store adds nothing.
    #[test]
    fn merge_folds_an_identical_observation_but_keeps_a_proxy_copy() {
        let t0 = base_ts();
        let (uac, proxy) = (ip(10, 33, 6, 100), ip(10, 33, 6, 101));
        let invite = make_invite_msg("dup@h", t0);

        let mut a = DialogStore::new(1000, true);
        a.process_message(observed_on_leg(&invite, uac, proxy, t0));

        // Same bytes, same timestamp, same 5-tuple: the same observation.
        let mut same = DialogStore::new(1000, true);
        same.process_message(observed_on_leg(&invite, uac, proxy, t0));
        a.merge(same);
        assert_eq!(
            a.get("dup@h").expect("dialog").messages.len(),
            1,
            "an identical observation is not stored twice"
        );

        // Same bytes and timestamp, different host pair: a second observation.
        let mut other_leg = DialogStore::new(1000, true);
        other_leg.process_message(observed_on_leg(&invite, proxy, ip(10, 33, 6, 102), t0));
        a.merge(other_leg);
        assert_eq!(
            a.get("dup@h").expect("dialog").messages.len(),
            2,
            "the same message seen on another leg is a distinct observation"
        );
    }

    /// The merged dialog's STATE is recomputed over the merged message list,
    /// not inherited from whichever fragment happened to be the base.
    ///
    /// The base here is the fragment that saw the call first AND holds more
    /// messages — the old merge kept it outright, reporting a call that was
    /// still ringing when the other worker had watched it answer and hang up.
    /// Measured on the carrier capture: 20 of 2311 dialogs reported the wrong
    /// state for exactly this reason.
    #[test]
    fn merge_recomputes_state_over_the_merged_messages() {
        let t0 = base_ts();
        let (uac, proxy, uas) = (ip(10, 33, 6, 100), ip(10, 33, 6, 101), ip(10, 33, 6, 102));

        // Base leg: INVITE + two retransmissions. Three messages, still Trying.
        let invite = make_invite_msg("state@h", t0);
        let mut near = DialogStore::new(1000, true);
        for i in 0..3 {
            let ts = t0 + TimeDelta::milliseconds(i * 10);
            near.process_message(observed_on_leg(&invite, uac, proxy, ts));
        }
        assert_eq!(
            near.get("state@h").expect("dialog").state(),
            &DialogState::Trying
        );
        assert_eq!(near.get("state@h").expect("dialog").messages.len(), 3);

        // Other leg: the answer and the hang-up. Fewer messages, later start.
        let mut far = DialogStore::new(1000, true);
        far.process_message(observed_on_leg(
            &make_200_ok("state@h", t0),
            uas,
            proxy,
            t0 + TimeDelta::seconds(1),
        ));
        far.process_message(observed_on_leg(
            &make_bye_msg("state@h", t0),
            uac,
            proxy,
            t0 + TimeDelta::seconds(2),
        ));

        near.merge(far);
        let d = near.get("state@h").expect("dialog");
        assert_eq!(d.messages.len(), 5, "every leg's messages are kept");
        assert_eq!(
            d.state(),
            &DialogState::Completed,
            "the state machine is re-run over the merged messages, so the \
             answer and BYE the other worker saw take effect"
        );
    }

    /// `merge` must respect the store's capacity, in both disposal modes.
    ///
    /// Each `--cores` worker enforces `--limit` on its own shard and the merge
    /// target used to accept every survivor unconditionally, so `--cores N`
    /// silently permitted up to N × the cap. The limit an operator sets to
    /// bound memory must not be multiplied by the core count.
    #[test]
    fn merge_enforces_capacity_in_both_disposal_modes() {
        let t0 = base_ts();
        // Drop-oldest (the default): the cap holds and the newest survive.
        let mut rotating = DialogStore::new(2, true);
        rotating.process_message(make_invite_msg("keep-1", t0));
        rotating.process_message(make_invite_msg("keep-2", t0));
        let mut incoming = DialogStore::new(2, true);
        incoming.process_message(make_invite_msg("new-1", t0));
        incoming.process_message(make_invite_msg("new-2", t0));
        rotating.merge(incoming);
        assert!(
            rotating.len() <= 2,
            "merge must not exceed the store capacity: got {}",
            rotating.len()
        );
        assert!(
            rotating.total_capacity_dialogs_evicted() > 0,
            "the dialogs the merge displaced are counted as drop-oldest evictions"
        );

        // Reject-newest (--no-rotate): the merged-in Call-ID is refused.
        let mut fixed = DialogStore::new(2, false);
        fixed.process_message(make_invite_msg("first-1", t0));
        fixed.process_message(make_invite_msg("first-2", t0));
        let mut late = DialogStore::new(2, false);
        late.process_message(make_invite_msg("late-1", t0));
        fixed.merge(late);
        assert_eq!(fixed.len(), 2, "a full no-rotate store stays at capacity");
        assert!(
            fixed.get("late-1").is_none(),
            "the newest Call-ID is the one rejected"
        );
        assert_eq!(
            fixed.total_capacity_dialogs_dropped(),
            1,
            "the rejected merge insert is counted"
        );
    }

    /// The DEFAULT disposal path — drop-oldest rotation — counts what it
    /// discards.
    ///
    /// `capacity_dialogs_dropped` was incremented only in the `--no-rotate`
    /// branch, so the policy nobody uses had a counter and the policy everybody
    /// uses had none: the store discarded the earliest calls and reported
    /// nothing. `evict_oldest` drains a batch of `max_dialogs / 100` (at least
    /// one), so the count is of dialogs actually discarded, not of inserts.
    #[test]
    fn drop_oldest_evictions_are_counted_separately_from_rejections() {
        let t0 = base_ts();
        let mut store = DialogStore::new(3, true);
        for i in 0..3 {
            store.process_message(make_invite_msg(&format!("rot-{i}"), t0));
        }
        assert_eq!(
            store.total_capacity_dialogs_evicted(),
            0,
            "nothing evicted yet"
        );

        for i in 3..6 {
            store.process_message(make_invite_msg(&format!("rot-{i}"), t0));
        }
        assert!(store.len() <= 3, "the cap is a hard upper bound");
        assert_eq!(
            store.total_capacity_dialogs_evicted(),
            3,
            "each of the three oldest dialogs discarded to make room is counted"
        );
        assert_eq!(
            store.total_capacity_dialogs_dropped(),
            0,
            "drop-oldest is not a rejection; the two counters stay distinct"
        );

        // The counter accumulates across a merge, like its siblings.
        let mut other = DialogStore::new(1, true);
        other.process_message(make_invite_msg("o-1", t0));
        other.process_message(make_invite_msg("o-2", t0));
        assert_eq!(other.total_capacity_dialogs_evicted(), 1);
        let before = store.total_capacity_dialogs_evicted();
        store.merge(other);
        assert!(
            store.total_capacity_dialogs_evicted() > before,
            "merge folds in the other store's eviction count"
        );
    }

    /// A same-Call-ID merge collision unions the losing reconstruction's
    /// state into the winner instead of discarding it: seen-CSeq set union,
    /// retransmit counts summed, timing milestones taken as the earliest
    /// observation, `created_at` earliest / `updated_at` latest.
    #[test]
    fn merge_unions_collision_state_not_just_messages() {
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);
        let t5 = t0 + TimeDelta::seconds(5);
        let t6 = t0 + TimeDelta::seconds(6);

        // Winner: more messages (INVITE + 3 retransmissions), no answer/BYE.
        let mut a = DialogStore::new(1000, true);
        a.process_message(make_invite_msg("call-x@h", t0));
        a.process_message(make_invite_msg("call-x@h", t0)); // retransmit
        a.process_message(make_invite_msg("call-x@h", t0)); // retransmit
        a.process_message(make_invite_msg("call-x@h", t0)); // retransmit
        assert_eq!(a.get("call-x@h").unwrap().timing.total_retransmits(), 3);

        // Loser: fewer messages but distinct state — later INVITE start, one
        // retransmit, an answer and a BYE the winner never saw.
        let mut b = DialogStore::new(1000, true);
        b.process_message(make_invite_msg("call-x@h", t1));
        b.process_message(make_invite_msg("call-x@h", t1)); // retransmit
        b.process_message(make_200_ok("call-x@h", t5));
        b.process_message(make_bye_msg("call-x@h", t6));
        assert_eq!(b.get("call-x@h").unwrap().timing.total_retransmits(), 1);

        a.merge(b);
        assert_eq!(a.len(), 1, "same Call-ID stays a single dialog");
        let d = a.get("call-x@h").unwrap();

        // Retransmit counts are summed across both reconstructions.
        assert_eq!(
            d.timing.total_retransmits(),
            4,
            "retransmit counts unioned (summed), not dropped"
        );
        // Timing milestones: earliest non-None wins.
        assert_eq!(
            d.timing.invite_sent,
            Some(t0),
            "earliest INVITE timestamp survives"
        );
        assert_eq!(
            d.timing.answered_at,
            Some(t5),
            "answer milestone adopted from the losing reconstruction"
        );
        assert_eq!(
            d.timing.bye_sent,
            Some(t6),
            "BYE milestone adopted from the losing reconstruction"
        );
        // created_at earliest, updated_at latest.
        assert_eq!(d.created_at, t0, "created_at is the earliest of the two");
        assert_eq!(d.updated_at, t6, "updated_at is the latest of the two");
        // seen-CSeq set union: the loser's 200-OK and BYE identities are folded in.
        assert!(
            d.seen_cseq.iter().any(|k| k.contains("2 BYE")),
            "loser's BYE seen-CSeq identity unioned in"
        );
        assert!(
            d.seen_cseq.iter().any(|k| k.starts_with("r200")),
            "loser's 200-OK seen-CSeq identity unioned in"
        );
    }

    /// Build and parse a minimal INVITE (CSeq 1) for `call_id` at `ts`.
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

    /// In no-rotate mode, new Call-IDs arriving at capacity are dropped;
    /// each drop is counted (the observability sibling of idle eviction).
    /// Updates to existing dialogs are not drops, and the counter is
    /// accumulated across a merge.
    #[test]
    fn capacity_drops_counted_in_no_rotate_mode() {
        let mut store = DialogStore::new(2, false);
        store.process_message(make_invite_msg("cap-1", base_ts()));
        store.process_message(make_invite_msg("cap-2", base_ts()));
        assert_eq!(store.len(), 2);
        assert_eq!(store.total_capacity_dialogs_dropped(), 0);

        // New Call-IDs at capacity are dropped and counted.
        store.process_message(make_invite_msg("cap-3", base_ts()));
        store.process_message(make_invite_msg("cap-4", base_ts()));
        assert_eq!(store.len(), 2, "no-rotate store stays at cap");
        assert_eq!(
            store.total_capacity_dialogs_dropped(),
            2,
            "each dropped new Call-ID is counted"
        );

        // Updates to existing dialogs are not capacity drops.
        store.process_message(make_200_ok("cap-1", base_ts()));
        assert_eq!(store.total_capacity_dialogs_dropped(), 2);

        // Merge accumulates the counter, mirroring idle-eviction plumbing —
        // and enforces the cap itself, so the surviving Call-ID it tries to
        // bring in is rejected by the full store and counted as well.
        let mut other = DialogStore::new(1, false);
        other.process_message(make_invite_msg("m-1", base_ts()));
        other.process_message(make_invite_msg("m-2", base_ts())); // dropped
        assert_eq!(other.total_capacity_dialogs_dropped(), 1);
        store.merge(other);
        assert_eq!(store.len(), 2, "merge respects the capacity of its target");
        assert_eq!(
            store.total_capacity_dialogs_dropped(),
            4,
            "merge folds in the other store's capacity-drop count (2 + 1) and \
             counts the Call-ID its own capacity check rejected (+1)"
        );
    }

    // ── compact_idle: long-run memory bound for idle dialogs ─────────

    /// Build a dialog with `n` stored messages by feeding distinct CSeqs.
    fn store_with_messages(call_id: &str, n: usize) -> DialogStore {
        let mut store = DialogStore::new(100, false);
        store.process_message(make_invite_msg(call_id, base_ts()));
        for i in 2..=n {
            let raw = build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>",
                    &format!("Call-ID: {call_id}"),
                    &format!("CSeq: {i} INVITE"),
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
        }
        store
    }

    /// A timestamp just past the idle-compaction window after `base_ts`,
    /// so any dialog last updated at `base_ts` counts as idle.
    fn idle_now() -> DateTime<Utc> {
        base_ts() + IDLE_COMPACT_AFTER + TimeDelta::seconds(1)
    }

    /// An idle dialog over the keep limit is compacted to
    /// `KEEP_MESSAGES_PER_IDLE_DIALOG` messages.
    ///
    /// The fixture is 30 `INVITE`s and nothing else, so exactly one of them —
    /// the first, which opened the dialog — is load-bearing. It survives at
    /// index 0 and the remaining 19 slots go to the most recent messages, so
    /// the middle (CSeq 2..11) is what disappears. This assertion used to read
    /// `Some(11)`: that was "keep the last N" stated as a contract, and it is
    /// the contract that cost answered calls their `200 OK`.
    #[test]
    fn compact_idle_truncates_idle_dialog_to_keep_limit() {
        let n = KEEP_MESSAGES_PER_IDLE_DIALOG + 10;
        let mut store = store_with_messages("idle-1", n);
        assert_eq!(store.get("idle-1").unwrap().messages.len(), n);

        let stats = store.compact_idle(idle_now());
        assert_eq!(stats.dialogs_compacted, 1);
        assert_eq!(stats.messages_evicted, 10);

        let d = store.get("idle-1").unwrap();
        assert_eq!(d.messages.len(), KEEP_MESSAGES_PER_IDLE_DIALOG);
        assert_eq!(
            d.messages[0].cseq().map(|(seq, _)| seq),
            Some(1),
            "the request that opened the dialog survives wherever it sits"
        );
        assert_eq!(
            d.messages[1].cseq().map(|(seq, _)| seq),
            Some(12),
            "the middle is what gets compacted"
        );
        assert_eq!(
            d.messages.last().unwrap().cseq().map(|(seq, _)| seq),
            Some(n as u32)
        );
    }

    /// A dialog updated within the idle window is not compacted at all.
    #[test]
    fn compact_idle_leaves_active_dialogs_alone() {
        let n = KEEP_MESSAGES_PER_IDLE_DIALOG + 10;
        let mut store = store_with_messages("active-1", n);
        // "now" is within the idle window — dialog is still active.
        let stats = store.compact_idle(base_ts() + TimeDelta::seconds(30));
        assert_eq!(stats.dialogs_compacted, 0);
        assert_eq!(stats.messages_evicted, 0);
        assert_eq!(store.get("active-1").unwrap().messages.len(), n);
    }

    /// A second compaction sweep over an already-compacted dialog is a
    /// no-op (stats stay zero).
    #[test]
    fn compact_idle_is_idempotent() {
        let mut store = store_with_messages("idle-2", KEEP_MESSAGES_PER_IDLE_DIALOG + 5);
        let first = store.compact_idle(idle_now());
        assert_eq!(first.messages_evicted, 5);
        let second = store.compact_idle(idle_now());
        assert_eq!(second.dialogs_compacted, 0, "second pass must be a no-op");
        assert_eq!(second.messages_evicted, 0);
    }

    /// An idle dialog already under the keep limit evicts nothing and is
    /// not counted as compacted.
    #[test]
    fn compact_idle_skips_small_idle_dialogs() {
        // Idle but already under the keep limit: nothing to evict, and it
        // must not be counted as compacted.
        let mut store = store_with_messages("small-idle", 3);
        let stats = store.compact_idle(idle_now());
        assert_eq!(stats.dialogs_compacted, 0);
        assert_eq!(stats.messages_evicted, 0);
        assert_eq!(store.get("small-idle").unwrap().messages.len(), 3);
    }

    /// Retransmission detection must survive message compaction: the old
    /// implementation scanned the STORED messages, so once compact_idle
    /// dropped a message, a retransmission of it was misclassified as new
    /// (wrong flag, state churn, memory regrowth). Detection is keyed on
    /// a per-dialog seen-CSeq set, independent of message retention.
    #[test]
    fn retransmission_detected_after_compaction() {
        let n = KEEP_MESSAGES_PER_IDLE_DIALOG + 10;
        let mut store = store_with_messages("retx-c", n);
        store.compact_idle(idle_now());
        // CSeq 1 (the initial INVITE) was compacted away; retransmit it.
        let retx = make_invite_msg("retx-c", idle_now());
        store.process_message(retx);
        let d = store.get("retx-c").unwrap();
        let last = d.messages.last().unwrap();
        assert!(
            last.is_retransmission,
            "retransmission of a compacted-away message must still be flagged"
        );
    }

    /// A dialog at its per-dialog message cap that keeps receiving
    /// retransmissions is still ACTIVE: even a dropped retransmission
    /// must advance `updated_at`, or compact_idle would wrongly treat a
    /// retransmission-flooded dialog as idle and compact it.
    #[test]
    fn capped_retransmission_flood_still_counts_as_active() {
        let cap = DEFAULT_MAX_MESSAGES_PER_DIALOG;
        let mut store = store_with_messages("retx-cap", cap);
        assert_eq!(
            store.get("retx-cap").unwrap().messages.len(),
            cap,
            "dialog must start at the message cap"
        );

        // Retransmit the initial INVITE at the idle cutoff; at the cap
        // the message itself is dropped, but it is still traffic.
        let retx_ts = base_ts() + IDLE_COMPACT_AFTER;
        store.process_message(make_invite_msg("retx-cap", retx_ts));
        let d = store.get("retx-cap").unwrap();
        assert_eq!(d.messages.len(), cap, "capped retransmission is not stored");
        assert_eq!(
            d.updated_at, retx_ts,
            "a dropped retransmission must still advance updated_at"
        );

        // One second past the ORIGINAL traffic's idle cutoff: the dialog
        // saw a retransmission 1s ago, so it must not be compacted.
        let stats = store.compact_idle(idle_now());
        assert_eq!(
            stats.dialogs_compacted, 0,
            "retransmission-flooded dialog is not idle"
        );
        assert_eq!(store.get("retx-cap").unwrap().messages.len(), cap);
    }

    /// Evictions from compaction sweeps accumulate into the lifetime
    /// `total_idle_messages_evicted` counter.
    #[test]
    fn compact_idle_accumulates_lifetime_counter() {
        let mut store = store_with_messages("idle-3", KEEP_MESSAGES_PER_IDLE_DIALOG + 4);
        assert_eq!(store.total_idle_messages_evicted(), 0);
        store.compact_idle(idle_now());
        assert_eq!(store.total_idle_messages_evicted(), 4);
    }

    // ── compact_idle: the outcome survives ───────────────────────────

    /// A timestamp past the idle window measured from the dialog's OWN last
    /// message, so a fixture whose messages are spaced realistically still
    /// counts as idle. `idle_now` is measured from `base_ts` and would
    /// silently fail to make a spread-out fixture idle at all.
    fn idle_after(store: &DialogStore, call_id: &str) -> DateTime<Utc> {
        store.get(call_id).expect("dialog exists").updated_at
            + IDLE_COMPACT_AFTER
            + TimeDelta::seconds(1)
    }

    /// An in-dialog request (`OPTIONS`, CSeq `cseq`) for `call_id` at `ts` —
    /// the mid-call filler that pushes an answered call past the keep limit
    /// without carrying any outcome of its own.
    fn make_in_dialog_filler(call_id: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "OPTIONS sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq} OPTIONS"),
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
        .expect("should parse OPTIONS")
    }

    /// A `CANCEL` of the initial `INVITE` (CSeq 1) for `call_id` at `ts`.
    fn make_cancel_msg(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "CANCEL sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 CANCEL",
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
        .expect("should parse CANCEL")
    }

    /// An arbitrary response for `call_id` carrying `cseq` (e.g. `"1 INVITE"`).
    fn make_response(
        call_id: &str,
        code: u16,
        phrase: &str,
        cseq: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {code} {phrase}"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
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
        .expect("should parse response")
    }

    /// A call that was offered, answered, filled with `filler` mid-dialog
    /// requests, then hung up — the ordinary shape of a long call, and the
    /// one where "keep the last N" throws away the answer.
    fn store_with_answered_call(call_id: &str, filler: u32) -> DialogStore {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        store.process_message(make_invite_msg(call_id, t0));
        store.process_message(make_200_ok(call_id, t0 + TimeDelta::seconds(1)));
        for i in 0..filler {
            store.process_message(make_in_dialog_filler(
                call_id,
                10 + i,
                t0 + TimeDelta::seconds(2 + i64::from(i)),
            ));
        }
        store.process_message(make_bye_msg(
            call_id,
            t0 + TimeDelta::seconds(2 + i64::from(filler)),
        ));
        store
    }

    /// The defect: the `200 OK` arrives second, so "keep the last N" evicts it
    /// first and the call's OUTCOME disappears while the mid-call filler
    /// survives. A completed call then reports no final response — which is
    /// itself a diagnosis sipnab emits (`NoFinalResponse`, Timer C), so
    /// compaction manufactures the appearance of a specific fault.
    #[test]
    fn compact_idle_keeps_the_final_response() {
        let mut store = store_with_answered_call("answered-1", 40);
        assert_eq!(
            store.get("answered-1").unwrap().final_status_code(),
            Some(200),
            "precondition: the call answered"
        );

        let now = idle_after(&store, "answered-1");
        let stats = store.compact_idle(now);
        assert!(stats.messages_evicted > 0, "the dialog is over the limit");

        let d = store.get("answered-1").unwrap();
        assert_eq!(
            d.final_status_code(),
            Some(200),
            "a call that completed normally must not read as having no final response \
             after compaction"
        );
    }

    /// The request that opened the dialog is the other end of the ladder that
    /// position-based eviction always takes first.
    #[test]
    fn compact_idle_keeps_the_opening_request() {
        let mut store = store_with_answered_call("answered-2", 40);
        let now = idle_after(&store, "answered-2");
        store.compact_idle(now);
        let d = store.get("answered-2").unwrap();
        assert!(
            d.messages
                .iter()
                .any(|m| m.is_request && m.method == Some(SipMethod::Invite)),
            "the INVITE the call was made with must survive"
        );
    }

    /// A `BYE` says the call was torn down deliberately.
    #[test]
    fn compact_idle_keeps_the_teardown() {
        let mut store = store_with_answered_call("answered-3", 40);
        let now = idle_after(&store, "answered-3");
        store.compact_idle(now);
        let d = store.get("answered-3").unwrap();
        assert!(
            d.messages
                .iter()
                .any(|m| m.is_request && m.method == Some(SipMethod::Bye)),
            "the BYE must survive"
        );
    }

    /// A `CANCEL`ed call that then goes quiet: the `CANCEL` and the `487` both
    /// sit early in a long ladder, and both are the outcome. Unlike the `BYE`
    /// case they cannot survive by being recent, so this is the test that
    /// tells retention-by-meaning from retention-by-position.
    #[test]
    fn compact_idle_keeps_a_cancelled_calls_outcome() {
        let call_id = "cancelled-1";
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        store.process_message(make_invite_msg(call_id, t0));
        store.process_message(make_cancel_msg(call_id, t0 + TimeDelta::seconds(1)));
        store.process_message(make_response(
            call_id,
            487,
            "Request Terminated",
            "1 INVITE",
            t0 + TimeDelta::seconds(2),
        ));
        for i in 0..40 {
            store.process_message(make_in_dialog_filler(
                call_id,
                10 + i,
                t0 + TimeDelta::seconds(3 + i64::from(i)),
            ));
        }

        let now = idle_after(&store, call_id);
        store.compact_idle(now);
        let d = store.get(call_id).unwrap();
        assert_eq!(
            d.final_status_code(),
            Some(487),
            "a cancelled call must still report 487"
        );
        assert!(
            d.messages
                .iter()
                .any(|m| m.is_request && m.method == Some(SipMethod::Cancel)),
            "the CANCEL must survive"
        );
    }

    /// A call that FAILED must keep its failure: the `486` sits early in the
    /// ladder exactly as a `200` does.
    #[test]
    fn compact_idle_keeps_a_failure_code() {
        let call_id = "busy-1";
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        store.process_message(make_invite_msg(call_id, t0));
        store.process_message(make_response(
            call_id,
            486,
            "Busy Here",
            "1 INVITE",
            t0 + TimeDelta::seconds(1),
        ));
        for i in 0..40 {
            store.process_message(make_in_dialog_filler(
                call_id,
                10 + i,
                t0 + TimeDelta::seconds(2 + i64::from(i)),
            ));
        }
        let now = idle_after(&store, call_id);
        store.compact_idle(now);
        assert_eq!(store.get(call_id).unwrap().final_status_code(), Some(486));
    }

    /// Compaction is a memory bound, so retention must not exceed it: the
    /// surviving set is still capped at `KEEP_MESSAGES_PER_IDLE_DIALOG`.
    #[test]
    fn compact_idle_still_bounds_the_message_count() {
        let mut store = store_with_answered_call("answered-4", 200);
        let now = idle_after(&store, "answered-4");
        store.compact_idle(now);
        assert!(
            store.get("answered-4").unwrap().messages.len() <= KEEP_MESSAGES_PER_IDLE_DIALOG,
            "compaction must still bound memory"
        );
    }

    /// Messages are kept in capture order whatever the retention rule: an
    /// evidence index is only readable if the ladder still runs forwards.
    #[test]
    fn compact_idle_preserves_capture_order() {
        let mut store = store_with_answered_call("answered-5", 60);
        let now = idle_after(&store, "answered-5");
        store.compact_idle(now);
        let d = store.get("answered-5").unwrap();
        let ts: Vec<_> = d.messages.iter().map(|m| m.timestamp).collect();
        assert!(
            ts.windows(2).all(|w| w[0] <= w[1]),
            "retained messages must stay in capture order"
        );
    }

    /// Selective retention must still be idempotent — a second sweep over an
    /// already-compacted dialog evicts nothing, or a long-running capture
    /// would re-count the same loss on every sweep.
    #[test]
    fn compact_idle_selective_retention_is_idempotent() {
        let mut store = store_with_answered_call("answered-6", 60);
        let now = idle_after(&store, "answered-6");
        let first = store.compact_idle(now);
        assert!(first.messages_evicted > 0);
        let second = store.compact_idle(now);
        assert_eq!(second.dialogs_compacted, 0, "second pass must be a no-op");
        assert_eq!(second.messages_evicted, 0);
    }

    /// A budget smaller than the anchor set is still a hard bound, and a
    /// budget of zero does not panic. Neither is reachable from
    /// `KEEP_MESSAGES_PER_IDLE_DIALOG`, but both are reachable from the
    /// function signature.
    #[test]
    fn retained_indices_honours_a_budget_below_the_anchor_count() {
        let store = store_with_answered_call("degenerate-1", 40);
        let d = store.get("degenerate-1").expect("dialog exists");
        for budget in [0usize, 1, 2, 3] {
            let keep = retained_indices(&d.messages, &d.method, budget)
                .expect("the dialog is over every one of these budgets");
            assert!(
                keep.len() <= budget,
                "budget {budget} exceeded: kept {}",
                keep.len()
            );
            assert!(
                keep.windows(2).all(|w| w[0] < w[1]),
                "indices must stay ascending: {keep:?}"
            );
        }
    }

    /// The most recent messages are still the tie-break for everything that
    /// carries no outcome: the newest filler survives and the oldest does not.
    #[test]
    fn compact_idle_fills_the_remaining_budget_with_the_newest_messages() {
        let mut store = store_with_answered_call("answered-7", 60);
        let now = idle_after(&store, "answered-7");
        store.compact_idle(now);
        let d = store.get("answered-7").unwrap();
        let fillers: Vec<u32> = d
            .messages
            .iter()
            .filter(|m| m.method == Some(SipMethod::Options))
            .filter_map(|m| m.cseq().map(|(n, _)| n))
            .collect();
        assert!(!fillers.is_empty(), "some filler must survive");
        assert!(
            fillers.contains(&69),
            "the newest filler (CSeq 69) must survive: {fillers:?}"
        );
        assert!(
            !fillers.contains(&10),
            "the oldest filler (CSeq 10) must not: {fillers:?}"
        );
    }

    /// Build and parse a 200 OK to the initial INVITE (CSeq 1) for
    /// `call_id` at `ts`.
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

    /// Build and parse an in-dialog BYE (CSeq 2) for `call_id` at `ts`.
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

    /// INVITE followed by 200 OK yields one dialog in the InCall state
    /// with both messages stored.
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

    /// With rotate enabled, inserting past capacity evicts the oldest
    /// dialog to make room for the new one.
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

    /// At large caps, eviction is batched (cap/100 at a time) so cap
    /// pressure costs one O(n) drain per ~1% of capacity instead of an
    /// O(n) shift per insert. After the 1001st insert into a 1000-cap
    /// store, a batch of 10 was evicted and the new dialog added.
    #[test]
    fn large_cap_eviction_is_batched() {
        let mut store = DialogStore::new(1000, true);
        for i in 0..1001 {
            store.process_message(make_invite_msg(&format!("b-{i:04}@test"), base_ts()));
            assert!(store.len() <= 1000, "cap is a hard upper bound");
        }
        assert_eq!(
            store.len(),
            991,
            "1001st insert evicts a batch of cap/100 = 10, then inserts"
        );
        assert!(store.get("b-0000@test").is_none(), "oldest evicted");
        assert!(store.get("b-1000@test").is_some(), "newest present");
    }

    /// Batch eviction must preserve insertion-order iteration — the TUI
    /// call list's default sort IS store iteration order.
    #[test]
    fn batch_eviction_preserves_insertion_order() {
        let mut store = DialogStore::new(200, true);
        for i in 0..500 {
            store.process_message(make_invite_msg(&format!("o-{i:04}@test"), base_ts()));
        }
        let ids: Vec<&str> = store.iter().map(|d| d.call_id.as_str()).collect();
        assert!(!ids.is_empty());
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(
            ids, sorted,
            "iteration must remain in insertion order after batched evictions"
        );
        assert_eq!(*ids.last().unwrap(), "o-0499@test");
    }

    /// Without rotate, a new Call-ID arriving at capacity is silently
    /// dropped and existing dialogs are untouched.
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

    /// Build and parse an OPTIONS request with an explicit CSeq number and
    /// Via branch parameter (for transaction-identity tests).
    fn make_options_with_branch(
        call_id: &str,
        cseq: u32,
        branch: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            "OPTIONS sip:ping@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"),
                "From: <sip:mon@example.com>;tag=m1",
                "To: <sip:ping@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq} OPTIONS"),
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
        .expect("should parse OPTIONS")
    }

    /// Build and parse a 200 OK to OPTIONS with an explicit CSeq number
    /// and Via branch parameter.
    fn make_options_200_with_branch(
        call_id: &str,
        cseq: u32,
        branch: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"),
                "From: <sip:mon@example.com>;tag=m1",
                "To: <sip:ping@example.com>;tag=u1",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq} OPTIONS"),
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

    // RFC 3261 §17: transaction identity is the top Via branch. OPTIONS
    // keepalives that reuse Call-ID + CSeq but carry a fresh branch are new
    // transactions and must NOT be folded away as retransmissions.
    /// OPTIONS keepalives reusing Call-ID + CSeq but with fresh Via
    /// branches are distinct transactions, not retransmissions.
    #[test]
    fn same_cseq_new_branch_is_not_a_retransmission() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        for i in 0..3u32 {
            let ts = t0 + TimeDelta::seconds(30 * i64::from(i));
            store.process_message(make_options_with_branch(
                "keepalive@test",
                1,
                &format!("z9hG4bK.ka{i}"),
                ts,
            ));
        }

        let dialog = store.get("keepalive@test").expect("dialog should exist");
        assert_eq!(dialog.messages.len(), 3, "all three keepalives stored");
        for (i, m) in dialog.messages.iter().enumerate() {
            assert!(
                !m.is_retransmission,
                "keepalive {i} wrongly flagged as retransmission"
            );
        }
        assert_eq!(dialog.timing.total_retransmits(), 0);
    }

    /// A repeat of the same CSeq AND the same Via branch is flagged as a
    /// retransmission and counted in the timing stats.
    #[test]
    fn same_cseq_same_branch_is_a_retransmission() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_options_with_branch(
            "retx-branch@test",
            1,
            "z9hG4bK.same",
            t0,
        ));
        store.process_message(make_options_with_branch(
            "retx-branch@test",
            1,
            "z9hG4bK.same",
            t0 + TimeDelta::milliseconds(500),
        ));

        let dialog = store.get("retx-branch@test").expect("dialog should exist");
        assert_eq!(dialog.messages.len(), 2);
        assert!(!dialog.messages[0].is_retransmission);
        assert!(dialog.messages[1].is_retransmission);
        assert_eq!(dialog.timing.total_retransmits(), 1);
    }

    /// Responses are also keyed by branch: 200 OKs from distinct
    /// transactions are new, while a repeated 200 OK (same branch) is a
    /// retransmission.
    #[test]
    fn response_retransmission_keyed_by_branch_too() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        // Two full keepalive transactions: each 200 OK carries its own branch.
        for i in 0..2u32 {
            let ts = t0 + TimeDelta::seconds(30 * i64::from(i));
            let branch = format!("z9hG4bK.tx{i}");
            store.process_message(make_options_with_branch("resp-branch@test", 1, &branch, ts));
            store.process_message(make_options_200_with_branch(
                "resp-branch@test",
                1,
                &branch,
                ts + TimeDelta::milliseconds(20),
            ));
        }
        let dialog = store.get("resp-branch@test").expect("dialog should exist");
        assert_eq!(dialog.messages.len(), 4);
        assert!(
            dialog.messages.iter().all(|m| !m.is_retransmission),
            "distinct transactions must not be flagged"
        );

        // A genuinely repeated 200 OK (same branch) IS a retransmission.
        store.process_message(make_options_200_with_branch(
            "resp-branch@test",
            1,
            "z9hG4bK.tx1",
            t0 + TimeDelta::seconds(31),
        ));
        let dialog = store.get("resp-branch@test").expect("dialog should exist");
        assert!(dialog.messages[4].is_retransmission);
    }

    // Adversarial branch values: none of these may panic, and behavior must be
    // deterministic. An empty `branch=` is treated as absent (CSeq fallback),
    // so two of them compare equal → retransmission.
    /// Adversarial branch values (backslashes, quotes, spaces, empty) are
    /// handled deterministically without panicking.
    #[test]
    fn adversarial_branch_values_are_handled() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        for (cid, branch) in [
            ("adv-backslash@test", r"z9hG4bK.a\b\\c"),
            ("adv-quote@test", "z9hG4bK.'\"quoted"),
            ("adv-space@test", "z9hG4bK.with stuff"),
        ] {
            store.process_message(make_options_with_branch(cid, 1, branch, t0));
            store.process_message(make_options_with_branch(
                cid,
                1,
                branch,
                t0 + TimeDelta::milliseconds(100),
            ));
            let dialog = store.get(cid).expect("dialog should exist");
            assert!(
                dialog.messages[1].is_retransmission,
                "{cid}: identical odd branch must still detect retransmission"
            );
        }

        // Empty branch value → fallback identity (same as no branch at all).
        store.process_message(make_options_with_branch("adv-empty@test", 1, "", t0));
        store.process_message(make_options_with_branch(
            "adv-empty@test",
            1,
            "",
            t0 + TimeDelta::milliseconds(100),
        ));
        let dialog = store.get("adv-empty@test").expect("dialog should exist");
        assert!(dialog.messages[1].is_retransmission);
    }

    /// Retransmitted INVITEs are stored for ladder display but flagged,
    /// and only the repeats count as retransmissions.
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

    /// A retransmitted INVITE after the 200 OK does not regress the
    /// dialog state from InCall.
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

    /// Messages with distinct Call-IDs create independent dialogs.
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

    /// INVITE → 200 OK → BYE through the store ends in Completed with all
    /// three messages stored.
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

    /// active_count counts only dialogs in an active state and drops as
    /// calls complete, while len keeps counting completed ones.
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

    /// A message without a Call-ID header is silently dropped and creates
    /// no dialog.
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

    /// A freshly created store is empty with zero total and active counts.
    #[test]
    fn is_empty_on_new_store() {
        let store = DialogStore::new(100, false);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.active_count(), 0);
    }

    /// iter yields every tracked dialog exactly once.
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

    /// Timing measurements (setup time here) are populated when messages
    /// flow through the store's processing path.
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

    /// Responses with the same CSeq but different status codes (100 then
    /// 180) are distinct messages, not retransmissions.
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
    /// Build an INVITE carrying an RFC 7989 `Session-ID`.
    fn make_invite_with_session_id(
        call_id: &str,
        session_id: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("Session-ID: {session_id}"),
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

    /// The case the whole feature exists for: an SBC rewrote the Call-ID, so
    /// nothing else ties the legs together, and the two `Session-ID` values are
    /// DIFFERENT STRINGS because the halves swap perspective across a B2BUA.
    #[test]
    fn session_id_correlates_two_legs_across_a_b2bua_that_rewrote_the_call_id() {
        const A: &str = "ab30317f1a784dc48ff824d0d3715d86";
        const B: &str = "47755a9de7794ba387653f2099600ef2";
        let ts = Utc::now();
        let mut store = DialogStore::new(100, false);
        store.process_message(make_invite_with_session_id(
            "leg-a@access",
            &format!("{A};remote={B}"),
            ts,
        ));
        store.process_message(make_invite_with_session_id(
            "leg-b@core",
            &format!("{B};remote={A}"),
            ts,
        ));

        let found = store.find_correlated_scored("leg-a@access");
        assert_eq!(found.len(), 1, "the far leg must be found");
        assert_eq!(found[0].dialog.call_id, "leg-b@core");
        assert_eq!(found[0].score, 100);
        assert_eq!(
            found[0].reason,
            CorrelationReason::SessionId,
            "and attributed to the standard, not to a timing guess"
        );
    }

    /// Mutation guard for the test above: unrelated sessions must NOT
    /// correlate, or `same_session_as` returning true would pass both.
    #[test]
    fn different_session_ids_do_not_correlate() {
        let ts = Utc::now();
        let mut store = DialogStore::new(100, false);
        store.process_message(make_invite_with_session_id(
            "leg-a@access",
            "ab30317f1a784dc48ff824d0d3715d86;remote=47755a9de7794ba387653f2099600ef2",
            ts,
        ));
        store.process_message(make_invite_with_session_id(
            "unrelated@core",
            "11111111111111111111111111111111;remote=22222222222222222222222222222222",
            ts,
        ));
        assert!(
            store
                .find_correlated_scored("leg-a@access")
                .iter()
                .all(|r| r.reason != CorrelationReason::SessionId)
        );
    }

    /// A shared `nil` half must not tie together every call still being set up.
    #[test]
    fn a_shared_nil_half_does_not_correlate_unrelated_setups() {
        const NIL: &str = "00000000000000000000000000000000";
        let ts = Utc::now();
        let mut store = DialogStore::new(100, false);
        store.process_message(make_invite_with_session_id(
            "setup-1@access",
            &format!("ab30317f1a784dc48ff824d0d3715d86;remote={NIL}"),
            ts,
        ));
        store.process_message(make_invite_with_session_id(
            "setup-2@access",
            &format!("47755a9de7794ba387653f2099600ef2;remote={NIL}"),
            ts,
        ));
        assert!(
            store
                .find_correlated_scored("setup-1@access")
                .iter()
                .all(|r| r.reason != CorrelationReason::SessionId),
            "nil is absence; two calls both saying 'unknown' are not one call"
        );
    }

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

    /// Build an INVITE carrying an arbitrary correlation header.
    fn make_invite_with_header(
        call_id: &str,
        header_name: &str,
        header_value: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("{header_name}: {header_value}"),
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
        .expect("should parse INVITE with custom header")
    }

    /// A custom correlation header configured via with_xcid_headers
    /// (X-CID) correlates the B-leg that points back through it.
    #[test]
    fn xcid_custom_header_correlates() {
        // With a custom correlation header configured, a B-leg pointing back via
        // that header (X-CID here, not X-Call-ID) must correlate.
        let mut store = DialogStore::new(100, false).with_xcid_headers(vec!["X-CID".to_string()]);
        let t0 = base_ts();
        store.process_message(make_invite_msg("a-leg@test", t0));
        store.process_message(make_invite_with_header(
            "b-leg@test",
            "X-CID",
            "a-leg@test",
            t0 + TimeDelta::seconds(30),
        ));
        let correlated = store.find_correlated("a-leg@test");
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].call_id, "b-leg@test");
    }

    /// A header outside the configured correlation list (X-CID with the
    /// default X-Call-ID-only config) does not correlate.
    #[test]
    fn xcid_header_not_in_configured_list_is_ignored() {
        // Default list is just ["X-Call-ID"]; a B-leg carrying only X-CID (30s
        // later, so the timing heuristic can't match) must NOT correlate.
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        store.process_message(make_invite_msg("a-leg@test", t0));
        store.process_message(make_invite_with_header(
            "b-leg@test",
            "X-CID",
            "a-leg@test",
            t0 + TimeDelta::seconds(30),
        ));
        assert!(
            store.find_correlated("a-leg@test").is_empty(),
            "X-CID must not correlate when only X-Call-ID is configured"
        );
    }

    /// Passing an empty header list to with_xcid_headers keeps the
    /// default X-Call-ID correlation working.
    #[test]
    fn with_xcid_headers_empty_keeps_default() {
        // An empty override must not wipe out the default X-Call-ID correlation.
        let mut store = DialogStore::new(100, false).with_xcid_headers(vec![]);
        let t0 = base_ts();
        store.process_message(make_invite_msg("a-leg@test", t0));
        store.process_message(make_invite_with_x_call_id(
            "b-leg@test",
            "a-leg@test",
            t0 + TimeDelta::seconds(30),
        ));
        assert_eq!(store.find_correlated("a-leg@test").len(), 1);
    }

    /// X-Call-ID correlation works in both directions: A-leg finds B-leg
    /// and B-leg finds A-leg.
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

    /// Unrelated dialogs (no shared headers/branches, created more than
    /// 2 s apart) do not correlate.
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

    /// find_correlated for a Call-ID not in the store returns empty.
    #[test]
    fn find_correlated_unknown_call_id_returns_empty() {
        let store = DialogStore::new(100, false);
        assert!(store.find_correlated("nonexistent@test").is_empty());
    }

    /// Legs whose X-Call-ID headers point at each other correlate without
    /// duplicate results.
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

    /// An X-Call-ID match scores 100 with the XCallId reason.
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

    /// A shared Via branch on the INVITEs scores 80 with the ViaBranch
    /// reason.
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

    /// Two INVITE dialogs sharing an endpoint IP and created within 2 s
    /// score 50 with the TimingHeuristic reason.
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

    /// The timing heuristic does not fire for dialogs created more than
    /// 2 s apart.
    #[test]
    fn timing_heuristic_excluded_beyond_2s() {
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();

        store.process_message(make_invite_msg("gap-a@test", t0));
        store.process_message(make_invite_msg("gap-b@test", t0 + TimeDelta::seconds(3)));

        let results = store.find_correlated_scored("gap-a@test");
        assert!(results.is_empty());
    }

    /// A candidate matching several strategies is reported once with the
    /// highest score (X-Call-ID beats Via branch).
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

    /// After eviction at a small cap, remaining dialogs stay reachable by
    /// key (immutably and mutably) and iteration order is preserved.
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

    /// A dialog's message list stops growing at the per-dialog message
    /// cap even as further messages are processed.
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

    /// Dialogs sharing a Via branch correlate (score 80); a dialog with a
    /// different branch created well apart does not.
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

    /// A REFER during an established call moves the dialog to
    /// Transferring and stores the Refer-To target URI.
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

    /// A REFER using the RFC 3515 compact `r:` form of Refer-To drives
    /// transfer tracking exactly like the long form.
    #[test]
    fn refer_with_compact_r_header_tracks_transfer() {
        // RFC 3515 registers `r` as the compact form of Refer-To; a REFER
        // using it must drive transfer tracking exactly like the long form.
        let mut store = DialogStore::new(100, false);
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(1);
        let t2 = t0 + TimeDelta::seconds(2);

        store.process_message(make_invite_msg("refer-compact@test", t0));
        store.process_message(make_200_ok("refer-compact@test", t1));

        let refer = {
            let raw = build_sip(
                "REFER sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: refer-compact@test",
                    "CSeq: 2 REFER",
                    "r: <sip:1003@example.com>",
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

        let dialog = store.get("refer-compact@test").expect("dialog exists");
        assert_eq!(*dialog.state(), DialogState::Transferring);
        let refer_to = dialog
            .refer_to
            .as_deref()
            .expect("compact r: must populate refer_to");
        assert!(refer_to.contains("sip:1003@example.com"));
    }

    /// A REFER without a Refer-To header leaves the dialog's refer_to
    /// field as None.
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

    /// SIPREC metadata inside a multipart/mixed body is parsed and stored
    /// on the dialog (session, participants, streams).
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
    /// The generation counter is the cache-invalidation signal for the
    /// per-frame displayed-dialogs cache: EVERY mutation — new dialog,
    /// in-place message on an existing dialog, clear, retain — must bump
    /// it, or the TUI would render stale rows.
    #[test]
    fn generation_bumps_on_every_mutation() {
        let t0 = base_ts();
        let mut store = DialogStore::new(10, false);
        let g0 = store.generation();

        store.process_message(make_invite_msg("gen-1@test", t0));
        let g1 = store.generation();
        assert!(g1 > g0, "new dialog must bump the generation");

        // An in-place update (no len() change) must bump too — this is the
        // case a len()-keyed cache would miss.
        store.process_message(make_200_ok("gen-1@test", t0));
        let g2 = store.generation();
        assert!(g2 > g1, "in-place message must bump the generation");

        store.retain(|d| d.call_id != "no-such");
        let g3 = store.generation();
        assert!(g3 > g2, "retain must bump the generation");

        store.clear();
        assert!(store.generation() > g3, "clear must bump the generation");
    }
}
