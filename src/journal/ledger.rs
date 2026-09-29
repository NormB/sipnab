// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the journal says is true now: the ledger a restarted sipnab rebuilds.
//!
//! Built from journal records alone, so every rule is a pure function over
//! records and what TFPS reports. The record kinds it reads are the ones the
//! action path writes (see the approved spec "sipnab Operations Journal"):
//!
//! * `action_intent` — admitted and about to run; in doubt until resolved;
//! * `action_outcome` — `applied`, `refused` or `failed`;
//! * `revert_intent` / `revert_outcome` — the same, for an unban that backs
//!   out an earlier ban;
//! * `reconciled` — an in-doubt action resolved against TFPS at startup;
//! * `lapsed_by_peer` — TFPS dropped an owned ban before its expiry;
//! * `checkpoint` — the whole ledger, opening a new segment.
//!
//! Every other kind is ignored here: a record this code does not know about is
//! not a reason to refuse the journal.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Record;

/// Seconds of admitted actions kept for rebuilding the rate limits: longer
/// than any window or cooldown they are rebuilt into.
const RECENT_KEEP_SECS: u64 = 3_600;

/// How far TFPS's reported expiry may differ from the intent's and still be
/// the same ban. Covers the time between writing the intent and TFPS
/// computing its own deadline.
const EXPIRY_SLACK_SECS: u64 = 5;

/// What an action asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    /// Ask TFPS to ban an address.
    Ban,
    /// Ask TFPS to unban an address.
    Unban,
}

/// An admitted action, as its `action_intent` record describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// The action id, which every later record about it names.
    pub id: String,
    /// Ban or unban.
    pub verb: Verb,
    /// The address acted on.
    pub address: String,
    /// When it was admitted, Unix seconds.
    pub at: u64,
    /// When a ban lapses, Unix seconds.
    #[serde(default)]
    pub expires: Option<u64>,
    /// Who asked: a token id, or the local operator.
    #[serde(default)]
    pub caller: String,
    /// Where it was asked: `rest`, `mcp` or `cli`.
    #[serde(default)]
    pub surface: String,
    /// The journal sequence number of the intent record: the order actions
    /// were taken in, across runs, where `at` alone ties within a second.
    #[serde(default)]
    pub seq: u64,
}

/// What TFPS reports about an address when asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TfpsView {
    /// Not banned.
    Absent,
    /// Banned, until `expires` (Unix seconds), or with no expiry.
    Banned {
        /// When TFPS says the ban lapses.
        expires: Option<u64>,
    },
    /// TFPS could not be asked.
    Unreachable,
}

/// How an action left in doubt is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// It took effect.
    Applied,
    /// It did not take effect.
    NotApplied,
    /// TFPS shows a ban sipnab cannot prove it placed. Never owned: owning it
    /// would let revert-all lift somebody else's ban.
    Unknown,
}

impl Intent {
    /// Resolve this action against what TFPS reports now, or `None` when TFPS
    /// cannot say, in which case it stays in doubt.
    #[must_use]
    pub fn resolve(&self, view: TfpsView) -> Option<Resolution> {
        match (self.verb, view) {
            (_, TfpsView::Unreachable) => None,
            (Verb::Ban, TfpsView::Absent) | (Verb::Unban, TfpsView::Banned { .. }) => {
                Some(Resolution::NotApplied)
            }
            (Verb::Unban, TfpsView::Absent) => Some(Resolution::Applied),
            (Verb::Ban, TfpsView::Banned { expires }) => match (self.expires, expires) {
                (Some(ours), Some(theirs)) if ours.abs_diff(theirs) <= EXPIRY_SLACK_SECS => {
                    Some(Resolution::Applied)
                }
                _ => Some(Resolution::Unknown),
            },
        }
    }
}

/// A ban sipnab placed and still owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owned {
    /// The action that placed it.
    pub id: String,
    /// The address banned.
    pub address: String,
    /// When it lapses, Unix seconds.
    pub expires: u64,
    /// When it was placed, Unix seconds.
    pub at: u64,
    /// The journal sequence number of the ban's intent.
    #[serde(default)]
    pub seq: u64,
    /// Who asked for it.
    #[serde(default)]
    pub caller: String,
    /// Where it was asked.
    #[serde(default)]
    pub surface: String,
}

/// An admitted action, for rebuilding the rate limits after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentAction {
    /// Who asked.
    pub caller: String,
    /// The address acted on.
    pub address: String,
    /// When, Unix seconds.
    pub at: u64,
}

/// The state the journal says is in force.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// Owned bans, by address.
    owned: BTreeMap<String, Owned>,
    /// Actions admitted with no outcome yet, by id.
    in_doubt: BTreeMap<String, Intent>,
    /// Actions resolved as `unknown`, for the operator.
    unknown: Vec<Intent>,
    /// Admitted actions of the last hour, oldest first.
    recent: Vec<RecentAction>,
    /// The time the ledger is read at, Unix seconds; not part of a checkpoint.
    #[serde(skip)]
    now: u64,
}

impl Ledger {
    /// The ledger `records` describe, read at `now` (Unix seconds).
    #[must_use]
    pub fn from_records(records: &[Record], now: u64) -> Self {
        let mut ledger = Self {
            now,
            ..Self::default()
        };
        for r in records {
            ledger.apply(r);
        }
        ledger.set_now(now);
        ledger
    }

    /// Move the ledger's clock to `now`, dropping what has lapsed.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
        self.owned.retain(|_, o| o.expires > now);
        let floor = now.saturating_sub(RECENT_KEEP_SECS);
        self.recent.retain(|a| a.at >= floor);
    }

    /// Apply one record. Unknown kinds and malformed bodies are ignored.
    pub fn apply(&mut self, record: &Record) {
        let body = &record.body;
        let id = || body["id"].as_str().map(str::to_string);
        match record.kind.as_str() {
            // A revert is an unban that names the action it backs out; the
            // ledger reads it as the unban it is.
            "action_intent" | "revert_intent" => {
                if let Ok(mut intent) = serde_json::from_value::<Intent>(body.clone()) {
                    intent.seq = record.seq;
                    self.recent.push(RecentAction {
                        caller: intent.caller.clone(),
                        address: intent.address.clone(),
                        at: intent.at,
                    });
                    self.in_doubt.insert(intent.id.clone(), intent);
                }
            }
            "action_outcome" | "revert_outcome" => {
                if let Some(intent) = id().and_then(|id| self.in_doubt.remove(&id))
                    && body["result"].as_str() == Some("applied")
                {
                    self.take_effect(&intent);
                }
            }
            "reconciled" => {
                if let Some(intent) = id().and_then(|id| self.in_doubt.remove(&id)) {
                    match serde_json::from_value::<Resolution>(body["resolution"].clone()) {
                        Ok(Resolution::Applied) => self.take_effect(&intent),
                        Ok(Resolution::Unknown) => self.unknown.push(intent),
                        Ok(Resolution::NotApplied) => {}
                        // Unreadable: keep it in doubt rather than guess.
                        Err(_) => {
                            self.in_doubt.insert(intent.id.clone(), intent);
                        }
                    }
                }
            }
            "lapsed_by_peer" => {
                if let (Some(id), Some(address)) = (id(), body["address"].as_str())
                    && self.owned.get(address).is_some_and(|o| o.id == id)
                {
                    self.owned.remove(address);
                }
            }
            "checkpoint" => {
                if let Ok(state) = serde_json::from_value::<Ledger>(body["state"].clone()) {
                    *self = Self {
                        now: self.now,
                        ..state
                    };
                }
            }
            _ => {}
        }
    }

    /// What an applied intent changes: a ban is owned, an unban is not.
    fn take_effect(&mut self, intent: &Intent) {
        match intent.verb {
            Verb::Ban => {
                if let Some(expires) = intent.expires {
                    self.owned.insert(
                        intent.address.clone(),
                        Owned {
                            id: intent.id.clone(),
                            address: intent.address.clone(),
                            expires,
                            at: intent.at,
                            seq: intent.seq,
                            caller: intent.caller.clone(),
                            surface: intent.surface.clone(),
                        },
                    );
                }
            }
            Verb::Unban => {
                self.owned.remove(&intent.address);
            }
        }
    }

    /// The ban sipnab owns on `address`, if it is still in force.
    #[must_use]
    pub fn owned(&self, address: &str) -> Option<&Owned> {
        self.owned.get(address).filter(|o| o.expires > self.now)
    }

    /// Every owned ban in force, newest first: the order revert-all undoes them.
    #[must_use]
    pub fn owned_newest_first(&self) -> Vec<&Owned> {
        let mut v: Vec<&Owned> = self
            .owned
            .values()
            .filter(|o| o.expires > self.now)
            .collect();
        v.sort_by_key(|o| std::cmp::Reverse(o.seq));
        v
    }

    /// Actions admitted with no outcome, oldest id first.
    #[must_use]
    pub fn in_doubt(&self) -> Vec<Intent> {
        self.in_doubt.values().cloned().collect()
    }

    /// Actions resolved as `unknown`.
    #[must_use]
    pub fn unknown(&self) -> &[Intent] {
        &self.unknown
    }

    /// Actions admitted within the last `window_secs` before `now`.
    #[must_use]
    pub fn recent_actions(&self, now: u64, window_secs: u64) -> Vec<RecentAction> {
        self.recent
            .iter()
            .filter(|a| a.at + window_secs > now && a.at <= now)
            .cloned()
            .collect()
    }

    /// The whole ledger, for the `checkpoint` that opens a new segment.
    #[must_use]
    pub fn checkpoint_state(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}
