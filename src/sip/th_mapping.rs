// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! OpenSIPS topology-hiding Call-ID mappings: one small event per call, sent
//! by OpenSIPS `event_datagram`, that names the caller-side Call-ID (`$ci`)
//! and the encoded callee-side Call-ID (`$TH_callee_callid`) of one call.
//!
//! # The event
//!
//! OpenSIPS `raise_event` with named attributes, delivered by `event_datagram`
//! over UDP, is one JSON-RPC 2.0 notification (`evi/evi_transport.c`,
//! `evi_build_payload`):
//!
//! ```text
//! {"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"callee_call_id":"DLGCH_...","caller_call_id":"1-th-map@example.com"}}
//! ```
//!
//! sipnab receives it on its `--hep-listen` socket, where a JSON body starts
//! with `{` and a HEP v3 packet with `HEP3`, and only from a sender listed in
//! `--hep-allow` (see `crate::capture::hep`).
//!
//! # The table
//!
//! [`ThMappingTable`] holds the mappings a dialog store uses to join the two
//! legs. A mapping may arrive before or after the SIP it describes: the join is
//! worked out when a correlation is asked for, so the order does not matter.
//!
//! - A repeated pair is a no-op ([`Insert::Duplicate`]).
//! - A pair that reuses either Call-ID with a different partner is refused,
//!   and the mapping already held for it stops joining as well
//!   ([`Insert::Conflict`]): the two cannot both be right, and sipnab cannot
//!   tell which is, so neither merges two calls.
//! - The table holds at most a configured number of mappings
//!   ([`Insert::Full`] past it), and a mapping neither of whose legs the store
//!   holds expires a configured time after either leg was last present.

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};

/// The event name the OpenSIPS script raises.
pub const EVENT_NAME: &str = "E_SIPNAB_TH_MAP";

/// The largest event accepted. Two Call-IDs and the JSON-RPC envelope fit in
/// well under this; a larger datagram is not this event.
pub const MAX_EVENT_BYTES: usize = 4096;

/// Default for `[sip] th_mapping_ttl_secs`: how long a mapping is kept after
/// the store last held either of its legs.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Default for `[sip] th_mapping_max`: how many mappings the table holds.
pub const DEFAULT_MAX_MAPPINGS: usize = 100_000;

/// One call's two Call-IDs, as OpenSIPS named them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThMapping {
    /// The caller-side Call-ID (`$ci`).
    pub caller_call_id: String,
    /// The callee-side Call-ID topology hiding wrote (`$TH_callee_callid`).
    pub callee_call_id: String,
}

/// Why an event datagram was not a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventRefusal {
    /// Larger than [`MAX_EVENT_BYTES`].
    TooLarge,
    /// Not a JSON object.
    NotJson,
    /// A JSON object, but not a JSON-RPC 2.0 call naming [`EVENT_NAME`].
    WrongEvent,
    /// `params` is not an object holding both Call-IDs as strings.
    MissingCallId,
    /// A Call-ID that is not an RFC 3261 `callid`, or the two are equal.
    BadCallId,
}

impl EventRefusal {
    /// The wire name, for logs and counters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::NotJson => "not_json",
            Self::WrongEvent => "wrong_event",
            Self::MissingCallId => "missing_call_id",
            Self::BadCallId => "bad_call_id",
        }
    }
}

/// Parse one event datagram.
///
/// # Errors
///
/// [`EventRefusal`] naming the first rule the datagram breaks.
pub fn parse_event(datagram: &[u8]) -> Result<ThMapping, EventRefusal> {
    if datagram.len() > MAX_EVENT_BYTES {
        return Err(EventRefusal::TooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_slice(datagram).map_err(|_| EventRefusal::NotJson)?;
    let Some(event) = value.as_object() else {
        return Err(EventRefusal::NotJson);
    };
    let is_str = |key: &str, want: &str| event.get(key).and_then(|v| v.as_str()) == Some(want);
    if !is_str("jsonrpc", "2.0") || !is_str("method", EVENT_NAME) {
        return Err(EventRefusal::WrongEvent);
    }
    let params = event
        .get("params")
        .and_then(serde_json::Value::as_object)
        .ok_or(EventRefusal::MissingCallId)?;
    let call_id = |key: &str| {
        params
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(EventRefusal::MissingCallId)
    };
    let caller = call_id("caller_call_id")?;
    let callee = call_id("callee_call_id")?;
    if !is_rfc3261_callid(caller.as_bytes())
        || !is_rfc3261_callid(callee.as_bytes())
        || caller == callee
    {
        return Err(EventRefusal::BadCallId);
    }
    Ok(ThMapping {
        caller_call_id: caller.to_string(),
        callee_call_id: callee.to_string(),
    })
}

/// RFC 3261 `word` characters: alphanum and `-.!%*_+`'~()<>:\"/[]?{}`.
fn is_word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-.!%*_+`'~()<>:\\\"/[]?{}".contains(&c)
}

/// RFC 3261 `callid = word [ "@" word ]`.
#[must_use]
pub fn is_rfc3261_callid(b: &[u8]) -> bool {
    let mut parts = b.splitn(2, |&c| c == b'@');
    let word_ok = |w: &[u8]| !w.is_empty() && w.iter().all(|&c| is_word_char(c));
    match (parts.next(), parts.next()) {
        (Some(w), None) => word_ok(w),
        (Some(w), Some(h)) => word_ok(w) && word_ok(h),
        _ => false,
    }
}

/// What [`ThMappingTable::insert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// A new mapping.
    Added,
    /// The same pair was already held: nothing changed.
    Duplicate,
    /// Either Call-ID is already mapped to a different partner. The new pair
    /// is refused, and the mapping already held stops joining.
    Conflict,
    /// The table is at its bound: the pair is refused.
    Full,
}

/// Counts a table keeps, for the status surfaces and metrics. Every field is
/// a running total since the process started, except where noted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ThMappingCounts {
    /// Events that added a mapping.
    pub accepted: u64,
    /// Events that repeated a mapping already held.
    pub duplicate: u64,
    /// Events refused because a Call-ID was already mapped to another
    /// partner.
    pub conflict: u64,
    /// Event datagrams that were not a valid mapping event.
    pub malformed: u64,
    /// Events refused because the table was full.
    pub refused_full: u64,
    /// Mappings dropped because neither leg was in the store for the
    /// configured lifetime.
    pub expired: u64,
    /// Mappings held now (not a running total).
    pub held: u64,
    /// Of `held`, mappings the store does not yet hold both legs of (not a
    /// running total). Filled in by the store, which knows the legs.
    pub pending: u64,
}

/// Where one held mapping stands, for the listing surfaces.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum ThMappingState {
    /// Another event named one of its Call-IDs with a different partner: it
    /// joins nothing.
    Conflict,
    /// Not both of its legs are captured yet.
    Pending,
    /// Both legs are captured, and the mapping joins them.
    Joined,
}

impl ThMappingState {
    /// The state of a mapping from whether a conflict stopped it and whether
    /// each leg is captured. A conflict decides first: a stopped mapping
    /// joins nothing whatever is captured.
    #[must_use]
    pub const fn of(conflicted: bool, caller_captured: bool, callee_captured: bool) -> Self {
        if conflicted {
            Self::Conflict
        } else if caller_captured && callee_captured {
            Self::Joined
        } else {
            Self::Pending
        }
    }

    /// The wire name: `conflict`, `pending` or `joined`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Pending => "pending",
            Self::Joined => "joined",
        }
    }

    /// The state named `s`.
    ///
    /// # Errors
    ///
    /// The refusal every listing surface gives for any other word, naming the
    /// three real ones.
    pub fn parse(s: &str) -> Result<Self, String> {
        [Self::Conflict, Self::Pending, Self::Joined]
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| {
                format!("'{s}' is not a mapping state; one of: conflict, pending, joined.")
            })
    }
}

impl std::fmt::Display for ThMappingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One held mapping, as [`ThMappingTable::entries`] yields it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldMapping<'a> {
    /// The caller-side Call-ID.
    pub caller_call_id: &'a str,
    /// The callee-side Call-ID.
    pub callee_call_id: &'a str,
    /// Whether a conflicting event stopped it.
    pub conflicted: bool,
}

/// One held mapping.
#[derive(Debug, Clone)]
struct Entry {
    /// The callee-side Call-ID.
    callee: String,
    /// When either leg was last known to be in the store, or the mapping
    /// arrived.
    touched: DateTime<Utc>,
    /// A conflicting event named one of these Call-IDs: the mapping no longer
    /// joins.
    conflicted: bool,
}

/// The mappings a dialog store joins legs with. See the module docs.
#[derive(Debug, Clone)]
pub struct ThMappingTable {
    /// Caller-side Call-ID to its entry.
    by_caller: HashMap<String, Entry>,
    /// Callee-side Call-ID to its caller-side Call-ID.
    by_callee: HashMap<String, String>,
    /// Most mappings held at once.
    max: usize,
    /// How long a mapping is kept after either leg was last present.
    ttl: TimeDelta,
    /// Running totals.
    counts: ThMappingCounts,
}

impl Default for ThMappingTable {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_MAPPINGS, DEFAULT_TTL_SECS)
    }
}

impl ThMappingTable {
    /// An empty table holding at most `max` mappings, each kept `ttl_secs`
    /// after either leg was last in the store.
    #[must_use]
    pub fn new(max: usize, ttl_secs: u64) -> Self {
        Self {
            by_caller: HashMap::new(),
            by_callee: HashMap::new(),
            max,
            ttl: TimeDelta::seconds(i64::try_from(ttl_secs).unwrap_or(i64::MAX / 1000)),
            counts: ThMappingCounts::default(),
        }
    }

    /// Record one event, received at `now`.
    pub fn insert(&mut self, mapping: ThMapping, now: DateTime<Utc>) -> Insert {
        let ThMapping {
            caller_call_id: caller,
            callee_call_id: callee,
        } = mapping;
        let held_for_caller = self
            .by_caller
            .get(&caller)
            .map(|e| (e.callee.clone(), e.conflicted));
        let held_for_callee = self.by_callee.get(&callee).cloned();
        let outcome = match (&held_for_caller, &held_for_callee) {
            // The same pair again, and nothing has contradicted it.
            (Some((held_callee, false)), _) if *held_callee == callee => Insert::Duplicate,
            (None, None) if self.by_caller.len() >= self.max => Insert::Full,
            (None, None) => {
                self.by_callee.insert(callee.clone(), caller.clone());
                self.by_caller.insert(
                    caller,
                    Entry {
                        callee,
                        touched: now,
                        conflicted: false,
                    },
                );
                Insert::Added
            }
            // Either Call-ID already belongs to a mapping that is not this
            // pair, or to this pair after a conflict stopped it: neither
            // joins from now on.
            _ => {
                if let Some(e) = self.by_caller.get_mut(&caller) {
                    e.conflicted = true;
                }
                if let Some(other) = held_for_callee
                    && let Some(e) = self.by_caller.get_mut(&other)
                {
                    e.conflicted = true;
                }
                Insert::Conflict
            }
        };
        match outcome {
            Insert::Added => self.counts.accepted += 1,
            Insert::Duplicate => self.counts.duplicate += 1,
            Insert::Conflict => self.counts.conflict += 1,
            Insert::Full => self.counts.refused_full += 1,
        }
        outcome
    }

    /// Count one event datagram that was not a valid mapping.
    pub fn note_malformed(&mut self) {
        self.counts.malformed += 1;
    }

    /// The other leg of `call_id`, when a mapping that still joins names it.
    #[must_use]
    pub fn partner(&self, call_id: &str) -> Option<&str> {
        if let Some(e) = self.by_caller.get(call_id) {
            return (!e.conflicted).then_some(e.callee.as_str());
        }
        let caller = self.by_callee.get(call_id)?;
        let e = self.by_caller.get(caller)?;
        (!e.conflicted).then_some(caller.as_str())
    }

    /// Whether a mapping that still joins names `a` and `b` as one call's
    /// two legs, in either order.
    ///
    /// Asked of a pair rather than answered with one partner, because a
    /// Call-ID can be the callee side of one mapping and the caller side of
    /// another: two topology-hiding proxies in series, where the first hop's
    /// hidden Call-ID is the second hop's `$ci`.
    #[must_use]
    pub fn links(&self, a: &str, b: &str) -> bool {
        let joined = |caller: &str, callee: &str| {
            self.by_caller
                .get(caller)
                .is_some_and(|e| !e.conflicted && e.callee == callee)
        };
        joined(a, b) || joined(b, a)
    }

    /// Whether `call_id` is a leg of a mapping that a conflict stopped.
    #[must_use]
    pub fn is_conflicted(&self, call_id: &str) -> bool {
        let caller = self.by_callee.get(call_id).map_or(call_id, String::as_str);
        self.by_caller.get(caller).is_some_and(|e| e.conflicted)
    }

    /// Whether `call_id` is the callee-side leg of any mapping held.
    #[must_use]
    pub fn is_callee(&self, call_id: &str) -> bool {
        self.by_callee.contains_key(call_id)
    }

    /// Drop the mappings neither of whose legs `present` reports, once `ttl`
    /// has passed since either was last present; restart the clock of every
    /// mapping with a leg present.
    pub fn sweep(&mut self, now: DateTime<Utc>, present: impl Fn(&str) -> bool) {
        let mut gone = Vec::new();
        for (caller, e) in &mut self.by_caller {
            if present(caller) || present(&e.callee) {
                e.touched = now;
            } else if now - e.touched > self.ttl {
                gone.push(caller.clone());
            }
        }
        for caller in gone {
            if let Some(e) = self.by_caller.remove(&caller) {
                self.by_callee.remove(&e.callee);
                self.counts.expired += 1;
            }
        }
    }

    /// The counts, with `held` filled in and `pending` the mappings that
    /// `present` does not report both legs of.
    #[must_use]
    pub fn counts(&self, present: impl Fn(&str) -> bool) -> ThMappingCounts {
        let pending = self
            .by_caller
            .iter()
            .filter(|(caller, e)| !(present(caller) && present(&e.callee)))
            .count();
        ThMappingCounts {
            held: self.by_caller.len() as u64,
            pending: pending as u64,
            ..self.counts
        }
    }

    /// Every mapping held, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = HeldMapping<'_>> {
        self.by_caller.iter().map(|(caller, e)| HeldMapping {
            caller_call_id: caller.as_str(),
            callee_call_id: e.callee.as_str(),
            conflicted: e.conflicted,
        })
    }

    /// How many mappings are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_caller.len()
    }

    /// Whether no mapping is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_caller.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    const CALLER: &str = "1-th-map@example.com";
    const CALLEE: &str = "DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-";

    /// The datagram OpenSIPS 4.0.2 sent for call 1 of
    /// `tests/fixtures/th-mapping/opensips-4.0-events.pcap`, byte for byte.
    const WIRE: &str = r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"callee_call_id":"DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-","caller_call_id":"1-th-map@example.com"}}"#;

    fn m(caller: &str, callee: &str) -> ThMapping {
        ThMapping {
            caller_call_id: caller.into(),
            callee_call_id: callee.into(),
        }
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + TimeDelta::days(20_000) + TimeDelta::seconds(secs)
    }

    #[test]
    fn the_datagram_opensips_sends_parses() {
        assert_eq!(
            parse_event(WIRE.as_bytes()),
            Ok(m(CALLER, CALLEE)),
            "the datagram OpenSIPS 4.0.2 sent names call 1's two Call-IDs"
        );
        // Key order and whitespace are JSON's business, not the event's.
        let spaced = r#"{ "method": "E_SIPNAB_TH_MAP", "jsonrpc": "2.0",
            "params": { "caller_call_id": "a@example.com", "callee_call_id": "DLGCH_b" } }"#;
        assert_eq!(
            parse_event(spaced.as_bytes()),
            Ok(m("a@example.com", "DLGCH_b")),
            "key order and whitespace do not matter"
        );
    }

    #[test]
    fn anything_else_is_refused_with_its_reason() {
        let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_EVENT_BYTES));
        assert_eq!(
            parse_event(big.as_bytes()),
            Err(EventRefusal::TooLarge),
            "a datagram past MAX_EVENT_BYTES is refused before it is parsed"
        );
        assert_eq!(
            parse_event(b"{not json"),
            Err(EventRefusal::NotJson),
            "bytes that are not JSON are refused"
        );
        assert_eq!(
            parse_event(b"[1,2]"),
            Err(EventRefusal::NotJson),
            "JSON that is not an object is refused"
        );
        for wrong in [
            r#"{"jsonrpc":"2.0","method":"E_OTHER","params":{"caller_call_id":"a@x","callee_call_id":"b"}}"#,
            r#"{"jsonrpc":"1.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":"b"}}"#,
            r#"{"method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":"b"}}"#,
        ] {
            assert_eq!(
                parse_event(wrong.as_bytes()),
                Err(EventRefusal::WrongEvent),
                "{wrong}"
            );
        }
        for missing in [
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP"}"#,
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":["a@x","b"]}"#,
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x"}}"#,
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":7}}"#,
            // An unset $TH_callee_callid arrives as JSON null.
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":null}}"#,
        ] {
            assert_eq!(
                parse_event(missing.as_bytes()),
                Err(EventRefusal::MissingCallId),
                "{missing}"
            );
        }
        for bad in [
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a b@x","callee_call_id":"c"}}"#,
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":""}}"#,
            r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"caller_call_id":"a@x","callee_call_id":"a@x"}}"#,
        ] {
            assert_eq!(
                parse_event(bad.as_bytes()),
                Err(EventRefusal::BadCallId),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_mapping_names_each_leg_to_the_other() {
        let mut tb = ThMappingTable::new(10, 60);
        assert_eq!(
            tb.insert(m(CALLER, CALLEE), t(0)),
            Insert::Added,
            "a new pair is added"
        );
        assert_eq!(
            tb.partner(CALLER),
            Some(CALLEE),
            "the caller side names the callee side"
        );
        assert_eq!(
            tb.partner(CALLEE),
            Some(CALLER),
            "the callee side names the caller side"
        );
        assert_eq!(
            tb.partner("other@example.com"),
            None,
            "a Call-ID no mapping names has no partner"
        );
        assert!(
            tb.is_callee(CALLEE) && !tb.is_callee(CALLER),
            "the callee-side Call-ID, and only it, is a callee"
        );
        assert_eq!(tb.counts(|_| false).accepted, 1, "one event accepted");
    }

    /// Two topology-hiding proxies in series: the first hop's hidden Call-ID
    /// is the second hop's caller-side Call-ID, and both pairs link.
    #[test]
    fn a_chain_of_two_hops_links_each_pair() {
        let mut tb = ThMappingTable::new(10, 60);
        assert_eq!(
            tb.insert(m("a@x", "DLGCH_1"), t(0)),
            Insert::Added,
            "first hop"
        );
        assert_eq!(
            tb.insert(m("DLGCH_1", "DLGCH_2"), t(0)),
            Insert::Added,
            "second hop"
        );
        assert!(tb.links("a@x", "DLGCH_1"), "the first hop links");
        assert!(
            tb.links("DLGCH_2", "DLGCH_1"),
            "the second hop links, either order"
        );
        assert!(
            !tb.links("a@x", "DLGCH_2"),
            "a pair nobody named does not link"
        );
    }

    #[test]
    fn a_repeated_event_changes_nothing() {
        let mut tb = ThMappingTable::new(10, 60);
        tb.insert(m(CALLER, CALLEE), t(0));
        assert_eq!(
            tb.insert(m(CALLER, CALLEE), t(1)),
            Insert::Duplicate,
            "the same pair again is a duplicate"
        );
        assert_eq!(tb.len(), 1, "a duplicate adds nothing");
        let c = tb.counts(|_| false);
        assert_eq!(
            (c.accepted, c.duplicate, c.held),
            (1, 1, 1),
            "one accepted, one duplicate, one held"
        );
        assert_eq!(tb.partner(CALLER), Some(CALLEE), "the mapping still joins");
    }

    #[test]
    fn a_conflict_is_refused_and_stops_the_mapping_it_contradicts() {
        // The same caller with a different callee, and the same callee with a
        // different caller: each refused, and the held mapping stops joining.
        for second in [m(CALLER, "DLGCH_other"), m("other@example.com", CALLEE)] {
            let mut tb = ThMappingTable::new(10, 60);
            tb.insert(m(CALLER, CALLEE), t(0));
            assert_eq!(
                tb.insert(second.clone(), t(1)),
                Insert::Conflict,
                "{second:?}"
            );
            assert_eq!(tb.partner(CALLER), None, "{second:?}");
            assert_eq!(tb.partner(CALLEE), None, "{second:?}");
            assert_eq!(
                tb.partner(&second.caller_call_id),
                None,
                "the refused pair's caller joins nothing"
            );
            assert_eq!(
                tb.partner(&second.callee_call_id),
                None,
                "the refused pair's callee joins nothing"
            );
            assert!(
                tb.is_conflicted(CALLER) && tb.is_conflicted(CALLEE),
                "both legs of the held mapping are marked conflicted"
            );
            assert_eq!(tb.counts(|_| false).conflict, 1, "one conflict counted");
            // The original pair again is still not trusted.
            assert_eq!(
                tb.insert(m(CALLER, CALLEE), t(2)),
                Insert::Conflict,
                "the held pair is no longer trusted, even sent again"
            );
            assert_eq!(tb.partner(CALLER), None, "so it still joins nothing");
        }
    }

    #[test]
    fn the_table_is_bounded() {
        let mut tb = ThMappingTable::new(2, 60);
        assert_eq!(
            tb.insert(m("a@x", "DLGCH_a"), t(0)),
            Insert::Added,
            "first pair added"
        );
        assert_eq!(
            tb.insert(m("b@x", "DLGCH_b"), t(0)),
            Insert::Added,
            "second pair added, filling the table"
        );
        assert_eq!(
            tb.insert(m("c@x", "DLGCH_c"), t(0)),
            Insert::Full,
            "a third is refused at the bound"
        );
        assert_eq!(tb.len(), 2, "the table holds no more than its bound");
        assert_eq!(tb.partner("c@x"), None, "the refused pair joins nothing");
        assert_eq!(
            tb.counts(|_| false).refused_full,
            1,
            "the refusal is counted"
        );
        // A duplicate of a held pair is still recognized when full.
        assert_eq!(
            tb.insert(m("a@x", "DLGCH_a"), t(0)),
            Insert::Duplicate,
            "a held pair is still recognized when the table is full"
        );
    }

    #[test]
    fn a_mapping_expires_only_while_neither_leg_is_present() -> Result<(), TestError> {
        let mut tb = ThMappingTable::new(10, 60);
        tb.insert(m("a@x", "DLGCH_a"), t(0));
        tb.insert(m("b@x", "DLGCH_b"), t(0));
        // At 59 s nothing has expired.
        tb.sweep(t(59), |_| false);
        assert_eq!(
            tb.len(),
            2,
            "nothing expires before the lifetime has passed"
        );
        // `b`'s caller leg is in the store at 59 s, which restarts its clock.
        tb.sweep(t(59), |c| c == "b@x");
        // At 61 s `a` has gone 61 s with no leg present; `b` 2 s.
        tb.sweep(t(61), |_| false);
        assert_eq!(
            tb.partner("a@x"),
            None,
            "a mapping with no leg present for the lifetime expires"
        );
        assert_eq!(tb.partner("DLGCH_a"), None, "from either side");
        assert_eq!(
            tb.partner("b@x"),
            Some("DLGCH_b"),
            "a mapping whose leg was present restarted its clock and stays"
        );
        assert_eq!(tb.counts(|_| false).expired, 1, "the expiry is counted");
        // The slot `a` held is free again.
        assert_eq!(
            tb.insert(m("a@x", "DLGCH_a"), t(62)),
            Insert::Added,
            "an expired mapping's slot is free again"
        );
        Ok(())
    }

    #[test]
    fn pending_counts_mappings_without_both_legs() {
        let mut tb = ThMappingTable::new(10, 60);
        tb.insert(m("a@x", "DLGCH_a"), t(0));
        tb.insert(m("b@x", "DLGCH_b"), t(0));
        let c = tb.counts(|c| c == "a@x" || c == "DLGCH_a" || c == "b@x");
        assert_eq!(
            (c.held, c.pending),
            (2, 1),
            "two held, one of them without both legs captured"
        );
    }

    #[test]
    fn rfc3261_callid_shape() {
        assert!(
            is_rfc3261_callid(b"a84b4c76e66710@example.com"),
            "word@word is a Call-ID"
        );
        assert!(
            is_rfc3261_callid(b"DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-"),
            "a word alone is a Call-ID"
        );
        assert!(!is_rfc3261_callid(b""), "an empty Call-ID is not one");
        assert!(
            !is_rfc3261_callid(b"a b"),
            "a space is not a word character"
        );
        assert!(
            !is_rfc3261_callid(b"a@"),
            "an empty host part is not a word"
        );
        assert!(
            !is_rfc3261_callid(b"a@b@c"),
            "a second @ is not a word character"
        );
    }
}
