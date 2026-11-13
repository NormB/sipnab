// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet serve`: a central sipnab that fleet members report to.
//!
//! Phase P1 of the fleet center (heartbeats). Each member pushes a heartbeat
//! to `POST /v1/fleet/ingest`; the center keeps the latest one per member,
//! says which members went silent, and serves them on
//! `GET /v1/fleet/members`.
//!
//! # Who a member is
//!
//! The member is the id of the bearer token it presented, a token of scope
//! `fleet-report` the center's own signing key minted. The signature is
//! what the center verified, so that id is the one identity in the record the
//! center vouches for. Everything in the heartbeat itself (node name, build,
//! configuration, counters) is the member's own claim, and the members answer
//! keeps it under `self_reported`. Revoking a member is revoking its token id
//! in the center's revocation file.
//!
//! # What is pure and what is not
//!
//! [`parse_batch`], [`admits`], [`is_silent`] and the [`Registry`] methods
//! take their inputs, the clock included, as arguments and hold every rule:
//! what a record must carry, when a record is a replay, when a member is
//! silent, what retention removes. [`Store`] is the one type that touches
//! the store file, and [`serve`] the one function that binds a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wire-format version of an ingest record this build reads.
pub const RECORD_SCHEMA_VERSION: u64 = 1;

/// Wire-format version of the members answer.
pub const MEMBERS_SCHEMA_VERSION: u32 = 1;

/// The one record kind P1 accepts.
pub const KIND_HEARTBEAT: &str = "heartbeat";

/// The shortest heartbeat interval a record may claim, in seconds.
pub const MIN_HEARTBEAT_SECS: u64 = 1;

/// The longest heartbeat interval a record may claim, in seconds.
pub const MAX_HEARTBEAT_SECS: u64 = 3600;

/// The most records one ingest request may carry.
///
/// Not a setting: a member sends what its spool holds, one request per spool
/// file, and one file holds one heartbeat. The bound is for a client that is
/// not a sipnab member.
pub const MAX_BATCH_RECORDS: usize = 1000;

/// The largest ingest body, in bytes; a larger one is answered `413`.
///
/// Not a setting: an inventory record is a few kilobytes, so this holds a
/// full batch of them with room to spare.
pub const MAX_INGEST_BYTES: usize = 4 * 1024 * 1024;

/// The longest member id (token id) and stream id.
pub const MAX_ID_LEN: usize = 64;

/// How often the center checks for silent members and logs a change.
const SILENCE_CHECK: std::time::Duration = std::time::Duration::from_secs(1);

/// How often the center applies retention and rewrites its store.
///
/// Not a setting: retention is in hours, so a minute's delay is inside it,
/// and a rewrite costs one file of the newest record per member.
const UPKEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// One heartbeat, as a member sent it.
#[derive(Debug, Clone, PartialEq)]
pub struct Heartbeat {
    /// The member's delivery stream: a random id its spool chose once.
    pub stream: String,
    /// Its position in that stream, from 1.
    pub seq: u64,
    /// When the member wrote it, on the member's clock.
    pub sent_at: DateTime<Utc>,
    /// How often the member says it sends one.
    pub heartbeat_secs: u64,
    /// The member's inventory record (`GET /v1/inventory`), as it sent it.
    pub inventory: serde_json::Value,
    /// What the member says it did with its ended calls, when it pushes
    /// call records.
    pub calls: Option<super::fleet_calls::CallCounts>,
}

/// One call record, as a member sent it.
#[derive(Debug, Clone, PartialEq)]
pub struct CallRecord {
    /// See [`Heartbeat::stream`].
    pub stream: String,
    /// See [`Heartbeat::seq`].
    pub seq: u64,
    /// See [`Heartbeat::sent_at`].
    pub sent_at: DateTime<Utc>,
    /// What selected the call on the member: `all`, or an exception's
    /// reason.
    pub selected_by: String,
    /// The call: the member's own REST answer for the dialog.
    pub call: serde_json::Value,
}

/// One record of an ingest body.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A heartbeat.
    Heartbeat(Heartbeat),
    /// A call record.
    Call(CallRecord),
}

impl Record {
    /// The heartbeat, when the record is one.
    #[must_use]
    pub fn heartbeat(&self) -> Option<&Heartbeat> {
        match self {
            Self::Heartbeat(hb) => Some(hb),
            Self::Call(_) => None,
        }
    }

    /// The call record, when the record is one.
    #[must_use]
    pub fn call(&self) -> Option<&CallRecord> {
        match self {
            Self::Heartbeat(_) => None,
            Self::Call(call) => Some(call),
        }
    }
}

/// One ingest record on the wire.
#[derive(Debug, Deserialize)]
struct WireRecord {
    /// [`RECORD_SCHEMA_VERSION`].
    schema_version: u64,
    /// [`KIND_HEARTBEAT`].
    kind: String,
    /// See [`Heartbeat::stream`].
    stream: String,
    /// See [`Heartbeat::seq`].
    seq: u64,
    /// See [`Heartbeat::sent_at`], RFC 3339.
    sent_at: String,
    /// See [`Heartbeat::heartbeat_secs`]. A heartbeat carries it.
    heartbeat_secs: Option<u64>,
    /// See [`Heartbeat::inventory`]. A heartbeat carries it.
    inventory: Option<serde_json::Value>,
    /// See [`Heartbeat::calls`].
    calls: Option<super::fleet_calls::CallCounts>,
    /// See [`CallRecord::selected_by`]. A call record carries it.
    selected_by: Option<String>,
    /// See [`CallRecord::call`]. A call record carries it.
    call: Option<serde_json::Value>,
}

/// Parse an ingest body: one JSON record per line, blank lines ignored.
///
/// All or nothing: one bad record refuses the batch, so a member never has
/// half a batch accepted and has to find out which half.
///
/// # Errors
///
/// A body that is not UTF-8, holds no record or more than
/// [`MAX_BATCH_RECORDS`], or a record that is not JSON, names another
/// `schema_version` or `kind`, or carries a field out of its range. The
/// message names the line.
pub fn parse_batch(body: &[u8]) -> Result<Vec<Record>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not UTF-8".to_string())?;
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let n = index + 1;
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if out.len() == MAX_BATCH_RECORDS {
            return Err(format!(
                "line {n}: more than {MAX_BATCH_RECORDS} records in one batch"
            ));
        }
        let record: WireRecord =
            serde_json::from_str(raw).map_err(|e| format!("line {n}: not a record: {e}"))?;
        out.push(self::record(record).map_err(|e| format!("line {n}: {e}"))?);
    }
    if out.is_empty() {
        return Err("the batch holds no record".to_string());
    }
    Ok(out)
}

/// The heartbeats of an ingest body that holds nothing else, for tests
/// that read a heartbeat's fields.
///
/// # Errors
///
/// [`parse_batch`] refused the body, or a record is not a heartbeat.
#[cfg(test)]
pub(crate) fn parse_heartbeats(body: &[u8]) -> Result<Vec<Heartbeat>, String> {
    parse_batch(body)?
        .into_iter()
        .map(|record| match record {
            Record::Heartbeat(hb) => Ok(hb),
            Record::Call(_) => Err("a call record".to_string()),
        })
        .collect()
}

/// `record` as a heartbeat or a call record, or why it is neither. The
/// rules of a record's position are the same for both kinds.
fn record(record: WireRecord) -> Result<Record, String> {
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(format!(
            "schema_version {}; this center reads {RECORD_SCHEMA_VERSION}",
            record.schema_version
        ));
    }
    let is_call = record.kind == super::fleet_calls::KIND_CALL;
    if !is_call && record.kind != KIND_HEARTBEAT {
        return Err(format!(
            "kind {:?}; this center accepts {KIND_HEARTBEAT:?} and {:?}",
            cut(&record.kind),
            super::fleet_calls::KIND_CALL
        ));
    }
    if !is_valid_id(&record.stream) {
        return Err(format!(
            "stream must be 1 to {MAX_ID_LEN} letters, digits, '.', '_' or '-'"
        ));
    }
    if record.seq == 0 {
        return Err("seq must be 1 or more".to_string());
    }
    let sent_at = DateTime::parse_from_rfc3339(&record.sent_at)
        .map_err(|_| format!("sent_at {:?} is not an RFC 3339 time", cut(&record.sent_at)))?
        .with_timezone(&Utc);
    if is_call {
        let selected_by = record
            .selected_by
            .filter(|by| is_valid_id(by))
            .ok_or_else(|| {
                format!("selected_by must be 1 to {MAX_ID_LEN} letters, digits, '.', '_' or '-'")
            })?;
        let call = record
            .call
            .filter(serde_json::Value::is_object)
            .ok_or("call must be a JSON object")?;
        return Ok(Record::Call(CallRecord {
            stream: record.stream,
            seq: record.seq,
            sent_at,
            selected_by,
            call,
        }));
    }
    let heartbeat_secs = record
        .heartbeat_secs
        .ok_or("a heartbeat needs heartbeat_secs")?;
    if !(MIN_HEARTBEAT_SECS..=MAX_HEARTBEAT_SECS).contains(&heartbeat_secs) {
        return Err(format!(
            "heartbeat_secs {} is outside {MIN_HEARTBEAT_SECS} to {MAX_HEARTBEAT_SECS}",
            heartbeat_secs
        ));
    }
    let inventory = record
        .inventory
        .filter(serde_json::Value::is_object)
        .ok_or("inventory must be a JSON object")?;
    Ok(Record::Heartbeat(Heartbeat {
        stream: record.stream,
        seq: record.seq,
        sent_at,
        heartbeat_secs,
        inventory,
        calls: record.calls,
    }))
}

/// At most the first 64 characters of a value a client sent, for an error.
fn cut(value: &str) -> String {
    value.chars().take(MAX_ID_LEN).collect()
}

/// Whether `id` may name a member or a stream: 1 to [`MAX_ID_LEN`] ASCII
/// letters, digits, `.`, `_` or `-`.
#[must_use]
pub fn is_valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Where a member's accepted records stand: the stream, position and send
/// time of the newest one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The stream of the newest accepted record.
    pub stream: String,
    /// Its position.
    pub seq: u64,
    /// Its send time, on the member's clock.
    pub sent_at: DateTime<Utc>,
}

/// Whether a record is new for a member whose newest accepted record is at
/// `prev`.
///
/// In the same stream, a record is new when its position is past `prev`'s.
/// In another stream, when it was sent after `prev`: a member whose spool
/// was recreated starts a new stream from 1, and a replayed record of an old
/// stream was sent before the newest one. The send time is the member's
/// own clock, which is the member's claim about itself, like the rest of
/// the record; it decides only which of that member's records count.
#[must_use]
pub fn admits(prev: Option<&Cursor>, hb: &Heartbeat) -> bool {
    admits_at(prev, &hb.stream, hb.seq, hb.sent_at)
}

/// [`admits`] for any record, by its stream, position and send time.
#[must_use]
pub fn admits_at(prev: Option<&Cursor>, stream: &str, seq: u64, sent_at: DateTime<Utc>) -> bool {
    match prev {
        None => true,
        Some(prev) if prev.stream == stream => seq > prev.seq,
        Some(prev) => sent_at > prev.sent_at,
    }
}

/// A member's record after a call record at the given stream, position and
/// send time: its position moves and
/// its count of call records grows. What its heartbeats said stays: when it
/// was last heard, from where, and its inventory. A member the center has
/// no heartbeat from gets a record with none, received at `now` from `peer`.
fn after_call(
    current: Option<MemberRecord>,
    member: &str,
    peer: &str,
    now: DateTime<Utc>,
    (stream, seq, sent_at): (&str, u64, DateTime<Utc>),
) -> MemberRecord {
    let cursor = Cursor {
        stream: stream.to_string(),
        seq,
        sent_at,
    };
    let mut record = current.unwrap_or_else(|| MemberRecord {
        member: member.to_string(),
        received_at: now,
        peer: peer.to_string(),
        heartbeats: 0,
        cursor: cursor.clone(),
        heartbeat_secs: super::fleet_member::DEFAULT_HEARTBEAT_SECS,
        inventory: serde_json::json!({}),
        call_records: 0,
        calls: None,
    });
    record.cursor = cursor;
    record.call_records = record.call_records.saturating_add(1);
    record
}

/// Whether a member last heard at `last` is silent at `now`: more than
/// `missed` of its `heartbeat_secs` intervals have passed.
///
/// Measured on the center's clock at both ends, so a member's clock cannot
/// make it look alive. A `now` before `last` (the center's clock stepped
/// back) is not silence.
#[must_use]
pub fn is_silent(
    now: DateTime<Utc>,
    last: DateTime<Utc>,
    heartbeat_secs: u64,
    missed: u32,
) -> bool {
    let allowed = heartbeat_secs.saturating_mul(u64::from(missed));
    // Saturating, not panicking: a record read back from the store carries
    // whatever interval the file holds, and chrono refuses a span past its
    // range by panicking.
    let allowed = i64::try_from(allowed)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .unwrap_or(chrono::Duration::MAX);
    now.signed_duration_since(last) > allowed
}

/// One member's newest accepted heartbeat, as the store keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The member: its token's id.
    pub member: String,
    /// When the center received the heartbeat, on the center's clock.
    pub received_at: DateTime<Utc>,
    /// The address the request came from.
    pub peer: String,
    /// Heartbeats accepted from this member, this one included.
    pub heartbeats: u64,
    /// Where the member's records stand.
    pub cursor: Cursor,
    /// The interval the member claims.
    pub heartbeat_secs: u64,
    /// The member's inventory, as it sent it.
    pub inventory: serde_json::Value,
    /// Call records accepted from this member.
    #[serde(default)]
    pub call_records: u64,
    /// What the member's newest heartbeat said it did with its ended
    /// calls, when it said.
    #[serde(default)]
    pub calls: Option<super::fleet_calls::CallCounts>,
}

/// Every member's newest accepted heartbeat.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Registry {
    /// By member id.
    members: BTreeMap<String, MemberRecord>,
}

/// What one ingest request does to the registry, before it is written.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Records that are new.
    pub accepted: usize,
    /// Records already accepted, or older than the member's newest.
    pub duplicate: usize,
    /// The member's record after this request, when anything was accepted:
    /// what the store appends and the registry then holds.
    pub record: Option<MemberRecord>,
    /// The call records that are new, in order: what the intake appends.
    pub calls: Vec<CallRecord>,
    /// The member's record as it stood at each heartbeat the request
    /// added, in order: the rows the history store keeps.
    pub heartbeats: Vec<MemberRecord>,
}

/// The records the store appends for `plan`, in order: the row of each new
/// heartbeat, and then the member's newest record when a call record moved
/// it past the last heartbeat. The last one is what the registry holds.
#[must_use]
pub fn store_lines(plan: &Plan) -> Vec<&MemberRecord> {
    let mut lines: Vec<&MemberRecord> = plan.heartbeats.iter().collect();
    if let Some(record) = &plan.record
        && plan.heartbeats.last() != Some(record)
    {
        lines.push(record);
    }
    lines
}

/// One member as the members report and the heartbeat history show it:
/// what the center verified apart from what the member says about itself.
#[must_use]
pub fn member_json(r: &MemberRecord) -> serde_json::Value {
    let secs = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    serde_json::json!({
        "member": r.member,
        "verified": {
            "received_at": secs(r.received_at),
            "peer": r.peer,
            "heartbeats": r.heartbeats,
            "call_records": r.call_records,
        },
        "self_reported": {
            "stream": r.cursor.stream,
            "seq": r.cursor.seq,
            "sent_at": secs(r.cursor.sent_at),
            "heartbeat_secs": r.heartbeat_secs,
            "inventory": r.inventory,
            "calls": r.calls,
        },
    })
}

/// The heartbeat rows the center acknowledged and has not yet filed into
/// its history store, oldest first.
///
/// The rows are also in the store file, so they outlast a stop. They are
/// bounded in bytes: when a filing fails for long, the oldest rows leave
/// and are counted.
#[derive(Debug, Default)]
pub struct Waiting {
    /// The rows, each with the bytes of its line in the store file.
    rows: std::collections::VecDeque<(MemberRecord, usize)>,
    /// The bytes of the rows held.
    bytes: usize,
    /// How many rows left the front since the center started: the number
    /// of the first row held.
    first: u64,
    /// The rows the bound removed.
    removed: u64,
}

impl Waiting {
    /// Hold `record`, whose line is `bytes` long, and remove the oldest
    /// rows while more than `max_bytes` are held.
    pub fn push(&mut self, record: MemberRecord, bytes: usize, max_bytes: usize) {
        self.rows.push_back((record, bytes));
        self.bytes = self.bytes.saturating_add(bytes);
        while self.bytes > max_bytes {
            if self.leave() {
                self.removed += 1;
            }
        }
    }

    /// The oldest row leaves. Returns whether there was one.
    fn leave(&mut self) -> bool {
        let Some((_, bytes)) = self.rows.pop_front() else {
            self.bytes = 0;
            return false;
        };
        self.bytes = self.bytes.saturating_sub(bytes);
        self.first += 1;
        true
    }

    /// The rows received before `cutoff` leave: their members are past the
    /// retention, and so is the day their rows would be filed in. They are
    /// counted as removed.
    pub fn expire(&mut self, cutoff: DateTime<Utc>) {
        while self
            .rows
            .front()
            .is_some_and(|(row, _)| row.received_at < cutoff)
            && self.leave()
        {
            self.removed += 1;
        }
    }

    /// The rows held, oldest first.
    #[must_use]
    pub fn rows(&self) -> Vec<MemberRecord> {
        self.rows.iter().map(|(row, _)| row.clone()).collect()
    }

    /// The rows held and the number of the first of them, for a filing
    /// that runs while more rows arrive.
    #[must_use]
    pub fn snapshot(&self) -> (u64, Vec<MemberRecord>) {
        (self.first, self.rows())
    }

    /// Forget the `count` rows a filing took at the number `first`
    /// ([`Self::snapshot`]): those of them still held leave.
    pub fn filed(&mut self, first: u64, count: usize) {
        let end = first.saturating_add(count as u64);
        while self.first < end && self.leave() {}
    }

    /// How many rows are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no row is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The bytes of the rows held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// The rows the bound removed since the center started.
    #[must_use]
    pub fn removed(&self) -> u64 {
        self.removed
    }
}

impl Registry {
    /// The registry the store's records describe: the last record per
    /// member, in file order.
    #[must_use]
    pub fn from_records(records: Vec<MemberRecord>) -> Self {
        let mut members = BTreeMap::new();
        for record in records {
            members.insert(record.member.clone(), record);
        }
        Self { members }
    }

    /// What `batch` from `member` at `peer`, received at `now`, would change.
    ///
    /// Each record is checked against the newest accepted before it, the
    /// batch's own earlier records included, so a batch that repeats a
    /// record counts it once.
    #[must_use]
    pub fn plan(&self, member: &str, peer: &str, now: DateTime<Utc>, batch: &[Heartbeat]) -> Plan {
        let records: Vec<Record> = batch.iter().cloned().map(Record::Heartbeat).collect();
        self.plan_records(member, peer, now, &records)
    }

    /// [`Self::plan`] for a batch of heartbeats and call records. A call
    /// record moves the member's position as a heartbeat does, and is
    /// returned in [`Plan::calls`] for the intake when it is new.
    #[must_use]
    pub fn plan_records(
        &self,
        member: &str,
        peer: &str,
        now: DateTime<Utc>,
        batch: &[Record],
    ) -> Plan {
        let mut current = self.members.get(member).cloned();
        let mut accepted = 0;
        let mut duplicate = 0;
        let mut calls = Vec::new();
        let mut heartbeats = Vec::new();
        for record in batch {
            let prev = current.as_ref().map(|r| &r.cursor);
            let hb = match record {
                Record::Heartbeat(hb) if admits(prev, hb) => hb,
                Record::Call(call) if admits_at(prev, &call.stream, call.seq, call.sent_at) => {
                    accepted += 1;
                    let position = (call.stream.as_str(), call.seq, call.sent_at);
                    current = Some(after_call(current, member, peer, now, position));
                    calls.push(call.clone());
                    continue;
                }
                _ => {
                    duplicate += 1;
                    continue;
                }
            };
            accepted += 1;
            current = Some(MemberRecord {
                member: member.to_string(),
                received_at: now,
                peer: peer.to_string(),
                heartbeats: current
                    .as_ref()
                    .map_or(0, |r| r.heartbeats)
                    .saturating_add(1),
                cursor: Cursor {
                    stream: hb.stream.clone(),
                    seq: hb.seq,
                    sent_at: hb.sent_at,
                },
                heartbeat_secs: hb.heartbeat_secs,
                inventory: hb.inventory.clone(),
                call_records: current.as_ref().map_or(0, |r| r.call_records),
                calls: hb.calls,
            });
            heartbeats.extend(current.clone());
        }
        Plan {
            accepted,
            duplicate,
            record: if accepted > 0 { current } else { None },
            calls,
            heartbeats,
        }
    }

    /// Take `record`, a member's newest heartbeat read from the history
    /// store, when the registry holds nothing of that member or something
    /// older. Returns whether it was taken.
    pub fn restore(&mut self, record: MemberRecord) -> bool {
        let later = self.members.get(&record.member).is_none_or(|held| {
            (record.received_at, record.heartbeats) > (held.received_at, held.heartbeats)
        });
        if later {
            self.members.insert(record.member.clone(), record);
        }
        later
    }

    /// Note a call record the intake holds for `member`, received at
    /// `received_at`: when the member's position is before it, the position
    /// moves to it and the record is counted. Used when the center starts
    /// ([`super::fleet_intake::replay`]).
    pub fn note_stored_call(
        &mut self,
        member: &str,
        received_at: DateTime<Utc>,
        position: (&str, u64, DateTime<Utc>),
    ) {
        let current = self.members.get(member).cloned();
        let (stream, seq, sent_at) = position;
        if admits_at(current.as_ref().map(|r| &r.cursor), stream, seq, sent_at) {
            let record = after_call(current, member, "", received_at, position);
            self.members.insert(member.to_string(), record);
        }
    }

    /// Apply a plan once the store holds its record.
    pub fn commit(&mut self, plan: Plan) {
        if let Some(record) = plan.record {
            self.members.insert(record.member.clone(), record);
        }
    }

    /// Remove every member last heard before `now - retention`, and return
    /// their ids.
    pub fn expire(&mut self, now: DateTime<Utc>, retention: chrono::Duration) -> Vec<String> {
        let cutoff = now - retention;
        let gone: Vec<String> = self
            .members
            .values()
            .filter(|r| r.received_at < cutoff)
            .map(|r| r.member.clone())
            .collect();
        for member in &gone {
            self.members.remove(member);
        }
        gone
    }

    /// The members' records, by member id.
    #[must_use]
    pub fn records(&self) -> Vec<&MemberRecord> {
        self.members.values().collect()
    }

    /// The ids of the members silent at `now`.
    #[must_use]
    pub fn silent(&self, now: DateTime<Utc>, missed: u32) -> Vec<String> {
        self.members
            .values()
            .filter(|r| is_silent(now, r.received_at, r.heartbeat_secs, missed))
            .map(|r| r.member.clone())
            .collect()
    }

    /// The members answer at `now`.
    ///
    /// Each member's row keeps what the center verified (`member`, the token
    /// id; `verified`: when and from where the heartbeat arrived, and how
    /// many it accepted) apart from what the member says about itself
    /// (`self_reported`: its stream, position, send time, interval and
    /// inventory). `silent` and `seconds_since_heartbeat` are measured on the
    /// center's clock.
    #[must_use]
    pub fn report(
        &self,
        now: DateTime<Utc>,
        missed: u32,
        retention_hours: u64,
    ) -> serde_json::Value {
        let secs = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let members: Vec<serde_json::Value> = self
            .members
            .values()
            .map(|r| {
                let mut row = member_json(r);
                row["silent"] =
                    serde_json::json!(is_silent(now, r.received_at, r.heartbeat_secs, missed));
                row["seconds_since_heartbeat"] = serde_json::json!(
                    now.signed_duration_since(r.received_at)
                        .num_seconds()
                        .max(0)
                );
                row
            })
            .collect();
        serde_json::json!({
            "schema_version": MEMBERS_SCHEMA_VERSION,
            "now": secs(now),
            "silent_after_missed": missed,
            "retention_hours": retention_hours,
            "members": members,
        })
    }
}

/// The store file: every member's newest record, sealed.
///
/// The file is a sealed log ([`crate::app::fleet_seal`]): the center never
/// writes a member's inventory in clear. It is created with mode 0600 and
/// refused when other users can read it. Each append is synced before the
/// center answers, so a heartbeat the center acknowledged survives a crash,
/// and a replay of it is still recognized afterwards.
///
/// A sealed file is written by one process only. [`Store::open`] reads the
/// file and writes it again under a new data key before it returns, so a
/// data key never seals records for two processes. After an append that
/// failed, the next append does the same first
/// ([`super::fleet_log::AppendLog`]).
#[derive(Debug)]
pub struct Store {
    /// Records appended since the last rewrite.
    appended: usize,
    /// The file, open for appends.
    log: super::fleet_log::AppendLog,
}

impl Store {
    /// Open the store at `path`, creating it with mode 0600 when absent,
    /// return the records it holds, and write it again under a new data
    /// key of the current key in `keys`.
    ///
    /// A store that an earlier release wrote in clear is read and replaced
    /// by its sealed form. An append the center did not finish is dropped:
    /// it was never acknowledged.
    ///
    /// # Errors
    ///
    /// The file cannot be created, read or rewritten, other users can read
    /// it, or the sealed layer refuses it: its key is not in `keys`, it was
    /// modified or truncated, or it is not a store. The message names the
    /// path and the layer. A refused file is left as it was found.
    pub fn open(
        path: &Path,
        keys: Arc<crate::app::fleet_seal::Keys>,
    ) -> Result<(Self, Vec<MemberRecord>), String> {
        use crate::app::fleet_seal::{Kind, SealError, open_log};
        let shown = path.display();
        let bytes = match std::fs::read(path) {
            Ok(bytes) => {
                check_private(path)?;
                bytes
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("--store '{shown}': {e}")),
        };
        let records = if bytes.is_empty() {
            Vec::new()
        } else {
            match open_log(&bytes, &keys, Kind::Registry) {
                Ok(log) => {
                    if log.torn_tail {
                        tracing::warn!(
                            "--store '{shown}': the last record is incomplete, from a write \
                             the center did not finish; it is dropped"
                        );
                    }
                    sealed_records(&log.records)
                        .map_err(|why| format!("--store '{shown}': sealed layer: {why}"))?
                }
                Err(SealError::NotSealed) => {
                    let records = plaintext_records(&bytes)
                        .map_err(|why| format!("--store '{shown}': {why}"))?;
                    tracing::warn!(
                        "--store '{shown}' held {} member(s) in clear, written by a release \
                         before encryption at rest; it is sealed now",
                        records.len()
                    );
                    records
                }
                Err(e @ SealError::KeyNotLoaded(_)) => {
                    return Err(format!(
                        "--store '{shown}': sealed layer: the file {e}; give that key's file \
                         with --store-old-key-file"
                    ));
                }
                Err(e) => return Err(format!("--store '{shown}': sealed layer: the file {e}")),
            }
        };
        let log = super::fleet_log::AppendLog::create(
            path,
            keys,
            Kind::Registry,
            records.iter().map(record_line),
        )
        .map_err(|e| format!("--store '{shown}': {e}"))?;
        Ok((Self { appended: 0, log }, records))
    }

    /// Append `record` and wait until it is on disk.
    ///
    /// # Errors
    ///
    /// The record cannot be sealed, or the file cannot be opened, written
    /// or synced.
    pub fn append(&mut self, record: &MemberRecord) -> std::io::Result<()> {
        self.append_all(&[record]).map(|_| ())
    }

    /// Append `records` in order as one write, and wait until they are on
    /// disk: all of them or, after an error, none. Returns the bytes of
    /// each record's line.
    ///
    /// # Errors
    ///
    /// As [`Self::append`].
    pub fn append_all(&mut self, records: &[&MemberRecord]) -> std::io::Result<Vec<usize>> {
        let lines = records
            .iter()
            .map(|record| record_line(record))
            .collect::<std::io::Result<Vec<Vec<u8>>>>()?;
        self.log.append(&lines)?;
        self.appended += records.len();
        Ok(lines.iter().map(Vec::len).collect())
    }

    /// Rewrite the store to hold exactly `registry`'s records, sealed under
    /// a new data key, mode 0600: staged beside it and renamed over it, so a
    /// reader sees the old file or the new one.
    ///
    /// # Errors
    ///
    /// The staged file cannot be sealed, written, synced or renamed.
    pub fn compact(&mut self, registry: &Registry) -> std::io::Result<()> {
        self.compact_with(registry, &[])
    }

    /// [`Self::compact`] for a center whose history store has not yet
    /// filed the heartbeat rows `waiting`: the file holds them first and
    /// then `registry`'s records, so a start reads the rows again and still
    /// finds each member's newest record last.
    ///
    /// # Errors
    ///
    /// As [`Self::compact`].
    pub fn compact_with(
        &mut self,
        registry: &Registry,
        waiting: &[MemberRecord],
    ) -> std::io::Result<()> {
        self.log
            .rewrite(waiting.iter().chain(registry.records()).map(record_line))?;
        self.appended = 0;
        Ok(())
    }

    /// Lines appended since the last rewrite.
    #[must_use]
    pub fn appended(&self) -> usize {
        self.appended
    }

    /// The file, for a test that makes its appends fail.
    #[cfg(test)]
    fn log_mut(&mut self) -> &mut super::fleet_log::AppendLog {
        &mut self.log
    }
}

/// The line that stores `record` in the store file.
fn record_line(record: &MemberRecord) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(record).map_err(std::io::Error::other)
}

/// Write the sealed file of `kind` at `path` holding exactly `records`,
/// with the read of the staged file as an argument: `read` returns what the
/// disk holds at the staged path, and the file at `path` is replaced only
/// when those bytes open and hold every record.
///
/// # Errors
///
/// A record is an error, or the staged file cannot be sealed, written,
/// synced, read back or renamed. The file at `path` is then as it was.
pub(super) fn write_sealed_reading(
    path: &Path,
    keys: &crate::app::fleet_seal::Keys,
    kind: crate::app::fleet_seal::Kind,
    records: impl Iterator<Item = std::io::Result<Vec<u8>>>,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<crate::app::fleet_seal::LogSealer> {
    use crate::app::fleet_seal::{LogSealer, system_draw};
    let name = path
        .file_name()
        .map_or_else(|| "store".into(), |n| n.to_string_lossy().into_owned());
    let staged = path.with_file_name(format!(".{name}.partial"));
    let _ = std::fs::remove_file(&staged);
    let result = (|| {
        let (mut sealer, header) =
            LogSealer::new(keys.current(), kind, &system_draw).map_err(std::io::Error::other)?;
        let mut file = create_private(&staged)?;
        file.write_all(&header)?;
        let mut count = 0usize;
        for record in records {
            file.write_all(&sealer.record(&record?).map_err(std::io::Error::other)?)?;
            count += 1;
        }
        file.write_all(&sealer.base_end().map_err(std::io::Error::other)?)?;
        file.sync_all()?;
        // The file, which may still be a store an earlier release wrote in
        // clear, is replaced only by one that is on disk and reads back.
        staged_reads_back(&read(&staged)?, keys, kind, count)?;
        std::fs::rename(&staged, path)?;
        Ok(sealer)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Check that the staged bytes of a rewrite open under `keys` as a file of
/// `kind` and hold `count` records, before the staged file replaces the
/// file it rewrites.
///
/// # Errors
///
/// The bytes do not open as a sealed file of that kind, or hold another
/// number of records.
fn staged_reads_back(
    bytes: &[u8],
    keys: &crate::app::fleet_seal::Keys,
    kind: crate::app::fleet_seal::Kind,
    count: usize,
) -> std::io::Result<()> {
    let log = crate::app::fleet_seal::open_log(bytes, keys, kind)
        .map_err(|e| std::io::Error::other(format!("the staged store {e}")))?;
    if log.records.len() != count || log.torn_tail {
        return Err(std::io::Error::other(format!(
            "the staged store holds {} record(s), not the {count} written",
            log.records.len()
        )));
    }
    Ok(())
}

/// The member records a sealed store's records hold.
fn sealed_records(records: &[Vec<u8>]) -> Result<Vec<MemberRecord>, String> {
    records
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            serde_json::from_slice::<MemberRecord>(bytes)
                .map_err(|e| format!("record {} is not a member record: {e}", index + 1))
        })
        .collect()
}

/// The member records of a store an earlier release wrote in clear, one
/// JSON line each. A last line that does not parse is dropped: it is a
/// write that release did not finish, and so never acknowledged.
fn plaintext_records(bytes: &[u8]) -> Result<Vec<MemberRecord>, String> {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let mut records = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<MemberRecord>(line) {
            Ok(record) => records.push(record),
            Err(_) if index + 1 == lines.len() => {
                tracing::warn!(
                    "the store's line {} is incomplete, from a write the center did not \
                     finish; it is dropped",
                    index + 1
                );
            }
            Err(e) => {
                return Err(format!("line {} is not a member record: {e}", index + 1));
            }
        }
    }
    Ok(records)
}

/// Create `path` new, readable and writable by this user only.
pub(super) fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuse a store other users can read, by the rule every private file
/// sipnab reads follows ([`crate::privilege::permission_refusal`]).
fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta =
            std::fs::metadata(path).map_err(|e| format!("--store '{}': {e}", path.display()))?;
        if let Some(why) = crate::privilege::permission_refusal(
            meta.uid(),
            crate::privilege::current_uid(),
            meta.mode(),
            meta.file_type().is_file(),
        ) {
            return Err(format!("--store '{}' {why}", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The refusal for serving plain HTTP on `addr`, or `None`.
///
/// Members send their inventory and their bearer token to the center, so
/// the center serves HTTPS, except on a loopback address, where nothing
/// crosses a network.
#[must_use]
pub fn plain_http_refusal(addr: std::net::SocketAddr, tls: bool) -> Option<String> {
    if tls || addr.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "--listen {addr} without --tls-cert and --tls-key would take members' tokens and \
         inventories in plain HTTP; plain HTTP is refused except on loopback"
    ))
}

/// What the center's client-certificate refusals call its flags.
const FLEET_CLIENT_AUTH_LABELS: crate::cli::ClientAuthLabels<'static> =
    crate::cli::ClientAuthLabels {
        ca: "--tls-client-ca",
        mode: "--tls-client-auth",
        first: "--tls-cert",
        second: "--tls-key",
    };

/// What `sipnab fleet serve` was asked for.
#[derive(Debug, Clone)]
pub struct ServeArgs {
    /// `--listen`: the address to serve on.
    pub listen: String,
    /// `--store`: the store file.
    pub store: PathBuf,
    /// `--store-key-file`: the key the store is encrypted under.
    pub store_key_file: Option<PathBuf>,
    /// `--store-old-key-file`: earlier keys the store may still be under.
    pub store_old_key_files: Vec<PathBuf>,
    /// `--store-encryption`: how the store is encrypted.
    pub store_encryption: crate::app::fleet_seal::Encryption,
    /// `--signing-key-file`: the key member and reader tokens are minted with.
    pub signing_key_file: PathBuf,
    /// `--revoked-file`: token ids no longer accepted, one per line.
    pub revoked_file: Option<PathBuf>,
    /// `--tls-cert`.
    pub tls_cert: Option<String>,
    /// `--tls-key`.
    pub tls_key: Option<String>,
    /// `--tls-client-ca` and `--tls-client-auth`: the member certificates
    /// the HTTPS handshake asks for.
    pub client_auth: crate::config::ClientCertAuth,
    /// `--retention-hours`: how long a member nobody heard from is kept.
    pub retention_hours: u64,
    /// `--silent-after-missed`: how many heartbeat intervals make a member
    /// silent.
    pub silent_after_missed: u32,
    /// `--allowed-host`: `Host` values served beyond loopback and the bound
    /// address.
    pub allowed_hosts: Vec<String>,
    /// `--rate-limit-per-peer`: requests per second per address; 0 is off.
    pub rate_limit_per_peer: u32,
    /// `--calls-retention-days`: the days of call records the history
    /// store keeps.
    pub calls_retention_days: u32,
    /// `--calls-flush-secs`: how often the intake is filed into the
    /// history store.
    pub calls_flush_secs: u64,
}

/// What a build without the `fleet-store` feature says where a build with
/// it keeps call history: at start, and on `GET /v1/fleet/calls`.
pub const NO_HISTORY_STORE: &str = "this build has no history store (cargo feature \
    fleet-store): call records wait in the intake, which holds at most 64 MiB and \
    --retention-hours of them, no heartbeat history is kept, and GET /v1/fleet/calls and \
    GET /v1/fleet/members/{id}/history answer 501. The gnu tarballs, the \
    .deb and .rpm packages that are not -noaudio, the macOS builds and the container image \
    have the history store; the static musl tarballs and the -noaudio packages do not";

/// Whether this build has the history store.
pub const HAS_HISTORY_STORE: bool = cfg!(feature = "fleet-store");

/// What the center filed into its history store since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FilingCounts {
    /// The files written.
    pub files_written: u64,
    /// The call records in them.
    pub rows_filed: u64,
    /// The filings that failed; the records stayed in the intake, the
    /// heartbeat rows stayed waiting.
    pub failed: u64,
    /// The files of heartbeats written.
    pub heartbeat_files: u64,
    /// The heartbeats in them.
    pub heartbeats_filed: u64,
    /// The members the start took from the history store because the
    /// store file held nothing of them, or something older.
    pub members_restored: u64,
}

/// The bytes of heartbeat rows that wait for a filing at most: the bound
/// the intake has for call records.
pub const MAX_WAITING_BYTES: usize = 64 * 1024 * 1024;

/// The center a running `sipnab fleet serve` holds.
struct Center {
    /// The members.
    registry: Registry,
    /// The store file.
    store: Store,
    /// The call records the center acknowledged.
    intake: super::fleet_intake::Intake,
    /// The history store the intake is filed into.
    #[cfg(feature = "fleet-store")]
    history: super::fleet_history::History,
    /// What was filed since the center started.
    filing: FilingCounts,
    /// The heartbeat rows the history store has not yet filed. A build
    /// without the history store holds none.
    waiting: Waiting,
}

impl Center {
    /// The center whose store is the file `store`, with its intake beside
    /// it, as both stand at `now`: members and call records past
    /// `retention` are removed, and each member's position is past the
    /// call records the intake holds. Returns the center and the members
    /// removed.
    ///
    /// # Errors
    ///
    /// The store or the intake is refused or cannot be rewritten. The
    /// message names the file.
    fn open(
        store: &Path,
        keys: Arc<crate::app::fleet_seal::Keys>,
        now: DateTime<Utc>,
        retention: chrono::Duration,
    ) -> Result<(Self, Vec<String>), String> {
        use super::fleet_intake::{Intake, MAX_INTAKE_BYTES, path_for, replay};
        let (mut file, records) = Store::open(store, Arc::clone(&keys))?;
        let mut registry = Registry::from_records(records.clone());
        #[cfg(not(feature = "fleet-store"))]
        let filing = FilingCounts::default();
        #[cfg(feature = "fleet-store")]
        let history = super::fleet_history::History::open(store, Arc::clone(&keys))?;
        #[cfg(feature = "fleet-store")]
        let filing = FilingCounts {
            members_restored: restore_from_history(&history, &mut registry, now, retention),
            ..FilingCounts::default()
        };
        let gone = registry.expire(now, retention);
        let (intake, stored) =
            Intake::open(&path_for(store), keys, now, retention, MAX_INTAKE_BYTES)?;
        replay(&mut registry, &stored);
        // Every heartbeat the store file held may be one no history file
        // holds: the center may have stopped before it filed them. They
        // wait again; a filing leaves out the rows a file already holds.
        // A record a call record moved is the heartbeat before it, once.
        let mut waiting = Waiting::default();
        let mut seen = BTreeSet::new();
        if HAS_HISTORY_STORE {
            for record in records {
                let is_row = record.heartbeats > 0
                    && record.received_at >= now - retention
                    && seen.insert((record.member.clone(), record.heartbeats, record.received_at));
                if is_row {
                    let bytes = record_line(&record).map_or(0, |line| line.len());
                    waiting.push(record, bytes, MAX_WAITING_BYTES);
                }
            }
        }
        file.compact_with(&registry, &waiting.rows())
            .map_err(|e| format!("--store '{}': {e}", store.display()))?;
        Ok((
            Self {
                registry,
                store: file,
                intake,
                #[cfg(feature = "fleet-store")]
                history,
                filing,
                waiting,
            },
            gone,
        ))
    }

    /// File the heartbeat rows that wait into the history store of the
    /// center behind `center`. The lock is held to take the rows and to
    /// forget them, not while the files are written, so requests are
    /// answered during a filing; rows that arrive meanwhile stay waiting.
    /// `gate` is held throughout: one filing of heartbeats runs at a time.
    ///
    /// # Errors
    ///
    /// The history store cannot be written. The rows then stay waiting,
    /// and the failure is counted.
    #[cfg(feature = "fleet-store")]
    fn file_heartbeats(
        center: &parking_lot::Mutex<Self>,
        gate: &parking_lot::Mutex<()>,
    ) -> Result<super::fleet_history::Filed, String> {
        let _one_at_a_time = gate.lock();
        let (history, first, rows) = {
            let center = center.lock();
            let (first, rows) = center.waiting.snapshot();
            (center.history.clone(), first, rows)
        };
        if rows.is_empty() {
            return Ok(super::fleet_history::Filed::default());
        }
        let filed = history.file(&rows);
        let mut center = center.lock();
        match &filed {
            Ok(filed) => {
                center.waiting.filed(first, rows.len());
                let counts = &mut center.filing;
                counts.heartbeat_files = counts.heartbeat_files.saturating_add(filed.files as u64);
                counts.heartbeats_filed = counts.heartbeats_filed.saturating_add(filed.rows as u64);
            }
            Err(_) => center.filing.failed = center.filing.failed.saturating_add(1),
        }
        filed
    }

    /// File every call record the intake holds into the history store,
    /// and then empty the intake. Returns what was filed.
    ///
    /// A stop between the two leaves the records in both; the next filing
    /// leaves out the rows a file already holds
    /// ([`super::fleet_history::History::file`]).
    ///
    /// # Errors
    ///
    /// The intake cannot be read or emptied, or the history store cannot
    /// be written. The records then stay in the intake, and the failure is
    /// counted.
    #[cfg(feature = "fleet-store")]
    fn file_calls(&mut self) -> Result<super::fleet_history::Filed, String> {
        if self.intake.records() == 0 {
            return Ok(super::fleet_history::Filed::default());
        }
        let filed = self
            .intake
            .rows()
            .and_then(|rows| self.history.file(&rows))
            .and_then(|filed| self.intake.clear().map(|_| filed));
        match &filed {
            Ok(filed) => {
                self.filing.files_written =
                    self.filing.files_written.saturating_add(filed.files as u64);
                self.filing.rows_filed = self.filing.rows_filed.saturating_add(filed.rows as u64);
            }
            Err(_) => self.filing.failed = self.filing.failed.saturating_add(1),
        }
        filed
    }

    /// Take `batch` from `member` at `peer`, received at `now`: the new
    /// call records go to the intake and the member's record to the store,
    /// each on disk before this returns, and then the registry holds what
    /// the files hold. Returns the records accepted, the duplicates, and
    /// the call records stored.
    ///
    /// # Errors
    ///
    /// The intake or the store could not be written. When the intake could
    /// not, the registry is unchanged, so the member's next try is taken as
    /// new. When the intake took the call records and the store then
    /// failed, the registry moves the member's position past those records
    /// and no further, as a start after a stop at that point does
    /// ([`super::fleet_intake::replay`]): the next try stores none of them
    /// twice.
    fn take(
        &mut self,
        member: &str,
        peer: &str,
        now: DateTime<Utc>,
        batch: &[Record],
    ) -> std::io::Result<(usize, usize, usize)> {
        let mut plan = self.registry.plan_records(member, peer, now, batch);
        // The intake first: a record it holds is a duplicate after a
        // restart whether or not the store got the position.
        let calls: Vec<super::fleet_intake::IntakeRecord> = std::mem::take(&mut plan.calls)
            .into_iter()
            .map(|call| super::fleet_intake::IntakeRecord::new(member, now, call))
            .collect();
        self.intake.append(&calls)?;
        let sizes = match self.store.append_all(&store_lines(&plan)) {
            Ok(sizes) => sizes,
            Err(e) => {
                // The intake holds the call records. As after a stop at
                // this point, the member's position moves past them, so
                // its next try does not put them in the intake a second
                // time.
                super::fleet_intake::replay(&mut self.registry, &calls);
                return Err(e);
            }
        };
        let counts = (plan.accepted, plan.duplicate, calls.len());
        if HAS_HISTORY_STORE {
            // The store file holds each heartbeat's row first, in order.
            for (row, bytes) in std::mem::take(&mut plan.heartbeats).into_iter().zip(sizes) {
                self.waiting.push(row, bytes, MAX_WAITING_BYTES);
            }
        }
        self.registry.commit(plan);
        Ok(counts)
    }
}

/// What every request handler shares.
#[derive(Clone)]
struct CenterState {
    /// The members and the store, behind one lock: a heartbeat is written
    /// and applied as one step.
    center: Arc<parking_lot::Mutex<Center>>,
    /// Verifies member and reader tokens.
    verifier: Arc<crate::auth::TokenVerifier>,
    /// Requests per second per address.
    limiter: Arc<parking_lot::Mutex<crate::output::api::RateLimiter>>,
    /// `--silent-after-missed`.
    missed: u32,
    /// `--retention-hours`.
    retention_hours: u64,
    /// `--calls-retention-days`.
    calls_retention_days: u32,
    /// `--calls-flush-secs`. A build without the history store files
    /// nothing and does not read it.
    #[cfg(feature = "fleet-store")]
    calls_flush: std::time::Duration,
    /// Held while heartbeat rows are filed: the upkeep task and the stop
    /// do not file the same rows at once.
    #[cfg(feature = "fleet-store")]
    filing: Arc<parking_lot::Mutex<()>>,
}

/// The most peers the rate limiter tracks.
const MAX_TRACKED_PEERS: usize = 4096;

/// Run `sipnab fleet serve` until SIGINT or SIGTERM. Returns the exit code:
/// 0 when stopped, 2 when the arguments, the key, the store or the listener
/// are refused.
///
/// # Side effects
///
/// Reads the signing key, opens and rewrites the store, binds the listener,
/// serves until stopped, and logs.
pub fn serve(args: ServeArgs) -> i32 {
    match prepare(&args) {
        Ok((addr, state, server_config)) => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    stderr_line!("sipnab fleet serve: the runtime did not start: {e}");
                    return 2;
                }
            };
            runtime.block_on(run(addr, state, server_config))
        }
        Err(e) => {
            stderr_line!("sipnab fleet serve: {e}");
            2
        }
    }
}

/// Check the arguments, read the key, open the store and apply retention.
fn prepare(
    args: &ServeArgs,
) -> Result<
    (
        std::net::SocketAddr,
        CenterState,
        crate::output::api::ApiServerConfig,
    ),
    String,
> {
    use std::io::Read as _;
    let addr = crate::output::api::parse_bind_addr(&args.listen)
        .map_err(|e| format!("--listen {}: {e}", args.listen))?;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => return Err("--tls-cert and --tls-key go together".to_string()),
    };
    if let Some(refusal) = plain_http_refusal(addr, tls) {
        return Err(refusal);
    }
    crate::cli::client_auth_problem(FLEET_CLIENT_AUTH_LABELS, &args.client_auth, tls)?;
    let mut key = String::new();
    crate::privilege::open_private_file(&args.signing_key_file, "--signing-key-file")?
        .read_to_string(&mut key)
        .map_err(|e| {
            format!(
                "--signing-key-file '{}': {e}",
                args.signing_key_file.display()
            )
        })?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!(
            "--signing-key-file '{}' is empty",
            args.signing_key_file.display()
        ));
    }
    let verifier = crate::auth::TokenVerifier::new(crate::auth::VerifierConfig {
        signing_keys: vec![key.as_bytes().to_vec()],
        static_keys: Vec::new(),
        revoked_file: args.revoked_file.clone(),
        audience: crate::auth::AUDIENCE_API.to_string(),
    });
    let keys = store_keys(args)?;
    let (center, gone) = Center::open(
        &args.store,
        keys,
        Utc::now(),
        retention(args.retention_hours),
    )?;
    let center = Arc::new(parking_lot::Mutex::new(center));
    start_history(&center, args.calls_retention_days, args.retention_hours);
    {
        let center = center.lock();
        tracing::info!(
            "fleet center store '{}': {} member(s), {} past --retention-hours {} removed; {} \
             call record(s) in its intake",
            args.store.display(),
            center.registry.records().len(),
            gone.len(),
            args.retention_hours,
            center.intake.records()
        );
    }
    let state = CenterState {
        center,
        verifier: Arc::new(verifier),
        limiter: Arc::new(parking_lot::Mutex::new(
            crate::output::api::RateLimiter::new(args.rate_limit_per_peer, MAX_TRACKED_PEERS),
        )),
        missed: args.silent_after_missed,
        retention_hours: args.retention_hours,
        calls_retention_days: args.calls_retention_days,
        #[cfg(feature = "fleet-store")]
        calls_flush: std::time::Duration::from_secs(args.calls_flush_secs),
        #[cfg(feature = "fleet-store")]
        filing: Arc::new(parking_lot::Mutex::new(())),
    };
    let server_config = crate::output::api::ApiServerConfig {
        max_conn: 0,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        client_auth: args.client_auth.clone(),
        allowed_hosts: args.allowed_hosts.clone(),
        // The fleet center serves its own routes, not the capture API's.
        console: false,
    };
    Ok((addr, state, server_config))
}

/// As the center starts: file what the intake and the store file held
/// when it last stopped and remove the days past `retention_days` of call
/// records and `retention_hours` of heartbeats, logging each. A build
/// without the history store says so instead, once.
fn start_history(center: &parking_lot::Mutex<Center>, retention_days: u32, retention_hours: u64) {
    #[cfg(feature = "fleet-store")]
    {
        {
            let mut center = center.lock();
            tracing::info!(
                "fleet center history store '{}': call records are kept {retention_days} \
                 day(s), heartbeats {retention_hours} hour(s)",
                center.history.dir().display()
            );
            file_and_log(&mut center);
            expire_history(&center, Utc::now(), retention_days, retention_hours);
        }
        file_heartbeats_and_log(center, &parking_lot::Mutex::new(()));
    }
    #[cfg(not(feature = "fleet-store"))]
    {
        let _ = (center, retention_days, retention_hours);
        tracing::warn!("fleet center: {NO_HISTORY_STORE}");
    }
}

/// File the heartbeat rows that wait and log what was filed, or why it
/// was not.
#[cfg(feature = "fleet-store")]
fn file_heartbeats_and_log(center: &parking_lot::Mutex<Center>, gate: &parking_lot::Mutex<()>) {
    match Center::file_heartbeats(center, gate) {
        Ok(filed) if filed.rows > 0 => tracing::debug!(
            "fleet center: filed {} heartbeat(s) in {} file(s) of the history store",
            filed.rows,
            filed.files
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            "fleet center: the heartbeats were not filed and wait in the store file: {e}"
        ),
    }
}

/// The newest heartbeat the history store holds of each member the
/// registry holds nothing of, or something older, goes into `registry`,
/// with the member's position moved past the call records the store filed
/// after that heartbeat. Returns how many members were taken. A file that
/// cannot be read is logged and restores nothing.
#[cfg(feature = "fleet-store")]
fn restore_from_history(
    history: &super::fleet_history::History,
    registry: &mut Registry,
    now: DateTime<Utc>,
    retention: chrono::Duration,
) -> u64 {
    let unread = |file: &str, why: &str| {
        tracing::warn!(
            "fleet center: the history store: {file} was not read for the member registry: {why}"
        );
    };
    let known: BTreeMap<String, DateTime<Utc>> = registry
        .records()
        .iter()
        .map(|r| (r.member.clone(), r.received_at))
        .collect();
    let oldest = super::fleet_history::oldest_kept_at(now, retention);
    let Some(found) = newest_in_history(history, oldest, &known, &unread) else {
        return 0;
    };
    // The members taken, each with the receive time of its heartbeat: the
    // call records the store filed after it are read in one pass.
    let mut since = BTreeMap::new();
    for record in found.members {
        let (member, at) = (record.member.clone(), record.received_at);
        if registry.restore(record) {
            since.insert(member, at);
        }
    }
    let restored = since.len() as u64;
    move_past_filed_calls(history, registry, &since, &unread);
    if restored > 0 {
        tracing::info!(
            "fleet center: {restored} member(s) the store file held nothing of, or an older \
             heartbeat of, were taken from the history store"
        );
    }
    restored
}

/// The newest heartbeats the history store holds for a registry that
/// `known` describes, from the days from `oldest` on
/// ([`super::fleet_history::History::newest_heartbeats`]), or nothing when
/// the store's directories cannot be read. A file that cannot be read goes
/// to `unread` with the reason, and files left unread at the bound are
/// logged.
#[cfg(feature = "fleet-store")]
fn newest_in_history(
    history: &super::fleet_history::History,
    oldest: chrono::NaiveDate,
    known: &BTreeMap<String, DateTime<Utc>>,
    unread: &dyn Fn(&str, &str),
) -> Option<super::fleet_history::Restored> {
    let found = match history.newest_heartbeats(
        oldest,
        known,
        super::fleet_history::MAX_FILES_PER_QUESTION,
    ) {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!("fleet center: the member registry was not checked against {e}");
            return None;
        }
    };
    for (file, why) in &found.refused {
        unread(file, why);
    }
    if found.files_not_read > 0 {
        tracing::warn!(
            "fleet center: the member registry was rebuilt from the newest {} file(s) of \
             heartbeats; {} older file(s) were not read",
            found.files_read,
            found.files_not_read
        );
    }
    Some(found)
}

/// Move the position of each member of `since`, a member the start took
/// from the heartbeat history, past the call records the history store
/// filed at or after that member's instant, so a record the member sends
/// again is a duplicate. The files are read in one pass for all of them. A
/// file that cannot be read goes to `unread` with the reason.
#[cfg(feature = "fleet-store")]
fn move_past_filed_calls(
    history: &super::fleet_history::History,
    registry: &mut Registry,
    since: &BTreeMap<String, DateTime<Utc>>,
    unread: &dyn Fn(&str, &str),
) {
    let restored = since.len();
    match history.calls_after(since, super::fleet_history::MAX_FILES_PER_QUESTION) {
        Ok(calls) => {
            super::fleet_intake::replay(registry, &calls.rows);
            for (file, why) in &calls.refused {
                unread(file, why);
            }
            if calls.files_not_read > 0 {
                tracing::warn!(
                    "fleet center: the positions of {restored} restored member(s) were moved \
                     past the call records of the newest {} file(s); {} older file(s) were not \
                     read",
                    calls.files_read,
                    calls.files_not_read
                );
            }
        }
        Err(e) => unread("the call records of the restored members", &e),
    }
}

/// File the intake into the history store and log what was filed, or why
/// it was not.
#[cfg(feature = "fleet-store")]
fn file_and_log(center: &mut Center) {
    match center.file_calls() {
        Ok(filed) if filed.rows > 0 || filed.already > 0 => tracing::info!(
            "fleet center: filed {} call record(s) in {} file(s) of the history store; {} \
             were in it already",
            filed.rows,
            filed.files,
            filed.already
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            "fleet center: the call records were not filed and stay in the intake: {e}"
        ),
    }
}

/// Remove the days of call records past `retention_days` and the days of
/// heartbeats past `retention_hours` at `now` from the history store, and
/// log what went and what was left.
#[cfg(feature = "fleet-store")]
fn expire_history(center: &Center, now: DateTime<Utc>, retention_days: u32, retention_hours: u64) {
    use super::fleet_history::{CLASS_CALLS, CLASS_MEMBERS, oldest_kept_at};
    let calls = center
        .history
        .expire(CLASS_CALLS, now.date_naive(), retention_days);
    let past = format!("--calls-retention-days {retention_days}");
    log_expired(calls, "call records", &past);
    let oldest = oldest_kept_at(now, retention(retention_hours));
    let heartbeats = center.history.expire_before(CLASS_MEMBERS, oldest);
    let past = format!("--retention-hours {retention_hours}");
    log_expired(heartbeats, "heartbeats", &past);
}

/// Log what a retention pass removed of `what` past the setting `past`,
/// and what it left.
#[cfg(feature = "fleet-store")]
fn log_expired(done: Result<super::fleet_history::Expired, String>, what: &str, past: &str) {
    match done {
        Ok(expired) => {
            if expired.days > 0 || expired.files > 0 {
                tracing::info!(
                    "fleet center: {} day(s) and {} file(s) of {what} past {past} were removed",
                    expired.days,
                    expired.files
                );
            }
            for left in &expired.left {
                tracing::warn!("fleet center: past {past} and not removed: {left}");
            }
        }
        Err(e) => tracing::warn!("fleet center: retention of the history store: {e}"),
    }
}

/// The keys `sipnab fleet serve` encrypts its store with, read from the
/// files the arguments name.
///
/// # Errors
///
/// `--store-encryption` names a value this build cannot run, no
/// `--store-key-file` was given, or a key file is refused. The center
/// stores nothing in clear, so it does not start without a key.
fn store_keys(args: &ServeArgs) -> Result<Arc<crate::app::fleet_seal::Keys>, String> {
    use crate::app::fleet_seal::{Keys, read_key_file};
    if let Some(why) = args.store_encryption.unavailable() {
        return Err(why);
    }
    let file = args.store_key_file.as_ref().ok_or(
        "--store-key-file is required: the center encrypts everything it stores. Create a \
         key with `sipnab fleet keygen --out FILE` and pass --store-key-file FILE",
    )?;
    let current = read_key_file(file, "--store-key-file")?;
    let old = args
        .store_old_key_files
        .iter()
        .map(|file| read_key_file(file, "--store-old-key-file"))
        .collect::<Result<Vec<_>, _>>()?;
    tracing::info!(
        "fleet center store encryption {}, key id {}, {} old key(s)",
        args.store_encryption.as_str(),
        current.id(),
        old.len()
    );
    Ok(Arc::new(Keys::new(current, old)))
}

/// `--retention-hours` as a duration.
fn retention(hours: u64) -> chrono::Duration {
    chrono::Duration::hours(i64::try_from(hours).unwrap_or(i64::MAX / 3600))
}

/// Bind, serve, keep the store, and stop on SIGINT or SIGTERM.
async fn run(
    addr: std::net::SocketAddr,
    state: CenterState,
    server_config: crate::output::api::ApiServerConfig,
) -> i32 {
    let (listener, router) = match bind(addr, &state, &server_config) {
        Ok(bound) => bound,
        Err(e) => {
            stderr_line!("sipnab fleet serve: {e}");
            return 2;
        }
    };
    tokio::spawn(upkeep(state.clone()));
    let code = serve_until_stopped(listener, router).await;
    rewrite_on_exit(&state);
    code
}

/// Bind the listener and build the router behind the `Host` allowlist.
fn bind(
    addr: std::net::SocketAddr,
    state: &CenterState,
    server_config: &crate::output::api::ApiServerConfig,
) -> Result<(crate::output::api::ApiListener, axum::Router), crate::Error> {
    let listener = crate::output::api::prepare_listener(addr, &state.verifier, server_config)?;
    let bound = listener.local_addr().unwrap_or(addr);
    let hosts = crate::host_allowlist::HostAllowlist::new(bound, &server_config.allowed_hosts);
    let router = crate::output::api::with_host_allowlist(router(state.clone()), hosts);
    tracing::info!(
        "fleet center serving {} on {bound}",
        if listener.is_tls() { "HTTPS" } else { "HTTP" }
    );
    Ok((listener, router))
}

/// Serve until the server fails (2) or a stop is asked for (0).
async fn serve_until_stopped(
    listener: crate::output::api::ApiListener,
    router: axum::Router,
) -> i32 {
    tokio::select! {
        served = crate::output::api::serve_router(listener, router) => match served {
            Ok(()) => 0,
            Err(e) => {
                stderr_line!("sipnab fleet serve: {e}");
                2
            }
        },
        () = stop_requested() => {
            tracing::info!("fleet center stopping: a stop was asked for");
            0
        }
    }
}

/// Resolves on SIGINT, or SIGTERM where there is one.
async fn stop_requested() {
    #[cfg(unix)]
    {
        let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Rewrite the store once more as the center stops.
fn rewrite_on_exit(state: &CenterState) {
    #[cfg(feature = "fleet-store")]
    {
        file_and_log(&mut state.center.lock());
        file_heartbeats_and_log(&state.center, &state.filing);
    }
    let mut center = state.center.lock();
    let Center {
        registry,
        store,
        waiting,
        ..
    } = &mut *center;
    if let Err(e) = store.compact_with(registry, &waiting.rows()) {
        tracing::warn!("fleet center: the store was not rewritten on the way out: {e}");
    }
}

/// The center's routes.
fn router(state: CenterState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/fleet/ingest", post(ingest))
        .route("/v1/fleet/members", get(members))
        .route("/v1/fleet/members/{id}/history", get(member_history))
        .route("/v1/fleet/calls", get(calls))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_INGEST_BYTES))
        .with_state(state)
}

/// Charge `peer` to the rate limit: `503` when over it, before any
/// credential is looked at, as the REST API does.
fn limit(state: &CenterState, peer: std::net::IpAddr) -> Result<(), crate::output::api::Problem> {
    if state.limiter.lock().check(peer) {
        Ok(())
    } else {
        Err(crate::output::api::Problem::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ))
    }
}

/// `POST /v1/fleet/ingest`: a member's heartbeats.
///
/// `401` without a `fleet-report` token, `403` for one whose id cannot name
/// a member, `400` for a batch that does not parse, `413` past
/// [`MAX_INGEST_BYTES`], `503` over the rate limit or when the store cannot
/// be written; else `200` with how many records were new and how many were
/// replays.
async fn ingest(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    use crate::output::api::Problem;
    use axum::http::StatusCode;
    limit(&state, peer.ip())?;
    let token = crate::output::api::verify_bearer(
        &state.verifier,
        &headers,
        crate::auth::SCOPE_FLEET_REPORT,
    )?;
    let member = token.id.filter(|id| is_valid_id(id)).ok_or_else(|| {
        Problem::detailed(
            StatusCode::FORBIDDEN,
            format!(
                "the token's id names no member: mint it with --token-id of 1 to {MAX_ID_LEN} \
                 letters, digits, '.', '_' or '-'"
            ),
        )
    })?;
    let batch = parse_batch(&body).map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e))?;
    let now = Utc::now();
    let peer = peer.ip().to_canonical().to_string();
    let center = Arc::clone(&state.center);
    let who = member.clone();
    let done = tokio::task::spawn_blocking(move || center.lock().take(&who, &peer, now, &batch))
        .await
        .map_err(|_| Problem::new(StatusCode::INTERNAL_SERVER_ERROR))?;
    let (accepted, duplicate, calls) = done.map_err(|e| {
        tracing::error!("fleet center: the store could not be written: {e}");
        Problem::detailed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the center could not write its store; send the batch again",
        )
    })?;
    Ok(axum::Json(serde_json::json!({
        "member": member,
        "accepted": accepted,
        "duplicate": duplicate,
        "calls": calls,
    })))
}

/// `GET /v1/fleet/members`: every member, its health and its heartbeat.
/// Needs scope `inventory` (or `full`, `actions`, `admin`).
async fn members(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    limit(&state, peer.ip())?;
    crate::output::api::verify_bearer(&state.verifier, &headers, crate::auth::SCOPE_INVENTORY)?;
    let center = state.center.lock();
    let mut report = center
        .registry
        .report(Utc::now(), state.missed, state.retention_hours);
    report["intake"] = serde_json::json!({
        "call_records": center.intake.records(),
        "bytes": center.intake.bytes(),
        "removed": center.intake.dropped(),
    });
    report["history"] = serde_json::json!({
        "available": HAS_HISTORY_STORE,
        "retention_days": state.calls_retention_days,
        "files_written": center.filing.files_written,
        "rows_filed": center.filing.rows_filed,
        "failed_filings": center.filing.failed,
        "heartbeat_files_written": center.filing.heartbeat_files,
        "heartbeats_filed": center.filing.heartbeats_filed,
        "heartbeats_waiting": center.waiting.len(),
        "heartbeats_removed": center.waiting.removed(),
        "members_restored": center.filing.members_restored,
    });
    Ok(axum::Json(report))
}

/// `GET /v1/fleet/members/{id}/history`: the heartbeats the center holds
/// of one member, newest first. Needs scope `inventory` (or `full`,
/// `actions`, `admin`), as `GET /v1/fleet/members` does: a row holds what
/// that answer holds of the member.
///
/// Parameters: `from` (included) and `to` (not included) as RFC 3339 times
/// of receipt, and `limit` (100 when absent, at most 1000). `400` names a
/// parameter or an id that is refused. The answer holds the rows in
/// `heartbeats`, their `count`, `more` when rows were cut by the limit, and
/// `complete`: `false` when a file could not be read (each in `refused`)
/// or the question ruled in more files than one question opens
/// (`files_not_read`).
///
/// A build without the history store answers `501` with
/// [`NO_HISTORY_STORE`].
async fn member_history(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    use crate::output::api::Problem;
    use axum::http::StatusCode;
    limit(&state, peer.ip())?;
    crate::output::api::verify_bearer(&state.verifier, &headers, crate::auth::SCOPE_INVENTORY)?;
    #[cfg(not(feature = "fleet-store"))]
    {
        let _ = (id, uri);
        Err(Problem::detailed(
            StatusCode::NOT_IMPLEMENTED,
            NO_HISTORY_STORE,
        ))
    }
    #[cfg(feature = "fleet-store")]
    {
        use super::fleet_history::{CLASS_MEMBERS, Query};
        let pairs: Vec<(String, String)> = axum::extract::Query::try_from_uri(&uri)
            .map(|axum::extract::Query(pairs)| pairs)
            .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e.to_string()))?;
        let query = Query::parse_heartbeats(&id, &pairs)
            .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e))?;
        // As for call records: the rows that wait and the list of files
        // are taken as one step, and the files are read without the lock.
        let (history, files, waiting) = {
            let center = state.center.lock();
            let files = center.history.list(CLASS_MEMBERS, &query);
            (center.history.clone(), files, center.waiting.rows())
        };
        let files = files.map_err(|e| {
            tracing::error!("fleet center: the heartbeats could not be read: {e}");
            Problem::detailed(
                StatusCode::SERVICE_UNAVAILABLE,
                "the center could not read its heartbeats; its log names the file",
            )
        })?;
        let mut answer = tokio::task::spawn_blocking(move || {
            history
                .answer(&query, &files, waiting)
                .json_as("heartbeats", member_json)
        })
        .await
        .map_err(|_| Problem::new(StatusCode::INTERNAL_SERVER_ERROR))?;
        answer["member"] = serde_json::Value::String(id);
        Ok(axum::Json(answer))
    }
}

/// `GET /v1/fleet/calls`: the call records the center holds, newest first.
/// Needs scope `full`, as the REST API's dialog routes do: a call record
/// carries the numbers and addresses of a call, which an `inventory`
/// token does not read.
///
/// Parameters: `member`, `from` (included) and `to` (not included) as RFC
/// 3339 times of receipt, `call_id`, and `limit` (100 when absent, at most
/// 1000). `400` names a parameter that is refused. The answer holds the
/// rows in `calls`, their `count`, `more` when rows were cut by the limit,
/// and `complete`: `false` when a file could not be read, with each such
/// file and the reason in `refused`.
///
/// A build without the history store answers `501` with
/// [`NO_HISTORY_STORE`].
async fn calls(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    use crate::output::api::Problem;
    use axum::http::StatusCode;
    limit(&state, peer.ip())?;
    crate::output::api::verify_bearer(&state.verifier, &headers, crate::auth::SCOPE_FULL)?;
    #[cfg(not(feature = "fleet-store"))]
    {
        let _ = uri;
        Err(Problem::detailed(
            StatusCode::NOT_IMPLEMENTED,
            NO_HISTORY_STORE,
        ))
    }
    #[cfg(feature = "fleet-store")]
    {
        use super::fleet_history::Query;
        let pairs: Vec<(String, String)> = axum::extract::Query::try_from_uri(&uri)
            .map(|axum::extract::Query(pairs)| pairs)
            .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e.to_string()))?;
        let query =
            Query::parse(&pairs).map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e))?;
        // The rows that wait and the list of files are taken as one step,
        // so a filing between the two cannot hide a row; the files are
        // read after, without the lock.
        let (history, files, waiting) = {
            let center = state.center.lock();
            let waiting = center.intake.rows();
            let files = center
                .history
                .list(super::fleet_history::CLASS_CALLS, &query);
            (center.history.clone(), files, waiting)
        };
        let unreadable = |e: String| {
            tracing::error!("fleet center: the call records could not be read: {e}");
            Problem::detailed(
                StatusCode::SERVICE_UNAVAILABLE,
                "the center could not read its call records; its log names the file",
            )
        };
        let files = files.map_err(unreadable)?;
        let waiting = waiting.map_err(unreadable)?;
        let answer =
            tokio::task::spawn_blocking(move || history.answer(&query, &files, waiting).json())
                .await
                .map_err(|_| Problem::new(StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(axum::Json(answer))
    }
}

/// Log members going silent and coming back, every [`SILENCE_CHECK`]; apply
/// retention and rewrite the store every [`UPKEEP_EVERY`].
async fn upkeep(state: CenterState) {
    let mut silent: BTreeSet<String> = BTreeSet::new();
    let mut tick = tokio::time::interval(SILENCE_CHECK);
    let mut last_upkeep = tokio::time::Instant::now();
    #[cfg(feature = "fleet-store")]
    let mut last_filing = tokio::time::Instant::now();
    loop {
        tick.tick().await;
        let now = Utc::now();
        #[cfg(feature = "fleet-store")]
        let filing_is_due = last_filing.elapsed() >= state.calls_flush;
        {
            let mut center = state.center.lock();
            silent = log_silence_changes(&center.registry, now, state.missed, &silent);
            #[cfg(feature = "fleet-store")]
            if filing_is_due {
                last_filing = tokio::time::Instant::now();
                file_and_log(&mut center);
            }
            if last_upkeep.elapsed() >= UPKEEP_EVERY {
                last_upkeep = tokio::time::Instant::now();
                #[cfg(feature = "fleet-store")]
                expire_history(
                    &center,
                    now,
                    state.calls_retention_days,
                    state.retention_hours,
                );
                for member in apply_retention(&mut center, now, state.retention_hours) {
                    silent.remove(&member);
                }
            }
        }
        // The heartbeat rows are filed with the lock released, so requests
        // are answered while their files are written.
        #[cfg(feature = "fleet-store")]
        if filing_is_due {
            file_heartbeats_and_log(&state.center, &state.filing);
        }
    }
}

/// Log each member that went silent or came back since `before`, the set
/// silent at the last check, and return the set silent at `now`.
fn log_silence_changes(
    registry: &Registry,
    now: DateTime<Utc>,
    missed: u32,
    before: &BTreeSet<String>,
) -> BTreeSet<String> {
    let silent_now: BTreeSet<String> = registry.silent(now, missed).into_iter().collect();
    for r in registry.records() {
        if silent_now.contains(&r.member) && !before.contains(&r.member) {
            tracing::warn!(
                "fleet member '{}' is silent: no heartbeat for {} s, more than {missed} of \
                 its {} s intervals",
                r.member,
                now.signed_duration_since(r.received_at).num_seconds(),
                r.heartbeat_secs
            );
        }
    }
    for member in before.difference(&silent_now) {
        tracing::info!("fleet member '{member}' is heard again");
    }
    silent_now
}

/// Remove the call records past retention or the intake's size, and log
/// how many went.
fn trim_intake(intake: &mut super::fleet_intake::Intake, now: DateTime<Utc>, retention_hours: u64) {
    match intake.trim(
        now,
        retention(retention_hours),
        super::fleet_intake::MAX_INTAKE_BYTES,
    ) {
        Ok(0) => {}
        Ok(removed) => tracing::info!(
            "fleet center: {removed} call record(s) past --retention-hours {retention_hours} \
             or the intake's size were removed"
        ),
        Err(e) => tracing::warn!("fleet center: the intake was not rewritten: {e}"),
    }
}

/// Remove the members and the call records past retention, rewrite the
/// store when anything changed, and return the members removed.
fn apply_retention(center: &mut Center, now: DateTime<Utc>, retention_hours: u64) -> Vec<String> {
    let Center {
        registry,
        store,
        intake,
        waiting,
        ..
    } = center;
    trim_intake(intake, now, retention_hours);
    let gone = registry.expire(now, retention(retention_hours));
    waiting.expire(now - retention(retention_hours));
    for member in &gone {
        tracing::info!(
            "fleet member '{member}' removed: not heard for --retention-hours {retention_hours}"
        );
    }
    if (store.appended() > 0 || !gone.is_empty())
        && let Err(e) = store.compact_with(registry, &waiting.rows())
    {
        tracing::warn!("fleet center: the store was not rewritten: {e}");
    }
    gone
}

/// The store keys the tests use: the key of 32 bytes of `byte`, and no
/// older one.
#[cfg(test)]
fn test_keys(byte: u8) -> Arc<crate::app::fleet_seal::Keys> {
    Arc::new(crate::app::fleet_seal::Keys::new(
        crate::app::fleet_seal::MasterKey::from_bytes([byte; 32]),
        Vec::new(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn t(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    fn line(stream: &str, seq: u64, sent_at: &str, secs: u64) -> String {
        serde_json::json!({
            "schema_version": 1,
            "kind": "heartbeat",
            "stream": stream,
            "seq": seq,
            "sent_at": sent_at,
            "heartbeat_secs": secs,
            "inventory": {"schema_version": 1, "node_name": "edge-a"},
        })
        .to_string()
    }

    fn hb(stream: &str, seq: u64, sent_at: &str) -> Result<Heartbeat, TestError> {
        Ok(Heartbeat {
            stream: stream.to_string(),
            seq,
            sent_at: t(sent_at)?,
            heartbeat_secs: 30,
            inventory: serde_json::json!({"node_name": "edge-a"}),
            calls: None,
        })
    }

    /// A body of heartbeat lines parses, blank lines and a final newline
    /// included, each record with its fields.
    #[test]
    fn a_batch_of_heartbeats_parses() -> Result<(), TestError> {
        let body = format!(
            "{}\n\n{}\n",
            line("s-1", 1, "2026-11-07T12:00:00Z", 30),
            line("s-1", 2, "2026-11-07T12:00:30Z", 30)
        );
        let got = parse_heartbeats(body.as_bytes())?;
        assert_eq!(got.len(), 2, "two records: {got:?}");
        assert_eq!(got[1].seq, 2, "{got:?}");
        assert_eq!(got[1].stream, "s-1", "{got:?}");
        assert_eq!(got[1].sent_at, t("2026-11-07T12:00:30Z")?, "{got:?}");
        assert_eq!(got[0].heartbeat_secs, 30, "{got:?}");
        assert_eq!(
            got[0].inventory["node_name"], "edge-a",
            "the inventory is kept as sent"
        );
        Ok(())
    }

    /// Every malformed record refuses the whole batch, and the reason names
    /// the line, so nothing is half accepted.
    #[test]
    fn a_malformed_record_refuses_the_batch_and_names_the_line() -> Result<(), TestError> {
        let good = line("s-1", 1, "2026-11-07T12:00:00Z", 30);
        let with = |key: &str, value: serde_json::Value| -> Result<String, TestError> {
            let mut v: serde_json::Value = serde_json::from_str(&good)?;
            v[key] = value;
            Ok(v.to_string())
        };
        let cases: Vec<(String, &str)> = vec![
            ("not json".to_string(), "line 2"),
            (with("kind", serde_json::json!("rollup"))?, "kind"),
            (
                with("schema_version", serde_json::json!(2))?,
                "schema_version",
            ),
            (with("stream", serde_json::json!("bad stream!"))?, "stream"),
            (with("seq", serde_json::json!(0))?, "seq"),
            (with("sent_at", serde_json::json!("yesterday"))?, "sent_at"),
            (
                with("heartbeat_secs", serde_json::json!(0))?,
                "heartbeat_secs",
            ),
            (
                with("heartbeat_secs", serde_json::json!(3601))?,
                "heartbeat_secs",
            ),
            (with("inventory", serde_json::json!([1]))?, "inventory"),
        ];
        for (bad, want) in cases {
            assert_ne!(bad, good, "the case must differ from the good record");
            let body = format!("{good}\n{bad}\n");
            let why = parse_batch(body.as_bytes())
                .err()
                .ok_or_else(|| format!("accepted a batch with {bad}"))?;
            assert!(why.contains(want), "{why} does not name {want} for {bad}");
            assert!(why.contains("line 2"), "{why} does not name the line");
        }
        assert!(parse_batch(b"").is_err(), "an empty batch is refused");
        assert!(parse_batch(b"\n\n").is_err(), "a blank batch is refused");
        let many: String = (1..=(MAX_BATCH_RECORDS as u64 + 1))
            .map(|n| line("s-1", n, "2026-11-07T12:00:00Z", 30) + "\n")
            .collect();
        assert!(
            parse_batch(many.as_bytes()).is_err_and(|e| e.contains("records")),
            "more than {MAX_BATCH_RECORDS} records are refused"
        );
        Ok(())
    }

    /// Member and stream ids: letters, digits, `.`, `_` and `-`, at most 64.
    #[test]
    fn ids_are_short_and_plain() {
        for good in ["edge-a", "E.1_x", &"a".repeat(MAX_ID_LEN)] {
            assert!(is_valid_id(good), "{good} refused");
        }
        for bad in ["", "a b", "a/b", "é", &"a".repeat(MAX_ID_LEN + 1), "a\n"] {
            assert!(!is_valid_id(bad), "{bad:?} accepted");
        }
    }

    /// The replay rule. In one stream a record is new when its position is
    /// past the newest accepted one. A record of another stream is new when
    /// it was sent after the newest accepted one: a member whose spool was
    /// recreated starts a new stream, and a replay of an old stream is older.
    #[test]
    fn a_record_is_new_once_and_a_replay_is_not() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 5,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            admits(None, &hb("s-1", 1, "2026-11-07T11:00:00Z")?),
            "first"
        );
        assert!(
            admits(Some(&at), &hb("s-1", 6, "2026-11-07T12:00:30Z")?),
            "next"
        );
        assert!(
            !admits(Some(&at), &hb("s-1", 5, "2026-11-07T12:00:00Z")?),
            "replay"
        );
        assert!(
            !admits(Some(&at), &hb("s-1", 4, "2026-11-07T12:00:30Z")?),
            "older"
        );
        assert!(
            admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:01Z")?),
            "a new stream, sent later"
        );
        assert!(
            !admits(Some(&at), &hb("s-0", 9, "2026-11-07T12:00:00Z")?),
            "another stream, sent no later: a replay of an old stream"
        );
        Ok(())
    }

    /// Silent once more than `missed` intervals passed since the last
    /// heartbeat; not at exactly that many.
    #[test]
    fn a_member_is_silent_after_the_missed_heartbeats() -> Result<(), TestError> {
        let last = t("2026-11-07T12:00:00Z")?;
        let at = |s: &str| t(s);
        assert!(
            !is_silent(at("2026-11-07T12:01:30Z")?, last, 30, 3),
            "3 x 30 s"
        );
        assert!(
            is_silent(at("2026-11-07T12:01:31Z")?, last, 30, 3),
            "past 3 x 30 s"
        );
        assert!(
            !is_silent(at("2026-11-07T12:00:05Z")?, last, 1, 5),
            "5 x 1 s"
        );
        assert!(
            is_silent(at("2026-11-07T12:00:06Z")?, last, 1, 5),
            "past 5 x 1 s"
        );
        assert!(
            !is_silent(at("2026-11-07T11:59:00Z")?, last, 1, 3),
            "a clock that went back is not silence"
        );
        Ok(())
    }

    /// One request: new records counted once, replays counted as
    /// duplicates, and the member's record is the newest accepted one with
    /// the center's receive time and the peer.
    #[test]
    fn a_plan_counts_new_records_once() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let now = t("2026-11-07T12:00:40Z")?;
        let batch = vec![
            hb("s-1", 1, "2026-11-07T12:00:00Z")?,
            hb("s-1", 2, "2026-11-07T12:00:30Z")?,
        ];
        let plan = reg.plan("edge-a", "192.0.2.11", now, &batch);
        assert_eq!((plan.accepted, plan.duplicate), (2, 0), "{plan:?}");
        let rec = plan.record.clone().ok_or("a record")?;
        assert_eq!(rec.member, "edge-a", "{rec:?}");
        assert_eq!(rec.heartbeats, 2, "{rec:?}");
        assert_eq!(rec.cursor.seq, 2, "{rec:?}");
        assert_eq!(rec.received_at, now, "{rec:?}");
        assert_eq!(rec.peer, "192.0.2.11", "{rec:?}");
        reg.commit(plan);
        // The same batch again, then once more with one new record.
        let again = reg.plan("edge-a", "192.0.2.11", now, &batch);
        assert_eq!((again.accepted, again.duplicate), (0, 2), "{again:?}");
        assert_eq!(again.record, None, "nothing new, nothing to write");
        let mut more = batch.clone();
        more.push(hb("s-1", 3, "2026-11-07T12:01:00Z")?);
        let plan = reg.plan("edge-a", "192.0.2.11", now, &more);
        assert_eq!((plan.accepted, plan.duplicate), (1, 2), "{plan:?}");
        assert_eq!(
            plan.record.as_ref().map(|r| r.heartbeats),
            Some(3),
            "the third record makes three"
        );
        reg.commit(plan);
        assert_eq!(reg.records().len(), 1, "one member");
        assert_eq!(reg.records()[0].heartbeats, 3, "counted once each");
        Ok(())
    }

    /// Retention removes the members last heard before it, and only them.
    #[test]
    fn retention_removes_what_it_should_and_nothing_else() -> Result<(), TestError> {
        let mut reg = Registry::default();
        for (member, at) in [
            ("old", "2026-11-04T11:59:59Z"),
            ("edge", "2026-11-04T12:00:00Z"),
            ("new", "2026-11-07T11:00:00Z"),
        ] {
            let plan = reg.plan(member, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            reg.commit(plan);
        }
        let gone = reg.expire(t("2026-11-07T12:00:00Z")?, chrono::Duration::hours(72));
        assert_eq!(
            gone,
            vec!["old".to_string()],
            "only the member past retention"
        );
        let left: Vec<&str> = reg.records().iter().map(|r| r.member.as_str()).collect();
        assert_eq!(left, ["edge", "new"], "the rest stay");
        Ok(())
    }

    /// The members answer keeps what the center verified apart from what the
    /// member says about itself, and says which members are silent.
    #[test]
    fn the_members_answer_labels_self_reported_fields() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let plan = reg.plan(
            "edge-a",
            "192.0.2.11",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s-1", 1, "2026-11-07T11:59:59Z")?],
        );
        reg.commit(plan);
        let plan = reg.plan(
            "edge-b",
            "192.0.2.12",
            t("2026-11-07T12:01:00Z")?,
            &[hb("s-2", 1, "2026-11-07T12:01:00Z")?],
        );
        reg.commit(plan);
        let v = reg.report(t("2026-11-07T12:01:31Z")?, 3, 72);
        assert_eq!(v["schema_version"], 1, "{v}");
        assert_eq!(v["silent_after_missed"], 3, "{v}");
        assert_eq!(v["retention_hours"], 72, "{v}");
        let rows = v["members"].as_array().ok_or("members")?;
        assert_eq!(rows.len(), 2, "{v}");
        let a = &rows[0];
        assert_eq!(a["member"], "edge-a", "{v}");
        assert_eq!(a["silent"], true, "91 s past a 30 s interval: {v}");
        assert_eq!(rows[1]["silent"], false, "{v}");
        assert_eq!(a["seconds_since_heartbeat"], 91, "{v}");
        assert_eq!(a["verified"]["peer"], "192.0.2.11", "{v}");
        assert_eq!(a["verified"]["received_at"], "2026-11-07T12:00:00Z", "{v}");
        assert_eq!(a["verified"]["heartbeats"], 1, "{v}");
        assert_eq!(
            a["self_reported"]["inventory"]["node_name"], "edge-a",
            "{v}"
        );
        assert_eq!(a["self_reported"]["heartbeat_secs"], 30, "{v}");
        assert_eq!(a["self_reported"]["stream"], "s-1", "{v}");
        assert_eq!(a["self_reported"]["seq"], 1, "{v}");
        assert_eq!(a["self_reported"]["sent_at"], "2026-11-07T11:59:59Z", "{v}");
        assert!(
            a["verified"]["inventory"].is_null(),
            "no claim among the verified: {v}"
        );
        assert_eq!(
            reg.silent(t("2026-11-07T12:01:31Z")?, 3),
            vec!["edge-a".to_string()],
            "the silent list agrees with the answer"
        );
        Ok(())
    }

    /// The store is created 0600, holds what was appended across a reopen,
    /// keeps only the newest record per member after a rewrite, and refuses
    /// a file other users can read.
    #[cfg(unix)]
    #[test]
    fn the_store_is_private_durable_and_compacts() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, loaded) = Store::open(&path, test_keys(1))?;
        assert!(loaded.is_empty(), "a new store is empty");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "created private"
        );
        let mut reg = Registry::default();
        for seq in 1..=3 {
            let at = format!("2026-11-07T12:00:0{seq}Z");
            let plan = reg.plan("edge-a", "192.0.2.11", t(&at)?, &[hb("s-1", seq, &at)?]);
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            reg.commit(plan);
        }
        assert_eq!(store.appended(), 3, "three lines");
        drop(store);
        let (mut store, loaded) = Store::open(&path, test_keys(1))?;
        assert_eq!(loaded.len(), 3, "every appended line is there");
        let reopened = Registry::from_records(loaded);
        assert_eq!(reopened, reg, "the reopened registry is the one written");
        store.compact(&reopened)?;
        assert_eq!(
            Store::open(&path, test_keys(1))?.1.len(),
            1,
            "the newest record per member"
        );
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "rewritten private"
        );
        assert_eq!(store.appended(), 0, "a rewrite resets the count");
        drop(store);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let refused = Store::open(&path, test_keys(1));
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("0644") && e.contains("chmod 600")),
            "{refused:?}"
        );
        Ok(())
    }

    /// A store an earlier release wrote in clear, whose last line is cut
    /// short (that center stopped mid-write), is imported with that line
    /// dropped; a bad line before the last is refused, because it is not a
    /// torn write.
    #[test]
    fn a_torn_last_line_is_dropped_and_a_bad_middle_line_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let reg = Registry::default();
        let plan = reg.plan(
            "edge-a",
            "192.0.2.11",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s-1", 1, "2026-11-07T12:00:00Z")?],
        );
        store.append(plan.record.as_ref().ok_or("a record")?)?;
        drop(store);
        let whole = format!(
            "{}\n",
            serde_json::to_string(plan.record.as_ref().ok_or("a record")?)?
        );
        std::fs::write(&path, format!("{whole}{{\"member\":\"edge-b\",\"recei"))?;
        let (_, loaded) = Store::open(&path, test_keys(1))?;
        assert_eq!(loaded.len(), 1, "the torn line is dropped");
        std::fs::write(&path, format!("{whole}garbage\n{whole}"))?;
        assert!(
            Store::open(&path, test_keys(1)).is_err_and(|e| e.contains("line 2")),
            "a bad line before the last is refused, by line"
        );
        Ok(())
    }

    /// FLEET-STORE-TAIL-TRUNCATION: a store whose last acknowledged
    /// heartbeat was removed from the end of the file is refused, by file
    /// and layer, and left as it was found.
    #[test]
    fn failure_a_store_whose_last_heartbeat_was_removed_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::default();
        let mut kept = 0;
        for seq in 1..=2 {
            kept = usize::try_from(std::fs::metadata(&path)?.len())?;
            let plan = reg.plan(
                "edge-a",
                "192.0.2.11",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s-1", seq, "2026-11-07T12:00:00Z")?],
            );
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            reg.commit(plan);
        }
        drop(store);
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, &bytes[..kept])?;
        assert_eq!(
            Store::open(&path, test_keys(1)).err(),
            Some(format!(
                "--store '{}': sealed layer: the file was cut at its end: it holds 3 of the 5 \
                 entries it was written with",
                path.display()
            )),
            "failure a store whose last heartbeat was removed is refused"
        );
        assert_eq!(
            std::fs::read(&path)?,
            bytes[..kept],
            "the refused file is left as it was found"
        );
        Ok(())
    }

    /// The store a center of a release up to 0.5.245 left, a format 1 file
    /// (the fixture, which the writer of release 0.5.244 made; 0.5.245
    /// writes the same format): this build reads its base and its append,
    /// and writes it again as format 2.
    #[test]
    fn success_a_store_a_release_up_to_0_5_245_wrote_is_read_and_written_again_as_format_2()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/fleet/center-store-format-1.sealed"
            ),
            &path,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            std::fs::read(&path)?[4],
            1,
            "the fixture is a format 1 file"
        );
        let (_, records) = Store::open(&path, test_keys(1))?;
        assert_eq!(
            records
                .iter()
                .map(|r| r.member.as_str())
                .collect::<Vec<_>>(),
            vec!["edge-a", "edge-b"],
            "success a store a release up to 0.5.245 wrote is read and written again as format 2"
        );
        assert_eq!(std::fs::read(&path)?[4], 2, "and is format 2 afterwards");
        Ok(())
    }

    /// After a rewrite the store counts its appends again: every member is
    /// read back, and a heartbeat removed from the end is refused.
    #[test]
    fn success_a_rewritten_store_counts_the_appends_after_the_rewrite() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::default();
        let mut kept = 0;
        for (n, member) in ["a", "b", "c"].iter().enumerate() {
            if n == 2 {
                store.compact(&reg)?;
            }
            kept = usize::try_from(std::fs::metadata(&path)?.len())?;
            let at = "2026-11-07T12:00:00Z";
            let plan = reg.plan(member, "192.0.2.11", t(at)?, &[hb("s-1", 1, at)?]);
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            reg.commit(plan);
        }
        drop(store);
        let whole = std::fs::read(&path)?;
        let dir2 = tempfile::tempdir()?;
        let copy = dir2.path().join("center.store");
        std::fs::write(&copy, &whole)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            Store::open(&copy, test_keys(1))?.1.len(),
            3,
            "success a rewritten store counts the appends after the rewrite"
        );
        std::fs::write(&path, &whole[..kept])?;
        assert!(
            Store::open(&path, test_keys(1)).is_err_and(|e| e
                .ends_with("was cut at its end: it holds 3 of the 5 entries it was written with")),
            "and the append after the rewrite is counted"
        );
        Ok(())
    }

    /// FLEET-STORE-APPEND-AFTER-FAILED-WRITE: an append that fails must not
    /// leave the store unreadable. Here the second append fails because
    /// the file is away for a moment; the third succeeds; the store must
    /// then reopen with the first and the third heartbeat.
    #[test]
    fn edge_an_append_after_a_failed_append_leaves_a_store_that_reopens() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let away = dir.path().join("away");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::default();
        for member in ["a", "b", "c"] {
            let at = "2026-11-07T12:00:00Z";
            let plan = reg.plan(member, "192.0.2.11", t(at)?, &[hb("s-1", 1, at)?]);
            let record = plan.record.as_ref().ok_or("a record")?;
            if member == "b" {
                std::fs::rename(&path, &away)?;
                assert!(store.append(record).is_err(), "the append fails");
                std::fs::rename(&away, &path)?;
            } else {
                store.append(record)?;
                reg.commit(plan);
            }
        }
        drop(store);
        assert_eq!(
            Store::open(&path, test_keys(1))
                .map(|(_, records)| records.into_iter().map(|r| r.member).collect::<Vec<_>>()),
            Ok(vec!["a".to_string(), "c".to_string()]),
            "edge an append after a failed append leaves a store that reopens"
        );
        Ok(())
    }

    /// The record a first heartbeat from `member` stores.
    fn first_record(member: &str) -> Result<MemberRecord, TestError> {
        let at = "2026-11-07T12:00:00Z";
        let plan = Registry::default().plan(member, "192.0.2.11", t(at)?, &[hb("s-1", 1, at)?]);
        Ok(plan.record.ok_or("a record")?)
    }

    /// The members the store at `path` holds at the next start, in order.
    fn members_at(path: &Path) -> Result<Vec<String>, String> {
        Store::open(path, test_keys(1))
            .map(|(_, records)| records.into_iter().map(|r| r.member).collect())
    }

    /// A store in a new directory that took member `a`, then failed to
    /// take member `b` through a file `open` made, with the real file back
    /// in place after.
    fn store_after_a_failure(
        open: crate::app::fleet_log::OpenFile,
    ) -> Result<(tempfile::TempDir, PathBuf, Store), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        store.append(&first_record("a")?)?;
        store.log_mut().open_with(open);
        if store.append(&first_record("b")?).is_ok() {
            return Err("the append did not fail".into());
        }
        store
            .log_mut()
            .open_with(crate::app::fleet_log::faults::real());
        Ok((dir, path, store))
    }

    #[test]
    fn success_a_store_append_after_a_full_disk_reopens() -> Result<(), TestError> {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, path, mut store) = store_after_a_failure(stop_at(20, libc::ENOSPC))?;
        store.append(&first_record("c")?)?;
        drop(store);
        assert_eq!(
            members_at(&path),
            Ok(vec!["a".to_string(), "c".to_string()]),
            "success a store append after a full disk reopens"
        );
        Ok(())
    }

    #[test]
    fn success_a_store_append_after_a_failed_sync_holds_no_unacknowledged_member()
    -> Result<(), TestError> {
        use crate::app::fleet_log::faults::sync_fails;
        // The second sync failed: member b is whole in the file, and the
        // center never acknowledged it.
        let (_dir, path, mut store) = store_after_a_failure(sync_fails(1))?;
        store.append(&first_record("c")?)?;
        drop(store);
        assert_eq!(
            members_at(&path),
            Ok(vec!["a".to_string(), "c".to_string()]),
            "success a store append after a failed sync holds no unacknowledged member"
        );
        Ok(())
    }

    #[test]
    fn success_a_compact_after_a_failed_store_append_reopens() -> Result<(), TestError> {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, path, mut store) = store_after_a_failure(stop_at(7, libc::EIO))?;
        let at = "2026-11-07T12:00:00Z";
        let mut reg = Registry::default();
        let plan = reg.plan("a", "192.0.2.11", t(at)?, &[hb("s-1", 1, at)?]);
        reg.commit(plan);
        store.compact(&reg)?;
        store.append(&first_record("c")?)?;
        drop(store);
        assert_eq!(
            members_at(&path),
            Ok(vec!["a".to_string(), "c".to_string()]),
            "success a compact after a failed store append reopens"
        );
        Ok(())
    }

    #[test]
    fn failure_a_failed_store_append_is_not_counted() -> Result<(), TestError> {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, _path, store) = store_after_a_failure(stop_at(0, libc::ENOSPC))?;
        assert_eq!(
            store.appended(),
            1,
            "failure a failed store append is not counted"
        );
        Ok(())
    }

    #[test]
    fn failure_store_appends_fail_while_the_disk_is_full_and_work_after() -> Result<(), TestError> {
        use crate::app::fleet_log::faults::{real, stop_at};
        let (_dir, path, mut store) = store_after_a_failure(stop_at(3, libc::ENOSPC))?;
        store.log_mut().open_with(stop_at(40, libc::ENOSPC));
        assert_eq!(
            store
                .append(&first_record("c")?)
                .map_err(|e| e.raw_os_error()),
            Err(Some(libc::ENOSPC)),
            "the append fails while the disk is full"
        );
        store.log_mut().open_with(real());
        store.append(&first_record("d")?)?;
        drop(store);
        assert_eq!(
            members_at(&path),
            Ok(vec!["a".to_string(), "d".to_string()]),
            "failure store appends fail while the disk is full and work after"
        );
        Ok(())
    }

    /// The file releases 0.5.244 to 0.5.247 left when an append failed and
    /// a later one worked: the record after the failure is sealed for a
    /// position the file does not reach. It is refused, by file and layer,
    /// and left as found.
    #[test]
    fn failure_a_store_an_earlier_release_wrote_past_a_failed_append_is_refused()
    -> Result<(), TestError> {
        use crate::app::fleet_seal::{Kind, append_counted};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let mut sealer = write_sealed_reading(
            &path,
            &test_keys(1),
            Kind::Registry,
            std::iter::empty(),
            &|staged| std::fs::read(staged),
        )?;
        let a = sealer.record(&record_line(&first_record("a")?)?)?;
        append_counted(&path, &mut sealer, &a)?;
        // The append of b failed after b was sealed; nothing was written.
        let _ = sealer.record(&record_line(&first_record("b")?)?)?;
        let c = sealer.record(&record_line(&first_record("c")?)?)?;
        append_counted(&path, &mut sealer, &c)?;
        let before = std::fs::read(&path)?;
        assert_eq!(
            Store::open(&path, test_keys(1)).map(|_| ()),
            Err(format!(
                "--store '{}': sealed layer: the file has a record 4 that did not authenticate \
                 (the file was modified, or its records were moved)",
                path.display()
            )),
            "failure a store an earlier release wrote past a failed append is refused"
        );
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "the refused store is left as found"
        );
        Ok(())
    }

    /// As the test above, when the failed append of those releases wrote a
    /// part of its record before it failed.
    #[test]
    fn failure_a_store_an_earlier_release_wrote_past_a_partly_written_append_is_refused()
    -> Result<(), TestError> {
        use crate::app::fleet_seal::{Kind, append_counted};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let mut sealer = write_sealed_reading(
            &path,
            &test_keys(1),
            Kind::Registry,
            std::iter::empty(),
            &|staged| std::fs::read(staged),
        )?;
        let a = sealer.record(&record_line(&first_record("a")?)?)?;
        append_counted(&path, &mut sealer, &a)?;
        let b = sealer.record(&record_line(&first_record("b")?)?)?;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(&b[..b.len() / 2])?;
        drop(file);
        let c = sealer.record(&record_line(&first_record("c")?)?)?;
        append_counted(&path, &mut sealer, &c)?;
        assert_eq!(
            Store::open(&path, test_keys(1)).map(|_| ()),
            Err(format!(
                "--store '{}': sealed layer: the file has a record 4 that did not authenticate \
                 (the file was modified, or its records were moved)",
                path.display()
            )),
            "failure a store an earlier release wrote past a partly written append is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_a_store_stopped_after_a_failed_append_starts_with_the_members_before_it()
    -> Result<(), TestError> {
        use crate::app::fleet_log::faults::stop_at;
        let (_dir, path, store) = store_after_a_failure(stop_at(20, libc::ENOSPC))?;
        drop(store);
        assert_eq!(
            members_at(&path),
            Ok(vec!["a".to_string()]),
            "edge a store stopped after a failed append starts with the members before it"
        );
        Ok(())
    }

    /// A store whose two counts were damaged is refused by file and layer.
    #[test]
    fn failure_a_store_whose_counts_were_damaged_is_refused() -> Result<(), TestError> {
        use crate::app::fleet_seal::{COUNT_SLOT_BYTES, KEY_HEADER_BYTES};
        let dir = tempfile::tempdir()?;
        let path = sealed_store_of(dir.path(), &["a", "b"])?;
        let mut bytes = std::fs::read(&path)?;
        bytes[KEY_HEADER_BYTES + 10] ^= 1;
        bytes[KEY_HEADER_BYTES + COUNT_SLOT_BYTES + 10] ^= 1;
        std::fs::write(&path, &bytes)?;
        assert_eq!(
            Store::open(&path, test_keys(1)).err(),
            Some(format!(
                "--store '{}': sealed layer: the file has a record count that did not \
                 authenticate (the file was modified, or the key is wrong)",
                path.display()
            )),
            "failure a store whose counts were damaged is refused"
        );
        Ok(())
    }

    /// A store in `dir` under key 1 with one appended heartbeat from each
    /// of `members`.
    fn sealed_store_of(dir: &Path, members: &[&str]) -> Result<PathBuf, TestError> {
        let path = dir.join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::default();
        for member in members {
            let at = "2026-11-07T12:00:00Z";
            let plan = reg.plan(member, "192.0.2.11", t(at)?, &[hb("s-1", 1, at)?]);
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            reg.commit(plan);
        }
        Ok(path)
    }

    /// An append the center did not finish, after heartbeats it had
    /// acknowledged, is dropped and the acknowledged ones are kept.
    #[test]
    fn edge_an_unfinished_append_after_counted_heartbeats_is_dropped() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let plan = Registry::default().plan(
            "edge-a",
            "192.0.2.11",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s-1", 1, "2026-11-07T12:00:00Z")?],
        );
        store.append(plan.record.as_ref().ok_or("a record")?)?;
        drop(store);
        let mut bytes = std::fs::read(&path)?;
        bytes.extend([0, 0, 2, 0, 1, 2, 3]);
        std::fs::write(&path, &bytes)?;
        assert_eq!(
            Store::open(&path, test_keys(1))?.1.len(),
            1,
            "edge an unfinished append after counted heartbeats is dropped"
        );
        Ok(())
    }

    /// The minute's upkeep removes a member past retention from the
    /// registry and from the store file, and leaves the others in both.
    #[test]
    fn the_upkeep_applies_retention_to_the_registry_and_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let keep = chrono::Duration::hours(72);
        let (mut center, _) = Center::open(&path, test_keys(1), t("2026-11-01T00:00:00Z")?, keep)?;
        for (member, at) in [
            ("old", "2026-11-01T00:00:00Z"),
            ("new", "2026-11-07T11:00:00Z"),
        ] {
            let batch = [Record::Heartbeat(hb("s", 1, at)?)];
            center.take(member, "192.0.2.1", t(at)?, &batch)?;
        }
        let gone = apply_retention(&mut center, t("2026-11-07T12:00:00Z")?, 72);
        assert_eq!(gone, vec!["old".to_string()], "only the old member");
        assert_eq!(center.registry.records().len(), 1, "one member left");
        drop(center);
        let mut members: Vec<String> = Store::open(&path, test_keys(1))?
            .1
            .into_iter()
            .map(|r| r.member)
            .collect();
        // A build with the history store keeps the heartbeat row that
        // waits for a filing before the member's record.
        members.dedup();
        assert_eq!(
            members,
            vec!["new".to_string()],
            "removed from the file, its waiting heartbeat row too, and the other stays in it"
        );
        Ok(())
    }

    /// The silence check returns the members silent now, so the next check
    /// logs only what changed.
    #[test]
    fn the_silence_check_returns_who_is_silent_now() -> Result<(), TestError> {
        let mut registry = Registry::default();
        for (member, at) in [
            ("quiet", "2026-11-07T12:00:00Z"),
            ("loud", "2026-11-07T12:01:00Z"),
        ] {
            let plan = registry.plan(member, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            registry.commit(plan);
        }
        let now = t("2026-11-07T12:01:31Z")?;
        let first = log_silence_changes(&registry, now, 3, &BTreeSet::new());
        assert_eq!(first, BTreeSet::from(["quiet".to_string()]), "{first:?}");
        let again = log_silence_changes(&registry, t("2026-11-07T11:00:00Z")?, 3, &first);
        assert!(
            again.is_empty(),
            "nobody silent before they were heard: {again:?}"
        );
        Ok(())
    }

    /// Plain HTTP is refused on any address but loopback; HTTPS anywhere.
    #[test]
    fn plain_http_is_refused_except_on_loopback() -> Result<(), TestError> {
        for (addr, tls, refused) in [
            ("127.0.0.1:8443", false, false),
            ("[::1]:8443", false, false),
            ("192.0.2.10:8443", false, true),
            ("0.0.0.0:8443", false, true),
            ("192.0.2.10:8443", true, false),
            ("0.0.0.0:8443", true, false),
        ] {
            let got = plain_http_refusal(addr.parse()?, tls);
            assert_eq!(got.is_some(), refused, "{addr} tls={tls}: {got:?}");
            if let Some(why) = got {
                assert!(why.contains("--tls-cert"), "{why}");
            }
        }
        Ok(())
    }
}

/// One behavior each, by category, for the center's rules (SUCCESS, FAILURE,
/// EDGE). The routes are driven in process through the router the center
/// serves, with no socket; the rules through their functions.
#[cfg(test)]
mod behavior_tests {
    use super::*;
    use tower::ServiceExt as _;

    type TestError = Box<dyn std::error::Error>;

    /// The key tokens are minted with in these tests, derived at run time
    /// (a literal here is a hard-coded cryptographic value to CodeQL).
    fn key() -> &'static [u8] {
        crate::test_material::key_bytes("fleet-center-behavior")
    }

    fn t(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    fn hb(stream: &str, seq: u64, sent_at: &str) -> Result<Heartbeat, TestError> {
        Ok(Heartbeat {
            stream: stream.to_string(),
            seq,
            sent_at: t(sent_at)?,
            heartbeat_secs: 30,
            inventory: serde_json::json!({"node_name": "edge-a"}),
            calls: None,
        })
    }

    fn record(v: serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "schema_version": 1,
            "kind": "heartbeat",
            "stream": "s-1",
            "seq": 1,
            "sent_at": "2026-11-07T12:00:00Z",
            "heartbeat_secs": 30,
            "inventory": {"node_name": "edge-a"},
        });
        if let (Some(b), Some(o)) = (base.as_object_mut(), v.as_object()) {
            for (k, val) in o {
                b.insert(k.clone(), val.clone());
            }
        }
        base.to_string()
    }

    fn without(key: &str) -> String {
        let mut v: serde_json::Value =
            serde_json::from_str(&record(serde_json::json!({}))).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove(key);
        }
        v.to_string()
    }

    fn token(id: &str, scope: &str, exp_offset: i64, audience: &str) -> String {
        crate::auth::mint(
            key(),
            id,
            Utc::now().timestamp() + exp_offset,
            audience,
            scope,
        )
    }

    fn member(id: &str) -> String {
        token(
            id,
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_API,
        )
    }

    /// A center state over a store in `dir`, `rate` requests per second.
    fn state(dir: &Path, rate: u32) -> Result<CenterState, TestError> {
        let (center, _) = Center::open(
            &dir.join("center.store"),
            test_keys(1),
            Utc::now(),
            chrono::Duration::hours(72),
        )?;
        Ok(CenterState {
            center: Arc::new(parking_lot::Mutex::new(center)),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    signing_keys: vec![key().to_vec()],
                    static_keys: Vec::new(),
                    revoked_file: None,
                    audience: crate::auth::AUDIENCE_API.to_string(),
                },
            )),
            limiter: Arc::new(parking_lot::Mutex::new(
                crate::output::api::RateLimiter::new(rate, 64),
            )),
            missed: 3,
            retention_hours: 72,
            calls_retention_days: 90,
            #[cfg(feature = "fleet-store")]
            calls_flush: std::time::Duration::from_secs(60),
            #[cfg(feature = "fleet-store")]
            filing: Arc::new(parking_lot::Mutex::new(())),
        })
    }

    /// One request through the center's router: status and body.
    async fn call(
        st: &CenterState,
        method: &str,
        path: &str,
        auth: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(u16, String), TestError> {
        let mut req = axum::http::Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        let mut req = req.body(axum::body::Body::from(body))?;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))));
        let resp = router(st.clone()).oneshot(req).await?;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn bearer(tok: &str) -> String {
        format!("Bearer {tok}")
    }

    fn line() -> Vec<u8> {
        (record(serde_json::json!({"sent_at": Utc::now().to_rfc3339()})) + "\n").into_bytes()
    }

    // ── SUCCESS ─────────────────────────────────────────────────────────

    /// A batch of exactly the most records parses.
    #[test]
    fn success_a_batch_at_the_record_limit_parses() -> Result<(), TestError> {
        let body: String = (1..=MAX_BATCH_RECORDS as u64)
            .map(|n| record(serde_json::json!({"seq": n})) + "\n")
            .collect();
        assert_eq!(
            parse_batch(body.as_bytes())?.len(),
            MAX_BATCH_RECORDS,
            "exactly the limit is accepted"
        );
        Ok(())
    }

    /// A gap in a stream's positions (heartbeats the member's cap dropped)
    /// is still new.
    #[test]
    fn success_a_gap_in_positions_is_new() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s".into(),
            seq: 5,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            admits(Some(&at), &hb("s", 9, "2026-11-07T12:02:00Z")?),
            "seq 9 after 5 is new"
        );
        Ok(())
    }

    /// Reopened, the registry holds the last record of each member in file
    /// order.
    #[test]
    fn success_the_last_record_per_member_wins() -> Result<(), TestError> {
        let reg = Registry::default();
        let a1 = reg
            .plan(
                "a",
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            )
            .record
            .ok_or("a record")?;
        let a2 = reg
            .plan(
                "a",
                "192.0.2.2",
                t("2026-11-07T12:01:00Z")?,
                &[hb("s", 2, "2026-11-07T12:01:00Z")?],
            )
            .record
            .ok_or("a record")?;
        let reg = Registry::from_records(vec![a1, a2]);
        assert_eq!(reg.records()[0].peer, "192.0.2.2", "the later record");
        Ok(())
    }

    /// The members answer lists members by id.
    #[test]
    fn success_members_are_listed_by_id() -> Result<(), TestError> {
        let mut reg = Registry::default();
        for m in ["edge-c", "edge-a", "edge-b"] {
            let p = reg.plan(
                m,
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            );
            reg.commit(p);
        }
        let v = reg.report(t("2026-11-07T12:00:01Z")?, 3, 72);
        let ids: Vec<&str> = v["members"]
            .as_array()
            .ok_or("members")?
            .iter()
            .filter_map(|r| r["member"].as_str())
            .collect();
        assert_eq!(ids, ["edge-a", "edge-b", "edge-c"], "sorted by member id");
        Ok(())
    }

    /// Two members' plans are independent: one's cursor does not touch the
    /// other's.
    #[test]
    fn success_members_have_their_own_cursors() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 5, "2026-11-07T12:00:00Z")?],
        );
        reg.commit(p);
        let p = reg.plan(
            "b",
            "192.0.2.2",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 1, "2026-11-07T11:00:00Z")?],
        );
        assert_eq!(p.accepted, 1, "b's first record is new whatever a holds");
        Ok(())
    }

    /// A store in `dir` under `keys` with one heartbeat from each of
    /// `members` appended, and the path of its file.
    fn sealed_store(
        dir: &Path,
        keys: Arc<crate::app::fleet_seal::Keys>,
        members: &[&str],
    ) -> Result<PathBuf, TestError> {
        let path = dir.join("center.store");
        let (mut store, _) = Store::open(&path, keys)?;
        let mut reg = Registry::default();
        for m in members {
            let at = "2026-11-07T12:00:00Z";
            let p = reg.plan(m, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            store.append(p.record.as_ref().ok_or("r")?)?;
            reg.commit(p);
        }
        Ok(path)
    }

    /// The members a store file opens to under `keys`.
    fn members_of(
        path: &Path,
        keys: Arc<crate::app::fleet_seal::Keys>,
    ) -> Result<Vec<String>, String> {
        Store::open(path, keys).map(|(_, r)| r.into_iter().map(|r| r.member).collect())
    }

    /// Whether `needle` appears anywhere in the file.
    fn file_holds(path: &Path, needle: &[u8]) -> Result<bool, TestError> {
        Ok(std::fs::read(path)?
            .windows(needle.len())
            .any(|w| w == needle))
    }

    /// The store file is a sealed file and holds no member name, node name
    /// or address in clear, after an append and after a rewrite.
    #[test]
    fn success_the_store_file_is_sealed_and_holds_no_member_in_clear() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["edge-secret-a"])?;
        for needle in [
            &b"edge-secret-a"[..],
            b"192.0.2.1",
            b"\"member\"",
            b"node_name",
        ] {
            assert!(
                !file_holds(&path, needle)?,
                "{:?}",
                String::from_utf8_lossy(needle)
            );
        }
        assert_eq!(&std::fs::read(&path)?[..4], b"SNFS", "a sealed file");
        let (mut store, records) = Store::open(&path, test_keys(1))?;
        store.compact(&Registry::from_records(records))?;
        assert!(!file_holds(&path, b"edge-secret-a")?, "after a rewrite");
        assert_eq!(
            &std::fs::read(&path)?[..4],
            b"SNFS",
            "still a sealed file after a rewrite"
        );
        Ok(())
    }

    /// A store an earlier release wrote in clear is read, and the file is
    /// sealed by the time `open` returns.
    #[test]
    fn success_a_plaintext_store_is_imported_and_sealed() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let reg = Registry::default();
        let at = "2026-11-07T12:00:00Z";
        let p = reg.plan("edge-old", "192.0.2.7", t(at)?, &[hb("s", 1, at)?]);
        let line = serde_json::to_string(p.record.as_ref().ok_or("r")?)?;
        std::fs::write(&path, format!("{line}\n"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            members_of(&path, test_keys(1))?,
            vec!["edge-old".to_string()],
            "the member the clear store held"
        );
        assert!(!file_holds(&path, b"edge-old")?, "no longer in clear");
        assert_eq!(
            members_of(&path, test_keys(1))?,
            vec!["edge-old".to_string()],
            "the member, read from the sealed file"
        );
        Ok(())
    }

    /// A store written under an earlier key opens when that key is listed
    /// as old, and is under the current key afterwards.
    #[test]
    fn success_a_store_under_an_old_key_opens_and_moves_to_the_current_key() -> Result<(), TestError>
    {
        use crate::app::fleet_seal::{Keys, MasterKey};
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b"])?;
        let rotated = Arc::new(Keys::new(
            MasterKey::from_bytes([2; 32]),
            vec![MasterKey::from_bytes([1; 32])],
        ));
        assert_eq!(
            members_of(&path, rotated)?.len(),
            2,
            "both members, read under the old key"
        );
        assert_eq!(
            members_of(&path, test_keys(2))?.len(),
            2,
            "the new key alone now opens it"
        );
        assert!(
            members_of(&path, test_keys(1)).is_err(),
            "the old key no longer does"
        );
        Ok(())
    }

    /// A store under a key that is not loaded is refused: the message names
    /// the sealed layer, the file, the key id and the flag that fixes it.
    #[test]
    fn failure_a_store_under_a_key_that_is_not_loaded_names_the_key_and_the_flag()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a"])?;
        let before = std::fs::read(&path)?;
        let e = members_of(&path, test_keys(2)).err().unwrap_or_default();
        let id = test_keys(1).current().id().to_string();
        assert!(e.contains("sealed layer"), "{e}");
        assert!(e.contains("center.store"), "{e}");
        assert!(e.contains(&id), "{e}");
        assert!(e.contains("--store-old-key-file"), "{e}");
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "a refused file is not touched"
        );
        Ok(())
    }

    /// One changed byte anywhere in the store refuses it, and the file is
    /// left as it was found.
    #[test]
    fn failure_a_modified_store_is_refused_as_the_sealed_layer() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b"])?;
        let good = std::fs::read(&path)?;
        for at in [20, good.len() / 2, good.len() - 1] {
            let mut bad = good.clone();
            bad[at] ^= 0x01;
            std::fs::write(&path, &bad)?;
            let e = members_of(&path, test_keys(1)).err().unwrap_or_default();
            assert!(
                e.contains("sealed layer") && e.contains("center.store"),
                "byte {at}: {e}"
            );
            assert_eq!(std::fs::read(&path)?, bad, "byte {at}: left as found");
        }
        Ok(())
    }

    /// A store cut inside the records it was rewritten with is refused as
    /// truncated.
    #[test]
    fn failure_a_truncated_store_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b"])?;
        let (mut store, records) = Store::open(&path, test_keys(1))?;
        store.compact(&Registry::from_records(records))?;
        drop(store);
        let good = std::fs::read(&path)?;
        std::fs::write(&path, &good[..good.len() - 30])?;
        let e = members_of(&path, test_keys(1)).err().unwrap_or_default();
        assert!(e.contains("sealed layer") && e.contains("truncated"), "{e}");
        Ok(())
    }

    /// A sealed file of another kind, put where the store is, is refused.
    #[test]
    fn failure_an_intake_file_in_the_stores_place_is_refused() -> Result<(), TestError> {
        use crate::app::fleet_seal::{Kind, LogSealer, system_draw};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let keys = test_keys(1);
        let (mut sealer, header) = LogSealer::new(keys.current(), Kind::Intake, &system_draw)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.base_end()?);
        std::fs::write(&path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let e = members_of(&path, keys).err().unwrap_or_default();
        assert!(e.contains("sealed layer") && e.contains("intake"), "{e}");
        Ok(())
    }

    /// A sealed record that authenticates but is not a member record is
    /// refused by its position.
    #[test]
    fn failure_a_sealed_record_that_is_not_a_member_record_is_refused() -> Result<(), TestError> {
        use crate::app::fleet_seal::{Kind, LogSealer, system_draw};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let keys = test_keys(1);
        let (mut sealer, header) = LogSealer::new(keys.current(), Kind::Registry, &system_draw)?;
        let mut bytes = header.to_vec();
        bytes.extend(sealer.record(b"{\"not\":\"a member\"}")?);
        bytes.extend(sealer.base_end()?);
        std::fs::write(&path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let e = members_of(&path, keys).err().unwrap_or_default();
        assert!(
            e.contains("record 1") && e.contains("not a member record"),
            "{e}"
        );
        Ok(())
    }

    /// An append the center did not finish is dropped at the next start,
    /// and every record before it is kept.
    #[test]
    fn edge_a_torn_append_is_dropped_and_the_rest_kept() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b"])?;
        // A part of a third record, and no count for it: the center
        // stopped while it wrote the record.
        let mut torn = std::fs::read(&path)?;
        torn.extend([0, 0, 2, 0, 9, 9, 9, 9, 9, 9, 9]);
        std::fs::write(&path, &torn)?;
        assert_eq!(
            members_of(&path, test_keys(1))?,
            vec!["a".to_string(), "b".to_string()],
            "the two whole appends"
        );
        Ok(())
    }

    /// A part cut from the last counted append is no unfinished write: the
    /// record was on disk whole before it was counted, so the store is
    /// refused.
    #[test]
    fn failure_a_counted_append_cut_short_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b", "c"])?;
        let good = std::fs::read(&path)?;
        std::fs::write(&path, &good[..good.len() - 7])?;
        let e = members_of(&path, test_keys(1)).err().map(|e| e.to_string());
        assert!(
            e.as_deref()
                .is_some_and(|e| e.contains("sealed layer: the file was cut at its end")),
            "failure a counted append cut short is refused: {e:?}"
        );
        Ok(())
    }

    /// Every open writes the file again under a new data key, so a data key
    /// never seals for two processes: the same members, different bytes.
    #[test]
    fn edge_each_open_writes_the_file_under_a_new_data_key() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a"])?;
        let first = std::fs::read(&path)?;
        assert_eq!(members_of(&path, test_keys(1))?.len(), 1, "the one member");
        let second = std::fs::read(&path)?;
        assert_ne!(first[14..30], second[14..30], "a new file id");
        assert_ne!(first[30..91], second[30..91], "a new wrapped data key");
        Ok(())
    }

    /// A record appended after a rewrite is sealed for the rewritten file:
    /// the store reopens with the rewritten records and the appended one.
    #[test]
    fn edge_an_append_after_a_rewrite_reopens() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a"])?;
        let (mut store, records) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::from_records(records);
        store.compact(&reg)?;
        let at = "2026-11-07T12:00:05Z";
        let p = reg.plan("b", "192.0.2.2", t(at)?, &[hb("s", 1, at)?]);
        store.append(p.record.as_ref().ok_or("r")?)?;
        reg.commit(p);
        drop(store);
        assert_eq!(
            members_of(&path, test_keys(1))?,
            vec!["a".to_string(), "b".to_string()],
            "the rewritten member and the one appended after"
        );
        Ok(())
    }

    /// A staged rewrite that does not read back is refused before it can
    /// replace the store: changed bytes, a missing end, or a record short.
    #[test]
    fn failure_a_staged_rewrite_that_does_not_read_back_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a", "b"])?;
        let (mut store, records) = Store::open(&path, test_keys(1))?;
        store.compact(&Registry::from_records(records))?;
        let good = std::fs::read(&path)?;
        let keys = test_keys(1);
        assert!(
            staged_reads_back(&good, &keys, crate::app::fleet_seal::Kind::Registry, 2).is_ok(),
            "the rewrite reads back"
        );
        let mut changed = good.clone();
        changed[good.len() / 2] ^= 1;
        assert!(
            staged_reads_back(&changed, &keys, crate::app::fleet_seal::Kind::Registry, 2).is_err(),
            "a changed byte"
        );
        assert!(
            staged_reads_back(
                &good[..good.len() - 29],
                &keys,
                crate::app::fleet_seal::Kind::Registry,
                2
            )
            .is_err(),
            "no end of the base"
        );
        assert!(
            staged_reads_back(&good, &keys, crate::app::fleet_seal::Kind::Registry, 3).is_err(),
            "a record short"
        );
        Ok(())
    }

    /// A store an earlier release wrote in clear is still there, byte for
    /// byte, when the sealed copy staged beside it does not read back.
    #[test]
    fn failure_a_clear_store_is_kept_when_its_sealed_copy_does_not_read_back()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let reg = Registry::default();
        let at = "2026-11-07T12:00:00Z";
        let p = reg.plan("edge-old", "192.0.2.7", t(at)?, &[hb("s", 1, at)?]);
        let clear = format!(
            "{}\n",
            serde_json::to_string(p.record.as_ref().ok_or("r")?)?
        );
        std::fs::write(&path, &clear)?;
        let records = plaintext_records(clear.as_bytes())?;
        let damaged = |staged: &Path| {
            let mut bytes = std::fs::read(staged)?;
            let middle = bytes.len() / 2;
            bytes[middle] ^= 1;
            Ok(bytes)
        };
        let e = write_sealed_reading(
            &path,
            &test_keys(1),
            crate::app::fleet_seal::Kind::Registry,
            records
                .iter()
                .map(|r| serde_json::to_vec(r).map_err(std::io::Error::other)),
            &damaged,
        )
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(e.starts_with("the staged store "), "refused: '{e}'");
        assert_eq!(std::fs::read(&path)?, clear.as_bytes(), "the clear store");
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 1, "no staged file");
        Ok(())
    }

    /// The staged file of a rewrite is gone afterwards, so no second copy
    /// of the store is left beside it.
    #[test]
    fn edge_a_rewrite_leaves_no_staged_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = sealed_store(dir.path(), test_keys(1), &["a"])?;
        let (mut store, records) = Store::open(&path, test_keys(1))?;
        store.compact(&Registry::from_records(records))?;
        let names: Vec<String> = std::fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["center.store".to_string()], "{names:?}");
        Ok(())
    }

    /// A rewritten store reopens to the same registry.
    #[test]
    fn success_a_compacted_store_reopens_the_same() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let mut reg = Registry::default();
        for m in ["a", "b"] {
            let p = reg.plan(
                m,
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            );
            store.append(p.record.as_ref().ok_or("r")?)?;
            reg.commit(p);
        }
        store.compact(&reg)?;
        drop(store);
        let (_, loaded) = Store::open(&path, test_keys(1))?;
        assert_eq!(Registry::from_records(loaded), reg, "same registry");
        Ok(())
    }

    /// The ingest answers `200` with the member, and counts.
    #[tokio::test]
    async fn success_the_ingest_answers_the_counts() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let (status, body) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(
            (
                v["member"].clone(),
                v["accepted"].clone(),
                v["duplicate"].clone()
            ),
            ("edge-a".into(), 1.into(), 0.into()),
            "{v}"
        );
        Ok(())
    }

    /// The `Bearer` scheme is matched without regard to case.
    #[tokio::test]
    async fn success_a_lowercase_bearer_scheme_is_accepted() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let auth = format!("bearer {}", member("edge-a"));
        let (status, body) = call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line()).await?;
        assert_eq!(status, 200, "{body}");
        Ok(())
    }

    /// An `admin` token reads the members list.
    #[tokio::test]
    async fn success_an_admin_token_reads_the_members() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "op",
            crate::auth::SCOPE_ADMIN,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (status, _) = call(
            &st,
            "GET",
            "/v1/fleet/members",
            Some(&bearer(&tok)),
            Vec::new(),
        )
        .await?;
        assert_eq!(status, 200, "admin reads the members");
        Ok(())
    }

    /// A heartbeat taken through the route is in the store file at once.
    #[tokio::test]
    async fn success_an_accepted_heartbeat_is_on_disk() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        let bytes = std::fs::read(dir.path().join("center.store"))?;
        let log = crate::app::fleet_seal::open_log(
            &bytes,
            &test_keys(1),
            crate::app::fleet_seal::Kind::Registry,
        )
        .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(log.records.last().ok_or("a record")?).into_owned();
        assert!(
            text.contains("\"member\":\"edge-a\""),
            "appended before the answer: {text}"
        );
        Ok(())
    }

    /// The members answer carries the center's settings.
    #[test]
    fn success_the_answer_carries_the_settings() -> Result<(), TestError> {
        let v = Registry::default().report(t("2026-11-07T12:00:00Z")?, 5, 24);
        assert_eq!(
            (
                v["silent_after_missed"].clone(),
                v["retention_hours"].clone(),
                v["now"].clone()
            ),
            (5.into(), 24.into(), "2026-11-07T12:00:00Z".into()),
            "{v}"
        );
        Ok(())
    }

    // ── FAILURE ─────────────────────────────────────────────────────────

    /// A body that is not UTF-8 is refused.
    #[test]
    fn failure_a_body_that_is_not_utf8_is_refused() {
        assert!(
            parse_batch(&[0xff, 0xfe, b'\n']).is_err_and(|e| e.contains("UTF-8")),
            "not UTF-8"
        );
    }

    /// A record without its `inventory` is refused, by line.
    #[test]
    fn failure_a_record_without_an_inventory_is_refused() {
        let body = without("inventory") + "\n";
        assert!(
            parse_batch(body.as_bytes())
                .is_err_and(|e| e == "line 1: inventory must be a JSON object"),
            "a missing field"
        );
    }

    /// An inventory of `null` is refused.
    #[test]
    fn failure_a_null_inventory_is_refused() {
        let body = record(serde_json::json!({"inventory": null}));
        assert!(
            parse_batch(body.as_bytes()).is_err_and(|e| e.contains("inventory")),
            "null inventory"
        );
    }

    /// No `Authorization` header: `401`.
    #[tokio::test]
    async fn failure_no_credential_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", None, line()).await?.0,
            401,
            "no header"
        );
        Ok(())
    }

    /// A `Basic` credential: `401`.
    #[tokio::test]
    async fn failure_a_basic_credential_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let auth = format!("Basic {}", member("edge-a"));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line())
                .await?
                .0,
            401,
            "Basic"
        );
        Ok(())
    }

    /// An expired member token: `401`.
    #[tokio::test]
    async fn failure_an_expired_token_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            -10,
            crate::auth::AUDIENCE_API,
        );
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            401,
            "expired"
        );
        Ok(())
    }

    /// A member token minted for the MCP audience: `401`.
    #[tokio::test]
    async fn failure_an_mcp_audience_token_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_MCP,
        );
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            401,
            "mcp audience"
        );
        Ok(())
    }

    /// A token id longer than a member name: `403`.
    #[tokio::test]
    async fn failure_a_token_id_too_long_is_403() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = member(&"a".repeat(MAX_ID_LEN + 1));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            403,
            "65 characters"
        );
        Ok(())
    }

    /// A body past the limit: `413`, and nothing counted.
    #[tokio::test]
    async fn failure_an_oversized_body_is_413() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let body = vec![b'x'; MAX_INGEST_BYTES + 1];
        let (status, _) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            body,
        )
        .await?;
        assert_eq!(status, 413, "past MAX_INGEST_BYTES");
        Ok(())
    }

    /// Past the rate limit: `503`, before the credential is looked at.
    #[tokio::test]
    async fn failure_past_the_rate_limit_is_503() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 1)?;
        let auth = bearer(&member("edge-a"));
        call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line()).await?;
        let (status, _) = call(&st, "POST", "/v1/fleet/ingest", None, line()).await?;
        assert_eq!(status, 503, "the second request in the second");
        Ok(())
    }

    /// The ingest takes `POST` only.
    #[tokio::test]
    async fn failure_get_on_the_ingest_is_405() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let (status, _) = call(
            &st,
            "GET",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            Vec::new(),
        )
        .await?;
        assert_eq!(status, 405, "GET");
        Ok(())
    }

    /// A store that cannot be written: `503`, and the heartbeat is not
    /// counted, so the member sends it again.
    #[tokio::test]
    async fn failure_an_unwritable_store_is_503_and_counts_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        std::fs::remove_file(dir.path().join("center.store"))?;
        std::fs::create_dir(dir.path().join("center.store"))?;
        let (status, _) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        assert_eq!(status, 503, "the append failed");
        assert!(
            st.center.lock().registry.records().is_empty(),
            "nothing counted"
        );
        Ok(())
    }

    /// A store path that is a directory is refused.
    #[test]
    fn failure_a_store_that_is_a_directory_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert!(
            Store::open(dir.path(), test_keys(1)).is_err(),
            "a directory"
        );
        Ok(())
    }

    /// A route the center does not serve: `404`.
    #[tokio::test]
    async fn failure_an_unknown_route_is_404() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "op",
            crate::auth::SCOPE_FULL,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (status, _) = call(&st, "GET", "/v1/dialogs", Some(&bearer(&tok)), Vec::new()).await?;
        assert_eq!(status, 404, "the center serves no dialogs");
        Ok(())
    }

    // ── EDGE ────────────────────────────────────────────────────────────

    /// Zero members: an empty list.
    #[tokio::test]
    async fn edge_zero_members_is_an_empty_list() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "r",
            crate::auth::SCOPE_INVENTORY,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (_, body) = call(
            &st,
            "GET",
            "/v1/fleet/members",
            Some(&bearer(&tok)),
            Vec::new(),
        )
        .await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(v["members"], serde_json::json!([]), "{v}");
        Ok(())
    }

    /// A member clock far ahead holds the cursor there: another stream's
    /// record sent "earlier" is not new until the clock passes it.
    #[test]
    fn edge_a_clock_far_ahead_holds_the_cursor() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 1,
            sent_at: t("2030-01-01T00:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:00Z")?),
            "behind a future send time"
        );
        Ok(())
    }

    /// A new stream sent at exactly the newest send time is not new.
    #[test]
    fn edge_a_new_stream_at_the_same_instant_is_not_new() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 1,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:00Z")?),
            "a tie"
        );
        Ok(())
    }

    /// The largest interval and count do not overflow the silence check.
    #[test]
    fn edge_the_silence_check_does_not_overflow() -> Result<(), TestError> {
        let last = t("2026-11-07T12:00:00Z")?;
        assert!(
            !is_silent(t("2026-11-08T12:00:00Z")?, last, u64::MAX, u32::MAX),
            "saturates rather than wraps"
        );
        Ok(())
    }

    /// Retention on an empty registry removes nothing.
    #[test]
    fn edge_retention_on_no_members_removes_nothing() -> Result<(), TestError> {
        let mut reg = Registry::default();
        assert!(
            reg.expire(t("2026-11-07T12:00:00Z")?, chrono::Duration::hours(1))
                .is_empty(),
            "none"
        );
        Ok(())
    }

    /// A member id of exactly 64 characters reports.
    #[tokio::test]
    async fn edge_a_64_character_member_reports() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = member(&"m".repeat(MAX_ID_LEN));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            200,
            "64"
        );
        Ok(())
    }

    /// Unicode in an inventory reaches the members answer unchanged.
    #[test]
    fn edge_unicode_in_the_inventory_is_kept() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let mut h = hb("s", 1, "2026-11-07T12:00:00Z")?;
        h.inventory = serde_json::json!({"node_name": "edge-zürich-東京"});
        let p = reg.plan("a", "192.0.2.1", t("2026-11-07T12:00:00Z")?, &[h]);
        reg.commit(p);
        let v = reg.report(t("2026-11-07T12:00:01Z")?, 3, 72);
        assert_eq!(
            v["members"][0]["self_reported"]["inventory"]["node_name"], "edge-zürich-東京",
            "{v}"
        );
        Ok(())
    }

    /// A record repeated inside one batch is counted once.
    #[test]
    fn edge_a_record_repeated_in_one_batch_counts_once() -> Result<(), TestError> {
        let reg = Registry::default();
        let h = hb("s", 1, "2026-11-07T12:00:00Z")?;
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[h.clone(), h],
        );
        assert_eq!((p.accepted, p.duplicate), (1, 1), "{p:?}");
        Ok(())
    }

    /// The largest position is accepted, and nothing in that stream follows.
    #[test]
    fn edge_the_largest_position_ends_the_stream() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s".into(),
            seq: u64::MAX,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s", u64::MAX, "2026-11-07T12:01:00Z")?),
            "no seq past MAX"
        );
        Ok(())
    }

    /// An empty store file opens with no members.
    #[test]
    fn edge_an_empty_store_opens_empty() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        Store::open(&path, test_keys(1))?;
        assert!(Store::open(&path, test_keys(1))?.1.is_empty(), "no records");
        Ok(())
    }

    /// Blank lines between the records of a store written in clear are
    /// passed over when it is imported.
    #[test]
    fn edge_blank_lines_in_the_store_are_passed_over() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 1, "2026-11-07T12:00:00Z")?],
        );
        store.append(p.record.as_ref().ok_or("r")?)?;
        let text = format!(
            "{}\n",
            serde_json::to_string(p.record.as_ref().ok_or("r")?)?
        );
        std::fs::write(&path, format!("\n{text}\n\n{text}"))?;
        assert_eq!(
            Store::open(&path, test_keys(1))?.1.len(),
            2,
            "two records, blank lines skipped"
        );
        Ok(())
    }

    /// Rewriting an empty registry leaves a sealed store with no records.
    #[test]
    fn edge_compacting_no_members_leaves_an_empty_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        store.compact(&Registry::default())?;
        drop(store);
        assert_eq!(
            std::fs::read(&path)?.len(),
            crate::app::fleet_seal::HEADER_BYTES + 4 + 1 + 8 + 16,
            "a header and the end of an empty base"
        );
        assert!(Store::open(&path, test_keys(1))?.1.is_empty(), "no records");
        Ok(())
    }

    /// A receive time after `now` (the clock stepped back) reports zero
    /// seconds, never a negative age.
    #[test]
    fn edge_a_receive_time_in_the_future_reports_zero_seconds() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:10:00Z")?,
            &[hb("s", 1, "2026-11-07T12:10:00Z")?],
        );
        reg.commit(p);
        let v = reg.report(t("2026-11-07T12:00:00Z")?, 3, 72);
        assert_eq!(v["members"][0]["seconds_since_heartbeat"], 0, "{v}");
        Ok(())
    }

    /// Plain HTTP on a routable IPv6 address is refused.
    #[test]
    fn edge_plain_http_on_routable_ipv6_is_refused() -> Result<(), TestError> {
        assert!(
            plain_http_refusal("[2001:db8::1]:8444".parse()?, false).is_some(),
            "routable IPv6"
        );
        Ok(())
    }

    /// An IPv4-mapped IPv6 peer is reported as its IPv4 address.
    #[tokio::test]
    async fn edge_an_ipv4_mapped_peer_is_reported_as_ipv4() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/fleet/ingest")
            .header("authorization", bearer(&member("edge-a")))
            .body(axum::body::Body::from(line()))?;
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "[::ffff:192.0.2.7]:40000".parse::<std::net::SocketAddr>()?,
        ));
        router(st.clone()).oneshot(req).await?;
        assert_eq!(
            st.center.lock().registry.records()[0].peer,
            "192.0.2.7",
            "canonical"
        );
        Ok(())
    }

    /// A call line as a member writes it, for the call `call_id`.
    fn call_line(
        stream: &str,
        seq: u64,
        sent_at: &str,
        call_id: &str,
    ) -> Result<String, TestError> {
        Ok(crate::app::fleet_calls::call_line(
            stream,
            seq,
            t(sent_at)?,
            "failed",
            &serde_json::json!({"call_id": call_id, "from": "sip:+12025550101@example.com"}),
        ))
    }

    /// A call record with `change` applied to the JSON a member writes.
    fn call_with(change: impl Fn(&mut serde_json::Map<String, serde_json::Value>)) -> String {
        let line = call_line("s-1", 1, "2026-11-07T12:00:00Z", "a@example.com").unwrap_or_default();
        let mut v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            change(o);
        }
        v.to_string()
    }

    /// Why the center refuses `body`.
    fn refusal(body: &str) -> String {
        parse_batch(body.as_bytes()).err().unwrap_or_default()
    }

    #[test]
    fn success_a_call_line_is_what_the_center_reads() -> Result<(), TestError> {
        let line = call_line("s-1", 7, "2026-11-07T12:00:00.5Z", "a@example.com")?;
        let got = parse_batch(line.as_bytes())?;
        let want = CallRecord {
            stream: "s-1".to_string(),
            seq: 7,
            sent_at: t("2026-11-07T12:00:00.5Z")?,
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": "a@example.com", "from": "sip:+12025550101@example.com"}),
        };
        assert_eq!(
            got,
            vec![Record::Call(want)],
            "success a call line is what the center reads"
        );
        Ok(())
    }

    #[test]
    fn success_a_body_of_heartbeats_and_calls_keeps_their_order() -> Result<(), TestError> {
        let body = format!(
            "{}\n{}{}\n",
            record(serde_json::json!({"seq": 1})),
            call_line("s-1", 2, "2026-11-07T12:00:01Z", "a@example.com")?,
            record(serde_json::json!({"seq": 3})),
        );
        let got = parse_batch(body.as_bytes())?;
        let kinds: Vec<bool> = got.iter().map(|r| r.call().is_some()).collect();
        assert_eq!(
            kinds,
            vec![false, true, false],
            "success a body of heartbeats and calls keeps their order"
        );
        assert_eq!(
            got[1].call().map(|c| c.seq),
            Some(2),
            "success a body of heartbeats and calls keeps their order"
        );
        assert_eq!(
            got[2].heartbeat().map(|h| h.seq),
            Some(3),
            "success a body of heartbeats and calls keeps their order"
        );
        Ok(())
    }

    #[test]
    fn failure_a_call_record_without_its_call_is_refused() {
        let body = call_with(|o| {
            o.remove("call");
        });
        assert_eq!(
            refusal(&body),
            "line 1: call must be a JSON object",
            "failure a call record without its call is refused"
        );
    }

    #[test]
    fn failure_a_call_that_is_not_an_object_is_refused() {
        for value in [
            serde_json::json!("text"),
            serde_json::json!(null),
            serde_json::json!([1]),
        ] {
            let body = call_with(|o| {
                o.insert("call".to_string(), value.clone());
            });
            assert_eq!(
                refusal(&body),
                "line 1: call must be a JSON object",
                "{value}"
            );
        }
    }

    #[test]
    fn failure_a_call_record_must_say_what_selected_it() {
        let long = "x".repeat(65);
        for value in [None, Some(""), Some("has space"), Some(long.as_str())] {
            let body = call_with(|o| {
                o.remove("selected_by");
                if let Some(v) = value {
                    o.insert("selected_by".to_string(), serde_json::json!(v));
                }
            });
            assert_eq!(
                refusal(&body),
                "line 1: selected_by must be 1 to 64 letters, digits, '.', '_' or '-'",
                "{value:?}"
            );
        }
    }

    #[test]
    fn failure_a_record_of_an_unknown_kind_names_the_two_the_center_reads() {
        let body = record(serde_json::json!({"kind": "rollup"}));
        assert_eq!(
            refusal(&body),
            "line 1: kind \"rollup\"; this center accepts \"heartbeat\" and \"call\"",
            "failure a record of an unknown kind names the two the center reads"
        );
    }

    #[test]
    fn failure_a_call_record_keeps_the_rules_of_its_position() {
        let no_seq = call_with(|o| {
            o.insert("seq".to_string(), serde_json::json!(0));
        });
        assert_eq!(
            refusal(&no_seq),
            "line 1: seq must be 1 or more",
            "failure a call record keeps the rules of its position"
        );
        let bad_time = call_with(|o| {
            o.insert("sent_at".to_string(), serde_json::json!("yesterday"));
        });
        assert!(
            refusal(&bad_time).contains("is not an RFC 3339 time"),
            "{}",
            refusal(&bad_time)
        );
        let version = call_with(|o| {
            o.insert("schema_version".to_string(), serde_json::json!(2));
        });
        assert!(
            refusal(&version).starts_with("line 1: schema_version 2;"),
            "{}",
            refusal(&version)
        );
    }

    #[test]
    fn edge_a_heartbeat_may_carry_the_members_call_counts() -> Result<(), TestError> {
        let counts = crate::app::fleet_calls::CallCounts {
            selected: 9,
            dropped_by_cap: 3,
            left_out: 1,
            spooled: 8,
        };
        let with = record(serde_json::json!({"calls": counts}));
        let got = parse_heartbeats(with.as_bytes())?;
        assert_eq!(
            got[0].calls,
            Some(counts),
            "edge a heartbeat may carry the members call counts"
        );
        let without = record(serde_json::json!({}));
        assert_eq!(
            parse_heartbeats(without.as_bytes())?[0].calls,
            None,
            "edge a heartbeat may carry the members call counts"
        );
        Ok(())
    }

    #[test]
    fn failure_call_counts_that_are_not_counts_refuse_the_heartbeat() {
        let body = record(serde_json::json!({"calls": {"selected": "many"}}));
        assert!(
            refusal(&body).starts_with("line 1: not a record"),
            "{}",
            refusal(&body)
        );
    }

    /// The call record at `seq` of stream `s`, sent at `sent_at`.
    fn call_at(seq: u64, sent_at: &str) -> Result<Record, TestError> {
        let line = call_line("s", seq, sent_at, &format!("call-{seq}@example.com"))?;
        Ok(parse_batch(line.as_bytes())?.remove(0))
    }

    /// A registry that took one heartbeat of stream `s` at position 1 from
    /// `edge-a`.
    fn registry_with_a_heartbeat() -> Result<Registry, TestError> {
        let mut reg = Registry::default();
        let first = [Record::Heartbeat(hb("s", 1, "2026-11-07T12:00:00Z")?)];
        let plan = reg.plan_records("edge-a", "192.0.2.7", t("2026-11-07T12:00:00Z")?, &first);
        reg.commit(plan);
        Ok(reg)
    }

    #[test]
    fn success_a_new_call_record_moves_the_position_and_goes_to_the_intake() -> Result<(), TestError>
    {
        let reg = registry_with_a_heartbeat()?;
        let batch = [
            call_at(2, "2026-11-07T12:00:05Z")?,
            call_at(3, "2026-11-07T12:00:06Z")?,
        ];
        let plan = reg.plan_records("edge-a", "192.0.2.7", t("2026-11-07T12:00:07Z")?, &batch);
        assert_eq!(
            (plan.accepted, plan.duplicate),
            (2, 0),
            "success a new call record moves the position and goes to the intake"
        );
        let seqs: Vec<u64> = plan.calls.iter().map(|c| c.seq).collect();
        assert_eq!(seqs, vec![2, 3], "both go to the intake, in order");
        let record = plan.record.ok_or("the member's record")?;
        assert_eq!(
            record.cursor.seq, 3,
            "success a new call record moves the position and goes to the intake"
        );
        assert_eq!(
            record.cursor.sent_at,
            t("2026-11-07T12:00:06Z")?,
            "success a new call record moves the position and goes to the intake"
        );
        assert_eq!(
            record.call_records, 2,
            "success a new call record moves the position and goes to the intake"
        );
        Ok(())
    }

    #[test]
    fn failure_a_replayed_call_record_is_a_duplicate_and_not_for_the_intake()
    -> Result<(), TestError> {
        let mut reg = registry_with_a_heartbeat()?;
        let batch = [call_at(2, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let first = reg.plan_records("edge-a", "192.0.2.7", now, &batch);
        reg.commit(first);
        let again = reg.plan_records("edge-a", "192.0.2.7", now, &batch);
        assert_eq!(
            (again.accepted, again.duplicate),
            (0, 1),
            "failure a replayed call record is a duplicate and not for the intake"
        );
        assert!(
            again.calls.is_empty() && again.record.is_none(),
            "{again:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_batch_that_repeats_a_call_record_stores_it_once() -> Result<(), TestError> {
        let reg = registry_with_a_heartbeat()?;
        let batch = [
            call_at(2, "2026-11-07T12:00:05Z")?,
            call_at(2, "2026-11-07T12:00:05Z")?,
        ];
        let plan = reg.plan_records("edge-a", "192.0.2.7", t("2026-11-07T12:00:07Z")?, &batch);
        assert_eq!(
            (plan.accepted, plan.duplicate, plan.calls.len()),
            (1, 1, 1),
            "edge a batch that repeats a call record stores it once"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_record_does_not_count_as_a_heartbeat() -> Result<(), TestError> {
        let reg = registry_with_a_heartbeat()?;
        let batch = [call_at(2, "2026-11-07T12:00:05Z")?];
        let plan = reg.plan_records("edge-a", "198.51.100.9", t("2026-11-07T13:00:00Z")?, &batch);
        let record = plan.record.ok_or("the member's record")?;
        assert_eq!(
            record.heartbeats, 1,
            "edge a call record does not count as a heartbeat"
        );
        assert_eq!(
            record.received_at,
            t("2026-11-07T12:00:00Z")?,
            "silence is counted from heartbeats"
        );
        assert_eq!(record.peer, "192.0.2.7", "and so is the address");
        assert_eq!(
            record.inventory,
            serde_json::json!({"node_name": "edge-a"}),
            "edge a call record does not count as a heartbeat"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_record_before_any_heartbeat_makes_a_member_with_no_inventory()
    -> Result<(), TestError> {
        let reg = Registry::default();
        let now = t("2026-11-07T12:00:07Z")?;
        let plan = reg.plan_records(
            "edge-new",
            "192.0.2.7",
            now,
            &[call_at(5, "2026-11-07T12:00:05Z")?],
        );
        assert_eq!(
            plan.calls.len(),
            1,
            "edge a call record before any heartbeat makes a member with no inventory"
        );
        let record = plan.record.ok_or("the member's record")?;
        assert_eq!(
            (record.heartbeats, record.call_records),
            (0, 1),
            "edge a call record before any heartbeat makes a member with no inventory"
        );
        assert_eq!(
            record.inventory,
            serde_json::json!({}),
            "edge a call record before any heartbeat makes a member with no inventory"
        );
        assert_eq!(
            record.heartbeat_secs,
            crate::app::fleet_member::DEFAULT_HEARTBEAT_SECS,
            "edge a call record before any heartbeat makes a member with no inventory"
        );
        assert_eq!(
            record.received_at, now,
            "edge a call record before any heartbeat makes a member with no inventory"
        );
        Ok(())
    }

    #[test]
    fn success_a_heartbeat_after_calls_keeps_their_count_and_brings_the_members_own()
    -> Result<(), TestError> {
        let mut reg = registry_with_a_heartbeat()?;
        let now = t("2026-11-07T12:00:40Z")?;
        let calls = reg.plan_records(
            "edge-a",
            "192.0.2.7",
            now,
            &[call_at(2, "2026-11-07T12:00:05Z")?],
        );
        reg.commit(calls);
        let counts = crate::app::fleet_calls::CallCounts {
            selected: 4,
            spooled: 4,
            ..Default::default()
        };
        let mut beat = hb("s", 3, "2026-11-07T12:00:30Z")?;
        beat.calls = Some(counts);
        let plan = reg.plan_records("edge-a", "192.0.2.7", now, &[Record::Heartbeat(beat)]);
        let record = plan.record.clone().ok_or("the member's record")?;
        assert_eq!(
            (record.heartbeats, record.call_records),
            (2, 1),
            "success a heartbeat after calls keeps their count and brings the members own"
        );
        assert_eq!(
            record.calls,
            Some(counts),
            "success a heartbeat after calls keeps their count and brings the members own"
        );
        reg.commit(plan);
        let report = reg.report(now, 3, 72);
        let row = &report["members"][0];
        assert_eq!(row["verified"]["call_records"], 1, "{row}");
        assert_eq!(row["self_reported"]["calls"]["selected"], 4, "{row}");
        Ok(())
    }

    #[test]
    fn edge_a_store_record_written_before_call_records_reads_with_none() -> Result<(), TestError> {
        let old = serde_json::json!({
            "member": "edge-a", "received_at": "2026-11-07T12:00:00Z", "peer": "192.0.2.7",
            "heartbeats": 3, "heartbeat_secs": 30, "inventory": {},
            "cursor": {"stream": "s", "seq": 3, "sent_at": "2026-11-07T12:00:00Z"},
        });
        let record: MemberRecord = serde_json::from_value(old)?;
        assert_eq!(
            (record.call_records, record.calls),
            (0, None),
            "edge a store record written before call records reads with none"
        );
        Ok(())
    }

    /// The center in `dir` under key 1 as it stands at `now`.
    fn center_at(dir: &Path, now: &str) -> Result<Center, TestError> {
        let keep = chrono::Duration::hours(72);
        Ok(Center::open(&dir.join("center.store"), test_keys(1), t(now)?, keep)?.0)
    }

    /// The Call-IDs in the intake of the center in `dir`.
    fn intake_ids(dir: &Path) -> Result<Vec<String>, TestError> {
        let path = crate::app::fleet_intake::path_for(&dir.join("center.store"));
        let bytes = std::fs::read(path)?;
        let log = crate::app::fleet_seal::open_log(
            &bytes,
            &test_keys(1),
            crate::app::fleet_seal::Kind::Intake,
        )
        .map_err(|e| e.to_string())?;
        let mut ids = Vec::new();
        for line in &log.records {
            let v: serde_json::Value = serde_json::from_slice(line)?;
            ids.push(
                v["call"]["call_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
        }
        Ok(ids)
    }

    #[test]
    fn success_taken_call_records_are_in_the_intake_before_the_answer() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let batch = [
            Record::Heartbeat(hb("s", 1, "2026-11-07T12:00:00Z")?),
            call_at(2, "2026-11-07T12:00:05Z")?,
            call_at(3, "2026-11-07T12:00:06Z")?,
        ];
        let got = center.take("edge-a", "192.0.2.7", t("2026-11-07T12:00:07Z")?, &batch)?;
        assert_eq!(
            got,
            (3, 0, 2),
            "success taken call records are in the intake before the answer"
        );
        assert_eq!(
            intake_ids(dir.path())?,
            vec!["call-2@example.com", "call-3@example.com"],
            "success taken call records are in the intake before the answer"
        );
        Ok(())
    }

    #[test]
    fn failure_a_replayed_batch_of_call_records_is_not_stored_twice() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let batch = [
            call_at(1, "2026-11-07T12:00:05Z")?,
            call_at(2, "2026-11-07T12:00:06Z")?,
        ];
        let now = t("2026-11-07T12:00:07Z")?;
        assert_eq!(
            center.take("edge-a", "192.0.2.7", now, &batch)?,
            (2, 0, 2),
            "failure a replayed batch of call records is not stored twice"
        );
        assert_eq!(
            center.take("edge-a", "192.0.2.7", now, &batch)?,
            (0, 2, 0),
            "failure a replayed batch of call records is not stored twice"
        );
        assert_eq!(
            intake_ids(dir.path())?.len(),
            2,
            "failure a replayed batch of call records is not stored twice"
        );
        Ok(())
    }

    #[test]
    fn failure_a_replay_after_a_restart_is_not_stored_twice() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let batch = [call_at(1, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        center.take("edge-a", "192.0.2.7", now, &batch)?;
        drop(center);
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.take("edge-a", "192.0.2.7", now, &batch)?,
            (0, 1, 0),
            "failure a replay after a restart is not stored twice"
        );
        assert_eq!(
            intake_ids(dir.path())?,
            vec!["call-1@example.com"],
            "failure a replay after a restart is not stored twice"
        );
        Ok(())
    }

    #[test]
    fn edge_a_record_stored_before_a_crash_noted_its_position_is_still_a_duplicate()
    -> Result<(), TestError> {
        // The center stopped after the intake held the record and before the
        // store held the member's new position.
        let dir = tempfile::tempdir()?;
        let batch = [call_at(1, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let call = batch[0].call().cloned().ok_or("a call")?;
        center
            .intake
            .append(&[crate::app::fleet_intake::IntakeRecord::new(
                "edge-a", now, call,
            )])?;
        drop(center);
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.registry.records()[0].call_records,
            1,
            "counted from the intake"
        );
        assert_eq!(
            again.take("edge-a", "192.0.2.7", now, &batch)?,
            (0, 1, 0),
            "edge a record stored before a crash noted its position is still a duplicate"
        );
        assert_eq!(
            intake_ids(dir.path())?.len(),
            1,
            "edge a record stored before a crash noted its position is still a duplicate"
        );
        Ok(())
    }

    #[test]
    fn edge_the_position_from_the_intake_is_in_the_store_after_the_start() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let call = call_at(4, "2026-11-07T12:00:05Z")?
            .call()
            .cloned()
            .ok_or("a call")?;
        center
            .intake
            .append(&[crate::app::fleet_intake::IntakeRecord::new(
                "edge-a", now, call,
            )])?;
        drop(center);
        drop(center_at(dir.path(), "2026-11-07T12:01:00Z")?);
        let (_, records) = Store::open(&dir.path().join("center.store"), test_keys(1))?;
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(
            (records[0].cursor.seq, records[0].call_records),
            (4, 1),
            "edge the position from the intake is in the store after the start"
        );
        Ok(())
    }

    #[test]
    fn edge_retention_removes_old_call_records_and_keeps_new_ones() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut center = center_at(dir.path(), "2026-11-01T00:00:00Z")?;
        center.take(
            "edge-a",
            "192.0.2.7",
            t("2026-11-01T00:00:00Z")?,
            &[call_at(1, "2026-11-01T00:00:00Z")?],
        )?;
        center.take(
            "edge-a",
            "192.0.2.7",
            t("2026-11-03T12:00:00Z")?,
            &[call_at(2, "2026-11-03T12:00:00Z")?],
        )?;
        apply_retention(&mut center, t("2026-11-04T00:00:01Z")?, 72);
        assert_eq!(
            center.intake.records(),
            1,
            "edge retention removes old call records and keeps new ones"
        );
        assert_eq!(
            intake_ids(dir.path())?,
            vec!["call-2@example.com"],
            "edge retention removes old call records and keeps new ones"
        );
        Ok(())
    }

    #[tokio::test]
    async fn success_the_ingest_answers_with_the_call_records_it_stored() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = bearer(&token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_API,
        ));
        let body = format!(
            "{}{}",
            call_line("s", 1, "2026-11-07T12:00:05Z", "a@example.com")?,
            call_line("s", 2, "2026-11-07T12:00:06Z", "b@example.com")?
        );
        let (status, text) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&tok),
            body.clone().into_bytes(),
        )
        .await?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(
            (status, &v["accepted"], &v["duplicate"], &v["calls"]),
            (
                200,
                &serde_json::json!(2),
                &serde_json::json!(0),
                &serde_json::json!(2)
            ),
            "{text}"
        );
        let (_, text) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&tok),
            body.into_bytes(),
        )
        .await?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(
            (&v["accepted"], &v["duplicate"], &v["calls"]),
            (
                &serde_json::json!(0),
                &serde_json::json!(2),
                &serde_json::json!(0)
            ),
            "{text}"
        );
        assert_eq!(
            intake_ids(dir.path())?,
            vec!["a@example.com", "b@example.com"],
            "success the ingest answers with the call records it stored"
        );
        Ok(())
    }

    #[tokio::test]
    async fn success_the_members_answer_counts_the_intake() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = bearer(&token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_API,
        ));
        let body = call_line("s", 1, "2026-11-07T12:00:05Z", "a@example.com")?;
        call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&tok),
            body.into_bytes(),
        )
        .await?;
        let reader = bearer(&token(
            "ops",
            crate::auth::SCOPE_INVENTORY,
            3600,
            crate::auth::AUDIENCE_API,
        ));
        let (status, text) =
            call(&st, "GET", "/v1/fleet/members", Some(&reader), Vec::new()).await?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(status, 200, "{text}");
        assert_eq!(v["intake"]["call_records"], 1, "{text}");
        assert!(
            v["intake"]["bytes"].as_u64().is_some_and(|b| b > 100),
            "{text}"
        );
        assert_eq!(v["intake"]["removed"], 0, "{text}");
        assert_eq!(v["members"][0]["verified"]["call_records"], 1, "{text}");
        Ok(())
    }

    /// When the intake cannot take a record, the member's position does not
    /// move: the record is refused whole, and taken as new when the member
    /// sends it again.
    #[cfg(unix)]
    #[test]
    fn failure_a_record_the_intake_could_not_take_leaves_the_position_where_it_was()
    -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let batch = [call_at(1, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let intake = crate::app::fleet_intake::path_for(&dir.path().join("center.store"));
        std::fs::set_permissions(&intake, std::fs::Permissions::from_mode(0o400))?;
        assert!(
            center.take("edge-a", "192.0.2.7", now, &batch).is_err(),
            "the intake cannot be appended to"
        );
        assert!(
            center.registry.records().is_empty(),
            "no position was noted"
        );
        drop(center);
        std::fs::set_permissions(&intake, std::fs::Permissions::from_mode(0o600))?;
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.take("edge-a", "192.0.2.7", now, &batch)?,
            (1, 0, 1),
            "the same record is new: neither file held it"
        );
        Ok(())
    }

    /// When the intake took a call record and the store then could not
    /// take the member's position, the member sends the record again. It
    /// is in the intake once.
    #[test]
    fn failure_a_record_the_intake_took_before_the_store_failed_is_not_stored_twice()
    -> Result<(), TestError> {
        use crate::app::fleet_log::faults::{real, refuse};
        let dir = tempfile::tempdir()?;
        let batch = [call_at(1, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        center.store.log_mut().open_with(refuse(libc::EIO));
        assert!(
            center.take("edge-a", "192.0.2.7", now, &batch).is_err(),
            "the store cannot be appended to"
        );
        center.store.log_mut().open_with(real());
        center.take("edge-a", "192.0.2.7", now, &batch)?;
        assert_eq!(
            intake_ids(dir.path())?.len(),
            1,
            "failure a record the intake took before the store failed is not stored twice"
        );
        Ok(())
    }

    /// A center whose store failed after its intake took `calls` call
    /// records from `edge-a`, with the store's real file back in place.
    fn center_after_a_store_failure(
        dir: &Path,
        calls: u64,
    ) -> Result<(Center, Vec<Record>), TestError> {
        use crate::app::fleet_log::faults::{real, stop_at};
        let batch = (1..=calls)
            .map(|seq| call_at(seq, "2026-11-07T12:00:05Z"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut center = center_at(dir, "2026-11-07T12:00:00Z")?;
        center.store.log_mut().open_with(stop_at(11, libc::ENOSPC));
        if center
            .take("edge-a", "192.0.2.7", t("2026-11-07T12:00:07Z")?, &batch)
            .is_ok()
        {
            return Err("the store did not fail".into());
        }
        center.store.log_mut().open_with(real());
        Ok((center, batch))
    }

    #[test]
    fn success_the_next_try_after_a_store_failure_is_acknowledged_as_duplicates()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (mut center, batch) = center_after_a_store_failure(dir.path(), 3)?;
        assert_eq!(
            center.take("edge-a", "192.0.2.7", t("2026-11-07T12:00:09Z")?, &batch)?,
            (0, 3, 0),
            "success the next try after a store failure is acknowledged as duplicates"
        );
        assert_eq!(intake_ids(dir.path())?.len(), 3, "each record is held once");
        Ok(())
    }

    #[test]
    fn success_a_record_after_the_ones_the_intake_took_is_new_and_the_store_reopens()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (mut center, mut batch) = center_after_a_store_failure(dir.path(), 2)?;
        batch.push(call_at(3, "2026-11-07T12:00:06Z")?);
        assert_eq!(
            center.take("edge-a", "192.0.2.7", t("2026-11-07T12:00:09Z")?, &batch)?,
            (1, 2, 1),
            "the third record is new"
        );
        drop(center);
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.take("edge-a", "192.0.2.7", t("2026-11-07T12:01:01Z")?, &batch)?,
            (0, 3, 0),
            "success a record after the ones the intake took is new and the store reopens"
        );
        assert_eq!(intake_ids(dir.path())?.len(), 3, "each record is held once");
        Ok(())
    }

    #[test]
    fn edge_a_center_stopped_after_a_store_failure_starts_with_each_record_once()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (center, batch) = center_after_a_store_failure(dir.path(), 2)?;
        drop(center);
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.take("edge-a", "192.0.2.7", t("2026-11-07T12:01:01Z")?, &batch)?,
            (0, 2, 0),
            "the records the intake holds are duplicates after the start"
        );
        assert_eq!(
            intake_ids(dir.path())?.len(),
            2,
            "edge a center stopped after a store failure starts with each record once"
        );
        Ok(())
    }

    #[test]
    fn edge_a_store_failure_counts_the_call_records_the_intake_took() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (center, _) = center_after_a_store_failure(dir.path(), 2)?;
        let records = center.registry.records();
        assert_eq!(
            records.iter().map(|r| r.call_records).collect::<Vec<_>>(),
            [2],
            "edge a store failure counts the call records the intake took"
        );
        Ok(())
    }

    #[test]
    fn failure_an_intake_failure_still_leaves_the_position_where_it_was() -> Result<(), TestError> {
        use crate::app::fleet_log::faults::{real, stop_at};
        let dir = tempfile::tempdir()?;
        let batch = [call_at(1, "2026-11-07T12:00:05Z")?];
        let now = t("2026-11-07T12:00:07Z")?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        center.intake.log_mut().open_with(stop_at(30, libc::ENOSPC));
        assert!(
            center.take("edge-a", "192.0.2.7", now, &batch).is_err(),
            "the intake cannot be appended to"
        );
        assert!(
            center.registry.records().is_empty(),
            "no position was noted"
        );
        center.intake.log_mut().open_with(real());
        assert_eq!(
            center.take("edge-a", "192.0.2.7", now, &batch)?,
            (1, 0, 1),
            "failure an intake failure still leaves the position where it was"
        );
        assert_eq!(intake_ids(dir.path())?.len(), 1, "the record is held once");
        Ok(())
    }

    // ── THE HISTORY STORE ───────────────────────────────────────────────

    /// A token of `scope` for an operator.
    fn operator(scope: &str) -> String {
        bearer(&token("ops", scope, 3600, crate::auth::AUDIENCE_API))
    }

    /// Post call records `from` to `to` of stream `s` as `member`, each
    /// sent now, and return the status.
    async fn push_calls(
        st: &CenterState,
        member_id: &str,
        from: u64,
        to: u64,
    ) -> Result<u16, TestError> {
        let mut body = String::new();
        for seq in from..=to {
            body.push_str(&call_line(
                "s",
                seq,
                &Utc::now().to_rfc3339(),
                &format!("call-{seq}@example.com"),
            )?);
            body.push('\n');
        }
        let (status, _) = call(
            st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member(member_id))),
            body.into_bytes(),
        )
        .await?;
        Ok(status)
    }

    /// `GET path` with a `full` token: the status and the JSON body.
    async fn get_json(st: &CenterState, path: &str) -> Result<(u16, serde_json::Value), TestError> {
        let (status, body) = call(
            st,
            "GET",
            path,
            Some(&operator(crate::auth::SCOPE_FULL)),
            Vec::new(),
        )
        .await?;
        Ok((status, serde_json::from_str(&body).unwrap_or_default()))
    }

    /// The positions of the calls in an answer of the calls route.
    #[cfg(feature = "fleet-store")]
    fn positions(answer: &serde_json::Value) -> Vec<u64> {
        answer["calls"]
            .as_array()
            .map(|calls| calls.iter().filter_map(|c| c["seq"].as_u64()).collect())
            .unwrap_or_default()
    }

    /// A center in `dir` that took a heartbeat and call records 2 to 4 of
    /// `edge-a`.
    #[cfg(feature = "fleet-store")]
    fn center_with_three_calls(dir: &Path) -> Result<Center, TestError> {
        let mut center = center_at(dir, "2026-11-07T12:00:00Z")?;
        let batch = [
            Record::Heartbeat(hb("s", 1, "2026-11-07T12:00:00Z")?),
            call_at(2, "2026-11-07T12:00:05Z")?,
            call_at(3, "2026-11-07T12:00:06Z")?,
            call_at(4, "2026-11-07T12:00:07Z")?,
        ];
        center.take("edge-a", "192.0.2.7", t("2026-11-07T12:00:08Z")?, &batch)?;
        Ok(center)
    }

    /// Every row the history store of `center` holds, as positions, newest
    /// first.
    #[cfg(feature = "fleet-store")]
    fn filed_positions(center: &Center) -> Result<Vec<u64>, TestError> {
        let query = crate::app::fleet_history::Query {
            limit: 1000,
            ..crate::app::fleet_history::Query::all()
        };
        let answer = center
            .history
            .answer::<crate::app::fleet_intake::IntakeRecord>(
                &query,
                &center.history.list("calls", &query)?,
                Vec::new(),
            );
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}").into());
        }
        Ok(answer.rows.iter().map(|r| r.seq).collect())
    }

    #[test]
    fn success_the_text_of_a_build_without_the_store_names_the_builds_that_have_it() {
        for needle in [
            "fleet-store",
            "GET /v1/fleet/calls and GET /v1/fleet/members/{id}/history answer 501",
            "no heartbeat history is kept",
            "musl",
            "-noaudio",
            "container image",
            "64 MiB",
        ] {
            assert!(
                NO_HISTORY_STORE.contains(needle),
                "success the text says {needle:?}: {NO_HISTORY_STORE}"
            );
        }
        assert_eq!(
            HAS_HISTORY_STORE,
            cfg!(feature = "fleet-store"),
            "success the build knows whether it has the store"
        );
    }

    #[cfg(feature = "fleet-store")]
    #[test]
    fn success_a_filing_moves_the_intake_into_the_history_store() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut center = center_with_three_calls(dir.path())?;
        let filed = center.file_calls()?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (1, 3, 0),
            "success three call records are one file"
        );
        assert_eq!(center.intake.records(), 0, "success the intake is empty");
        assert_eq!(
            filed_positions(&center)?,
            vec![4, 3, 2],
            "success the history store holds the three records"
        );
        assert_eq!(
            center.filing,
            FilingCounts {
                files_written: 1,
                rows_filed: 3,
                ..FilingCounts::default()
            },
            "success and the center counted them"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[test]
    fn success_a_start_files_what_the_intake_held_at_the_stop() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        drop(center_with_three_calls(dir.path())?);
        let center = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            center.intake.records(),
            3,
            "success the records waited in the intake over the stop"
        );
        let shared = parking_lot::Mutex::new(center);
        start_history(&shared, 90, 72);
        let center = shared.into_inner();
        assert_eq!(center.intake.records(), 0, "success the start filed them");
        assert_eq!(
            filed_positions(&center)?,
            vec![4, 3, 2],
            "success into the history store"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn success_the_calls_route_answers_filed_and_waiting_rows() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        assert_eq!(
            push_calls(&st, "edge-a", 1, 3).await?,
            200,
            "success pushed"
        );
        st.center.lock().file_calls()?;
        assert_eq!(
            push_calls(&st, "edge-a", 4, 5).await?,
            200,
            "success pushed"
        );
        let (status, answer) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(status, 200, "success the route answers");
        assert_eq!(
            positions(&answer),
            vec![5, 4, 3, 2, 1],
            "success rows in files and rows still in the intake, newest first"
        );
        assert_eq!(answer["count"], 5, "success five rows");
        assert_eq!(answer["complete"], true, "success complete");
        assert_eq!(answer["files_read"], 1, "success from one file");
        assert_eq!(
            answer["calls"][0]["call"]["call_id"], "call-5@example.com",
            "success a row carries the call the member sent"
        );
        assert_eq!(
            answer["calls"][0]["selected_by"], "failed",
            "success and what selected it"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn success_the_calls_route_narrows_by_member_call_id_and_limit() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 4).await?;
        push_calls(&st, "edge-b", 1, 2).await?;
        st.center.lock().file_calls()?;
        let (_, by_member) = get_json(&st, "/v1/fleet/calls?member=edge-b").await?;
        assert_eq!(
            positions(&by_member),
            vec![2, 1],
            "success one member's rows"
        );
        assert_eq!(
            by_member["files_read"], 1,
            "success from that member's file alone"
        );
        let (_, by_call) = get_json(
            &st,
            "/v1/fleet/calls?member=edge-a&call_id=call-3%40example.com",
        )
        .await?;
        assert_eq!(positions(&by_call), vec![3], "success one call");
        let (_, limited) = get_json(&st, "/v1/fleet/calls?member=edge-a&limit=2").await?;
        assert_eq!(positions(&limited), vec![4, 3], "success the newest two");
        assert_eq!(limited["more"], true, "success and more exist");
        Ok(())
    }

    #[tokio::test]
    async fn success_the_members_report_says_what_the_history_store_did() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 3).await?;
        #[cfg(feature = "fleet-store")]
        st.center.lock().file_calls()?;
        let (status, body) = call(
            &st,
            "GET",
            "/v1/fleet/members",
            Some(&operator(crate::auth::SCOPE_INVENTORY)),
            Vec::new(),
        )
        .await?;
        assert_eq!(status, 200, "success the report answers");
        let report: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(
            report["history"]["available"], HAS_HISTORY_STORE,
            "success the report says whether this build has the store"
        );
        let filed = if HAS_HISTORY_STORE { 3 } else { 0 };
        assert_eq!(
            report["history"]["rows_filed"], filed,
            "success and how many call records it filed"
        );
        assert_eq!(
            report["intake"]["call_records"],
            3 - filed,
            "success the rest wait in the intake"
        );
        assert_eq!(
            report["history"]["retention_days"], 90,
            "success with the retention in days"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failure_the_calls_route_needs_a_token_that_reads_calls() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let (none, _) = call(&st, "GET", "/v1/fleet/calls", None, Vec::new()).await?;
        assert_eq!(none, 401, "failure no token");
        for scope in [
            crate::auth::SCOPE_INVENTORY,
            crate::auth::SCOPE_FLEET_REPORT,
            crate::auth::SCOPE_METRICS,
            crate::auth::SCOPE_READ,
            crate::auth::SCOPE_AUDIO,
        ] {
            let (status, body) = call(
                &st,
                "GET",
                "/v1/fleet/calls",
                Some(&operator(scope)),
                Vec::new(),
            )
            .await?;
            assert_eq!(
                status, 401,
                "failure a {scope} token does not read call records: {body}"
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "fleet-store"))]
    #[tokio::test]
    async fn failure_a_build_without_the_store_answers_501_and_says_why() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 2).await?;
        let (status, answer) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(status, 501, "failure no history store: not an empty list");
        assert_eq!(
            answer["detail"], NO_HISTORY_STORE,
            "failure the problem says which builds have the store"
        );
        assert!(
            !dir.path().join("center.store.parquet").exists(),
            "failure and no history directory was made"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn failure_a_bad_question_is_refused_naming_the_parameter() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        for (query, needle) in [
            ("limit=0", "limit"),
            ("membr=edge-a", "membr"),
            ("from=noon", "from"),
            ("member=a&member=b", "member"),
            ("from=2026-11-11T00:00:02Z&to=2026-11-11T00:00:01Z", "after"),
        ] {
            let (status, answer) = get_json(&st, &format!("/v1/fleet/calls?{query}")).await?;
            assert_eq!(status, 400, "failure ?{query} is a bad request");
            assert!(
                answer["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains(needle)),
                "failure ?{query} names {needle}: {answer}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[test]
    fn failure_a_filing_that_cannot_write_leaves_the_records_in_the_intake() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let mut center = center_with_three_calls(dir.path())?;
        // A file where the class directory goes.
        let class = center.history.dir().join("calls");
        std::fs::write(&class, b"in the way")?;
        let got = center.file_calls();
        assert!(got.is_err(), "failure the filing fails: {got:?}");
        assert_eq!(
            center.intake.records(),
            3,
            "failure the records stay in the intake"
        );
        assert_eq!(center.filing.failed, 1, "failure the failure is counted");
        std::fs::remove_file(&class)?;
        let filed = center.file_calls()?;
        assert_eq!(filed.rows, 3, "failure the next filing files them");
        assert_eq!(center.intake.records(), 0, "failure and empties the intake");
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn failure_a_changed_file_makes_the_answer_say_it_is_not_complete()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 3).await?;
        st.center.lock().file_calls()?;
        push_calls(&st, "edge-a", 4, 4).await?;
        let (_, before) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(before["complete"], true, "failure whole before the change");
        let listed = {
            let center = st.center.lock();
            center
                .history
                .list("calls", &crate::app::fleet_history::Query::all())?
        };
        let path = st.center.lock().history.dir().join(&listed[0].rel);
        let mut bytes = std::fs::read(&path)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let (status, after) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(status, 200, "failure the route still answers");
        assert_eq!(after["complete"], false, "failure and says it is not whole");
        assert_eq!(
            after["refused"][0]["file"],
            listed[0].rel.as_str(),
            "failure naming the file"
        );
        assert_eq!(
            positions(&after),
            vec![4],
            "failure with the rows it could read"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[test]
    fn edge_a_stop_between_filing_and_emptying_files_no_row_twice() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let center = center_with_three_calls(dir.path())?;
        // The files are written and the center stops before it empties the
        // intake.
        center.history.file(&center.intake.rows()?)?;
        drop(center);
        let mut again = center_at(dir.path(), "2026-11-07T12:01:00Z")?;
        assert_eq!(
            again.intake.records(),
            3,
            "edge the intake still holds them"
        );
        let filed = again.file_calls()?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (0, 0, 3),
            "edge the start files none of them a second time"
        );
        assert_eq!(again.intake.records(), 0, "edge and empties the intake");
        assert_eq!(
            filed_positions(&again)?,
            vec![4, 3, 2],
            "edge each row is in the store once"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[test]
    fn edge_an_empty_intake_files_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut center = center_at(dir.path(), "2026-11-07T12:00:00Z")?;
        let intake = crate::app::fleet_intake::path_for(&dir.path().join("center.store"));
        let before = std::fs::read(&intake)?;
        assert_eq!(
            center.file_calls()?,
            crate::app::fleet_history::Filed::default(),
            "edge nothing to file"
        );
        assert_eq!(
            std::fs::read(&intake)?,
            before,
            "edge and the intake file is not written again for nothing"
        );
        assert!(
            !center.history.dir().join("calls").exists(),
            "edge and no directory is made for nothing"
        );
        assert_eq!(
            center.filing,
            FilingCounts::default(),
            "edge nothing is counted"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn edge_rows_are_answered_before_any_filing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 2).await?;
        let (_, answer) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(
            positions(&answer),
            vec![2, 1],
            "edge a record is answered from the moment it is acknowledged"
        );
        assert_eq!(answer["files_read"], 0, "edge with no file read");
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn edge_a_row_in_a_file_and_in_the_intake_is_answered_once() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 3).await?;
        {
            let center = st.center.lock();
            center.history.file(&center.intake.rows()?)?;
        }
        let (_, answer) = get_json(&st, "/v1/fleet/calls").await?;
        assert_eq!(
            positions(&answer),
            vec![3, 2, 1],
            "edge filed and not yet removed from the intake: each row once"
        );
        Ok(())
    }

    #[cfg(feature = "fleet-store")]
    #[tokio::test]
    async fn edge_a_question_no_row_answers_is_an_empty_complete_answer() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        push_calls(&st, "edge-a", 1, 3).await?;
        st.center.lock().file_calls()?;
        let (status, answer) = get_json(&st, "/v1/fleet/calls?member=edge-z").await?;
        assert_eq!(status, 200, "edge a member with no rows is not an error");
        assert_eq!(answer["count"], 0, "edge no rows");
        assert_eq!(answer["complete"], true, "edge and the answer is whole");
        assert_eq!(
            answer["files_read"], 1,
            "edge the one file of the filing holds every member's rows and was opened"
        );
        Ok(())
    }
}

/// The heartbeat rows a center keeps for its history store, and the
/// registry it rebuilds from them.
#[cfg(test)]
mod heartbeat_rows_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn t(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    /// The heartbeat at `seq` of stream `s`, sent at 12:00 plus `seq`
    /// seconds on 2026-11-11.
    fn beat(seq: u64) -> Result<Record, TestError> {
        Ok(Record::Heartbeat(Heartbeat {
            stream: "s".to_string(),
            seq,
            sent_at: t("2026-11-11T12:00:00Z")? + chrono::Duration::seconds(seq.cast_signed()),
            heartbeat_secs: 30,
            inventory: serde_json::json!({"host": "edge.example.com", "seq": seq}),
            calls: None,
        }))
    }

    /// The call record at `seq` of stream `s`, sent as [`beat`] sends.
    fn call(seq: u64) -> Result<Record, TestError> {
        Ok(Record::Call(CallRecord {
            stream: "s".to_string(),
            seq,
            sent_at: t("2026-11-11T12:00:00Z")? + chrono::Duration::seconds(seq.cast_signed()),
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": format!("call-{seq}@example.com")}),
        }))
    }

    /// A member's record with `count` heartbeats, received `secs` seconds
    /// after 12:00 on 2026-11-11.
    fn row(member: &str, secs: i64, count: u64) -> Result<MemberRecord, TestError> {
        let at = t("2026-11-11T12:00:00Z")? + chrono::Duration::seconds(secs);
        Ok(MemberRecord {
            member: member.to_string(),
            received_at: at,
            peer: "192.0.2.10".to_string(),
            heartbeats: count,
            cursor: Cursor {
                stream: "s".to_string(),
                seq: count,
                sent_at: at,
            },
            heartbeat_secs: 30,
            inventory: serde_json::json!({"host": "edge.example.com"}),
            call_records: 0,
            calls: None,
        })
    }

    /// The counts of the heartbeats `rows` hold.
    fn counts(rows: &[MemberRecord]) -> Vec<u64> {
        rows.iter().map(|r| r.heartbeats).collect()
    }

    #[test]
    fn success_a_plan_lists_each_new_heartbeat_as_a_row() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let plan = Registry::default().plan_records(
            "edge-a",
            "192.0.2.10",
            now,
            &[beat(1)?, beat(2)?, beat(3)?],
        );
        assert_eq!(
            counts(&plan.heartbeats),
            [1, 2, 3],
            "success one row for each heartbeat, in order, each with its own count"
        );
        assert_eq!(
            plan.heartbeats
                .iter()
                .map(|r| (r.cursor.seq, r.inventory["seq"].as_u64(), r.received_at))
                .collect::<Vec<_>>(),
            vec![(1, Some(1), now), (2, Some(2), now), (3, Some(3), now)],
            "success a row holds the position and inventory of its own heartbeat and the \
             receive time of the request"
        );
        assert_eq!(
            plan.heartbeats.last(),
            plan.record.as_ref(),
            "success and the last row is the record the registry then holds"
        );
        Ok(())
    }

    #[test]
    fn success_the_store_takes_the_rows_and_then_the_newest_record() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let plan =
            Registry::default().plan_records("edge-a", "192.0.2.10", now, &[beat(1)?, beat(2)?]);
        assert_eq!(
            counts(&store_lines(&plan).into_iter().cloned().collect::<Vec<_>>()),
            [1, 2],
            "success a request of heartbeats alone appends its rows: the last is the newest \
             record"
        );
        Ok(())
    }

    #[test]
    fn success_waiting_rows_are_handed_out_in_order_and_leave_when_filed() -> Result<(), TestError>
    {
        let mut waiting = Waiting::default();
        for n in 1..=3 {
            waiting.push(row("edge-a", i64::try_from(n)?, n)?, 100, 1000);
        }
        let (first, rows) = waiting.snapshot();
        assert_eq!(
            (first, counts(&rows), waiting.len(), waiting.bytes()),
            (0, vec![1, 2, 3], 3, 300),
            "success the rows wait in the order they came, with their bytes counted"
        );
        waiting.filed(first, rows.len());
        assert_eq!(
            (waiting.len(), waiting.bytes(), waiting.removed()),
            (0, 0, 0),
            "success filed rows leave, and are not counted as removed by the bound"
        );
        assert!(waiting.is_empty(), "success nothing waits");
        Ok(())
    }

    #[test]
    fn success_a_member_row_holds_what_the_members_report_holds() -> Result<(), TestError> {
        let record = row("edge-a", 0, 7)?;
        let reg = Registry::from_records(vec![record.clone()]);
        let mut reported = reg.report(t("2026-11-11T12:00:10Z")?, 3, 72)["members"][0].clone();
        let row = member_json(&record);
        assert_eq!(
            (&row["member"], &row["verified"]["heartbeats"]),
            (&serde_json::json!("edge-a"), &serde_json::json!(7)),
            "success the row names the member and the count the center verified"
        );
        let fields = reported.as_object_mut().ok_or("an object")?;
        fields.remove("silent");
        fields.remove("seconds_since_heartbeat");
        assert_eq!(
            row, reported,
            "success a history row is the report's row without what is measured now"
        );
        Ok(())
    }

    #[test]
    fn success_a_restored_heartbeat_enters_a_registry_that_lacks_the_member()
    -> Result<(), TestError> {
        let mut reg = Registry::from_records(vec![row("edge-a", 0, 1)?]);
        assert!(
            reg.restore(row("edge-b", 5, 4)?),
            "success a member the registry lacks is taken"
        );
        assert_eq!(
            reg.records()
                .iter()
                .map(|r| (r.member.as_str(), r.heartbeats))
                .collect::<Vec<_>>(),
            vec![("edge-a", 1), ("edge-b", 4)],
            "success and is listed with the heartbeat it was restored from"
        );
        Ok(())
    }

    #[test]
    fn success_a_restored_heartbeat_replaces_an_older_record() -> Result<(), TestError> {
        let mut reg = Registry::from_records(vec![row("edge-a", 0, 1)?]);
        assert!(
            reg.restore(row("edge-a", 30, 2)?),
            "success a later heartbeat is taken"
        );
        assert_eq!(
            counts(&reg.records().into_iter().cloned().collect::<Vec<_>>()),
            [2],
            "success and replaces the older record"
        );
        Ok(())
    }

    #[test]
    fn failure_a_replayed_heartbeat_is_no_row() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let mut reg = Registry::default();
        reg.commit(reg.plan_records("edge-a", "192.0.2.10", now, &[beat(1)?, beat(2)?]));
        let plan = reg.plan_records("edge-a", "192.0.2.10", now, &[beat(1)?, beat(2)?]);
        assert_eq!(
            (
                plan.duplicate,
                plan.heartbeats.len(),
                store_lines(&plan).len()
            ),
            (2, 0, 0),
            "failure a replay adds no row and appends nothing"
        );
        let plan = reg.plan_records("edge-a", "192.0.2.10", now, &[beat(2)?, beat(3)?]);
        assert_eq!(
            counts(&plan.heartbeats),
            [3],
            "failure and a request that mixes a replay with a new heartbeat adds the new one"
        );
        Ok(())
    }

    #[test]
    fn failure_rows_past_the_bound_leave_oldest_first_and_are_counted() -> Result<(), TestError> {
        let mut waiting = Waiting::default();
        for n in 1..=5 {
            waiting.push(row("edge-a", i64::try_from(n)?, n)?, 100, 300);
        }
        assert_eq!(
            (counts(&waiting.rows()), waiting.bytes(), waiting.removed()),
            (vec![3, 4, 5], 300, 2),
            "failure the two oldest rows left when the bound was passed, and are counted"
        );
        Ok(())
    }

    #[test]
    fn failure_a_row_larger_than_the_bound_does_not_wait() -> Result<(), TestError> {
        let mut waiting = Waiting::default();
        waiting.push(row("edge-a", 1, 1)?, 100, 300);
        waiting.push(row("edge-a", 2, 2)?, 301, 300);
        assert_eq!(
            (waiting.len(), waiting.bytes(), waiting.removed()),
            (0, 0, 2),
            "failure a row over the bound removes what waits and then itself"
        );
        Ok(())
    }

    #[test]
    fn failure_a_restored_heartbeat_older_than_the_registrys_is_not_taken() -> Result<(), TestError>
    {
        let mut reg = Registry::from_records(vec![row("edge-a", 30, 5)?]);
        assert!(
            !reg.restore(row("edge-a", 0, 4)?),
            "failure an older heartbeat is refused"
        );
        assert!(
            !reg.restore(row("edge-a", 30, 5)?),
            "failure and so is the heartbeat the registry already holds"
        );
        assert_eq!(
            reg.records()[0].heartbeats,
            5,
            "failure the registry keeps its record"
        );
        Ok(())
    }

    #[test]
    fn failure_a_store_append_that_fails_leaves_no_row_waiting() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let now = t("2026-11-11T12:01:00Z")?;
        let (mut center, _) = Center::open(&path, test_keys(1), now, chrono::Duration::hours(72))?;
        center
            .store
            .log_mut()
            .open_with(crate::app::fleet_log::faults::refuse(libc::ENOSPC));
        let got = center.take("edge-a", "192.0.2.10", now, &[beat(1)?]);
        assert!(got.is_err(), "failure the request fails");
        assert_eq!(
            (center.waiting.len(), center.registry.records().len()),
            (0, 0),
            "failure a heartbeat the store did not take is no row and no member"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_record_is_no_row_and_follows_as_the_newest_record() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let plan = Registry::default().plan_records(
            "edge-a",
            "192.0.2.10",
            now,
            &[beat(1)?, call(2)?, call(3)?],
        );
        assert_eq!(counts(&plan.heartbeats), [1], "edge the heartbeat is a row");
        let lines = store_lines(&plan);
        assert_eq!(
            lines
                .iter()
                .map(|r| (r.heartbeats, r.cursor.seq, r.call_records))
                .collect::<Vec<_>>(),
            vec![(1, 1, 0), (1, 3, 2)],
            "edge the store takes the heartbeat's row and then the record the call records \
             moved"
        );
        Ok(())
    }

    #[test]
    fn edge_a_request_of_call_records_alone_has_no_row() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let plan =
            Registry::default().plan_records("edge-a", "192.0.2.10", now, &[call(1)?, call(2)?]);
        assert!(
            plan.heartbeats.is_empty(),
            "edge call records are no heartbeat rows"
        );
        assert_eq!(
            store_lines(&plan)
                .iter()
                .map(|r| (r.heartbeats, r.cursor.seq))
                .collect::<Vec<_>>(),
            vec![(0, 2)],
            "edge the store takes the member's one newest record"
        );
        Ok(())
    }

    #[test]
    fn edge_a_heartbeat_after_a_call_record_ends_the_lines() -> Result<(), TestError> {
        let now = t("2026-11-11T12:01:00Z")?;
        let plan = Registry::default().plan_records(
            "edge-a",
            "192.0.2.10",
            now,
            &[beat(1)?, call(2)?, beat(3)?],
        );
        assert_eq!(
            store_lines(&plan)
                .iter()
                .map(|r| (r.heartbeats, r.cursor.seq, r.call_records))
                .collect::<Vec<_>>(),
            vec![(1, 1, 0), (2, 3, 1)],
            "edge the last heartbeat's row is the newest record: it is appended once"
        );
        Ok(())
    }

    #[test]
    fn edge_a_rewrite_keeps_the_waiting_rows_before_the_registry() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let reg = Registry::from_records(vec![row("edge-a", 60, 3)?, row("edge-b", 0, 1)?]);
        let waiting = vec![row("edge-a", 0, 1)?, row("edge-a", 30, 2)?];
        store.compact_with(&reg, &waiting)?;
        drop(store);
        let (_, records) = Store::open(&path, test_keys(1))?;
        assert_eq!(
            records
                .iter()
                .map(|r| (r.member.as_str(), r.heartbeats))
                .collect::<Vec<_>>(),
            vec![("edge-a", 1), ("edge-a", 2), ("edge-a", 3), ("edge-b", 1)],
            "edge the file holds the waiting rows and then every member's newest record"
        );
        assert_eq!(
            Registry::from_records(records),
            reg,
            "edge and a start reads the same registry from it"
        );
        Ok(())
    }

    #[test]
    fn edge_rows_that_arrive_during_a_filing_stay_waiting() -> Result<(), TestError> {
        let mut waiting = Waiting::default();
        waiting.push(row("edge-a", 1, 1)?, 100, 1000);
        waiting.push(row("edge-a", 2, 2)?, 100, 1000);
        let (first, taken) = waiting.snapshot();
        waiting.push(row("edge-a", 3, 3)?, 100, 1000);
        waiting.filed(first, taken.len());
        assert_eq!(
            (counts(&waiting.rows()), waiting.bytes()),
            (vec![3], 100),
            "edge the row that came after the filing took its rows still waits"
        );
        let (first, taken) = waiting.snapshot();
        assert_eq!(
            (first, counts(&taken)),
            (2, vec![3]),
            "edge and the next filing takes it, at the number after the two that left"
        );
        Ok(())
    }

    #[test]
    fn edge_rows_the_bound_removed_during_a_filing_are_not_removed_twice() -> Result<(), TestError>
    {
        let mut waiting = Waiting::default();
        for n in 1..=3 {
            waiting.push(row("edge-a", i64::try_from(n)?, n)?, 100, 300);
        }
        let (first, taken) = waiting.snapshot();
        // Two more rows pass the bound: rows 1 and 2 leave.
        waiting.push(row("edge-a", 4, 4)?, 100, 300);
        waiting.push(row("edge-a", 5, 5)?, 100, 300);
        waiting.filed(first, taken.len());
        assert_eq!(
            (counts(&waiting.rows()), waiting.removed()),
            (vec![4, 5], 2),
            "edge only row 3, the one filed row still held, leaves: rows 4 and 5 wait"
        );
        waiting.filed(first, taken.len());
        assert_eq!(
            counts(&waiting.rows()),
            [4, 5],
            "edge and saying the same filing twice removes nothing more"
        );
        Ok(())
    }

    #[test]
    fn edge_a_restored_heartbeat_of_the_same_instant_wins_by_its_count() -> Result<(), TestError> {
        let mut reg = Registry::from_records(vec![row("edge-a", 30, 5)?]);
        assert!(
            reg.restore(row("edge-a", 30, 6)?),
            "edge at one receive time the higher count is the later heartbeat"
        );
        assert_eq!(reg.records()[0].heartbeats, 6, "edge and it is held");
        Ok(())
    }

    #[test]
    fn edge_nothing_to_append_writes_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path, test_keys(1))?;
        let before = std::fs::read(&path)?;
        assert_eq!(
            store.append_all(&[])?,
            Vec::<usize>::new(),
            "edge no record has no size"
        );
        assert_eq!(
            (store.appended(), std::fs::read(&path)? == before),
            (0, true),
            "edge and the file is as it was"
        );
        let first = row("edge-a", 0, 1)?;
        let second = row("edge-a", 30, 2)?;
        let sizes = store.append_all(&[&first, &second])?;
        assert_eq!(
            (sizes.len(), store.appended()),
            (2, 2),
            "edge two records are two lines, each with its size"
        );
        Ok(())
    }

    /// What needs the history store itself.
    #[cfg(feature = "fleet-store")]
    mod with_the_store {
        use super::*;
        use crate::app::fleet_history::{CLASS_MEMBERS, Query};

        /// The center whose store is in `dir`, opened at 12:00 plus `secs`
        /// seconds on 2026-11-11 with a retention of 72 hours.
        fn open(dir: &Path, secs: i64) -> Result<Center, TestError> {
            let now = t("2026-11-11T12:00:00Z")? + chrono::Duration::seconds(secs);
            let keep = chrono::Duration::hours(72);
            Ok(Center::open(&dir.join("center.store"), test_keys(1), now, keep)?.0)
        }

        /// Take `batch` as edge-a, `secs` seconds after 12:00.
        fn take(center: &mut Center, secs: i64, batch: &[Record]) -> Result<(), TestError> {
            let now = t("2026-11-11T12:00:00Z")? + chrono::Duration::seconds(secs);
            center.take("edge-a", "192.0.2.10", now, batch)?;
            Ok(())
        }

        /// File the heartbeats that wait in `center` and give it back.
        fn file(center: Center) -> (Center, Result<crate::app::fleet_history::Filed, String>) {
            let shared = parking_lot::Mutex::new(center);
            let filed = Center::file_heartbeats(&shared, &parking_lot::Mutex::new(()));
            (shared.into_inner(), filed)
        }

        /// The counts of edge-a's heartbeats the history store of `center`
        /// holds in files, newest first.
        fn filed_counts(center: &Center) -> Result<Vec<u64>, TestError> {
            let query = Query {
                member: Some("edge-a".to_string()),
                ..Query::all()
            };
            let files = center.history.list(CLASS_MEMBERS, &query)?;
            let answer = center
                .history
                .answer(&query, &files, Vec::<MemberRecord>::new());
            if let Some((file, why)) = answer.refused.first() {
                return Err(format!("{file}: {why}").into());
            }
            Ok(counts(&answer.rows))
        }

        #[test]
        fn success_the_center_files_the_heartbeats_that_wait() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?, beat(2)?])?;
            take(&mut center, 2, &[beat(3)?])?;
            assert_eq!(
                counts(&center.waiting.rows()),
                [1, 2, 3],
                "success every acknowledged heartbeat waits as a row"
            );
            let (center, filed) = file(center);
            let filed = filed?;
            assert_eq!(
                (filed.rows, filed.files),
                (3, 1),
                "success the rows of one day and member go into one file"
            );
            assert_eq!(
                (
                    center.waiting.len(),
                    center.filing.heartbeats_filed,
                    center.filing.heartbeat_files,
                    center.filing.failed
                ),
                (0, 3, 1, 0),
                "success nothing waits after, and the center counted the filing"
            );
            assert_eq!(
                filed_counts(&center)?,
                [3, 2, 1],
                "success the files hold the three heartbeats"
            );
            Ok(())
        }

        #[test]
        fn success_a_lost_store_file_is_rebuilt_from_the_newest_heartbeats() -> Result<(), TestError>
        {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            take(&mut center, 31, &[beat(2)?])?;
            let held = center.registry.clone();
            let (center, filed) = file(center);
            filed?;
            drop(center);
            std::fs::remove_file(dir.path().join("center.store"))?;
            let center = open(dir.path(), 600)?;
            assert_eq!(
                center.registry, held,
                "success the registry is what it was before the store file was lost"
            );
            assert_eq!(
                center.filing.members_restored, 1,
                "success and the start counts the member it took from the history store"
            );
            assert_eq!(
                center.registry.silent(t("2026-11-11T12:10:00Z")?, 3),
                ["edge-a"],
                "success a member silent before the stop is silent after it"
            );
            Ok(())
        }

        #[test]
        fn failure_a_filing_that_fails_keeps_the_rows_waiting_and_is_counted()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            // A file where the class directory goes: no file can be written.
            std::fs::write(center.history.dir().join(CLASS_MEMBERS), b"")?;
            let (mut center, filed) = file(center);
            assert!(
                filed
                    .as_ref()
                    .is_err_and(|e| e.contains("the history store")),
                "failure the filing fails and names the history store: {filed:?}"
            );
            assert_eq!(
                (
                    counts(&center.waiting.rows()),
                    center.filing.failed,
                    center.filing.heartbeats_filed
                ),
                (vec![1], 1, 0),
                "failure the row still waits and the failure is counted"
            );
            std::fs::remove_file(center.history.dir().join(CLASS_MEMBERS))?;
            take(&mut center, 2, &[beat(2)?])?;
            let (center, filed) = file(center);
            assert_eq!(
                (filed?.rows, center.waiting.len()),
                (2, 0),
                "failure once the store can be written, the next filing files both rows"
            );
            Ok(())
        }

        #[test]
        fn failure_a_member_past_the_retention_is_not_restored() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            let (center, filed) = file(center);
            filed?;
            drop(center);
            std::fs::remove_file(dir.path().join("center.store"))?;
            // Four days later, with a retention of 72 hours.
            let center = open(dir.path(), 4 * 86_400)?;
            assert_eq!(
                (
                    center.registry.records().len(),
                    center.filing.members_restored
                ),
                (0, 0),
                "failure a member last heard before the retention is not listed again"
            );
            Ok(())
        }

        #[test]
        fn failure_a_heartbeat_file_that_does_not_open_restores_nothing_and_the_center_starts()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            let (center, filed) = file(center);
            filed?;
            let rel = center.history.list(CLASS_MEMBERS, &Query::all())?[0]
                .rel
                .clone();
            let path = center.history.dir().join(rel);
            drop(center);
            let mut bytes = std::fs::read(&path)?;
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0x01;
            std::fs::write(&path, bytes)?;
            std::fs::remove_file(dir.path().join("center.store"))?;
            let center = open(dir.path(), 60)?;
            assert_eq!(
                (
                    center.registry.records().len(),
                    center.filing.members_restored
                ),
                (0, 0),
                "failure the center starts, with no member made up from a file it cannot read"
            );
            Ok(())
        }

        #[test]
        fn edge_a_store_file_behind_the_history_takes_the_newer_heartbeat() -> Result<(), TestError>
        {
            let dir = tempfile::tempdir()?;
            let store = dir.path().join("center.store");
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            let old = std::fs::read(&store)?;
            take(&mut center, 31, &[beat(2)?, beat(3)?])?;
            let (center, filed) = file(center);
            filed?;
            drop(center);
            // An earlier copy of the store file is put back.
            std::fs::write(&store, old)?;
            let center = open(dir.path(), 60)?;
            let record = center.registry.records()[0].clone();
            assert_eq!(
                (record.heartbeats, record.cursor.seq),
                (3, 3),
                "edge the newest heartbeat is the history's, not the older store file's"
            );
            assert_eq!(center.filing.members_restored, 1, "edge and it is counted");
            let replay = center.registry.plan_records(
                "edge-a",
                "192.0.2.10",
                record.received_at,
                &[beat(3)?],
            );
            assert_eq!(
                (replay.accepted, replay.duplicate),
                (0, 1),
                "edge a replay of the heartbeat the old file lacked is a duplicate"
            );
            Ok(())
        }

        #[test]
        fn edge_a_store_file_ahead_of_the_history_keeps_its_record() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            let (mut center, filed) = file(center);
            filed?;
            take(&mut center, 31, &[beat(2)?])?;
            drop(center);
            let center = open(dir.path(), 60)?;
            assert_eq!(
                (
                    center.registry.records()[0].heartbeats,
                    center.filing.members_restored
                ),
                (2, 0),
                "edge the store file's later heartbeat stands and nothing is restored"
            );
            assert_eq!(
                counts(&center.waiting.rows()),
                [1, 2],
                "edge every heartbeat the store file held waits again for the filing"
            );
            Ok(())
        }

        #[test]
        fn edge_call_records_filed_after_the_newest_heartbeat_move_the_position()
        -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            take(&mut center, 2, &[call(2)?, call(3)?])?;
            center.file_calls()?;
            let (center, filed) = file(center);
            filed?;
            drop(center);
            std::fs::remove_file(dir.path().join("center.store"))?;
            let center = open(dir.path(), 60)?;
            let record = center.registry.records()[0].clone();
            assert_eq!(
                (record.heartbeats, record.cursor.seq, record.call_records),
                (1, 3, 2),
                "edge the position is past the two call records filed after the heartbeat"
            );
            let replay = center.registry.plan_records(
                "edge-a",
                "192.0.2.10",
                record.received_at,
                &[call(2)?, call(3)?],
            );
            assert_eq!(
                (replay.accepted, replay.calls.len()),
                (0, 0),
                "edge so a replay of them stores no call record twice"
            );
            Ok(())
        }

        #[test]
        fn edge_a_start_files_the_rows_the_store_file_held_once() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?, beat(2)?])?;
            take(&mut center, 2, &[call(3)?])?;
            // Stopped before any filing: the rows are in the store file.
            drop(center);
            let center = open(dir.path(), 60)?;
            assert_eq!(
                counts(&center.waiting.rows()),
                [1, 2],
                "edge every heartbeat of the store file waits once: the record a call moved \
                 is the heartbeat before it"
            );
            let (center, filed) = file(center);
            let filed = filed?;
            assert_eq!(
                (filed.rows, filed.already),
                (2, 0),
                "edge the two heartbeats are filed, each once"
            );
            drop(center);
            let center = open(dir.path(), 120)?;
            let (center, filed) = file(center);
            let filed = filed?;
            assert_eq!(
                (filed.rows, filed.files, filed.already > 0),
                (0, 0, true),
                "edge a second start files no row twice"
            );
            assert_eq!(filed_counts(&center)?, [2, 1], "edge two rows are held");
            Ok(())
        }

        #[test]
        fn success_heartbeat_days_past_the_retention_hours_are_removed() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?, call(2)?])?;
            center.file_calls()?;
            let (center, filed) = file(center);
            filed?;
            let now = t("2026-11-11T12:00:00Z")?;
            expire_history(&center, now + chrono::Duration::hours(83), 90, 72);
            assert_eq!(
                filed_counts(&center)?,
                [1],
                "success 83 hours later the 11th still holds an hour within 72: the day stays"
            );
            expire_history(&center, now + chrono::Duration::hours(84), 90, 72);
            assert_eq!(
                filed_counts(&center)?,
                Vec::<u64>::new(),
                "success once every hour of the day is past 72 hours, its heartbeats are removed"
            );
            let calls = center
                .history
                .list(crate::app::fleet_history::CLASS_CALLS, &Query::all())?;
            assert_eq!(
                calls.len(),
                1,
                "success the call record of that day stays: its retention is 90 days"
            );
            Ok(())
        }

        #[test]
        fn edge_a_start_lets_no_row_past_the_retention_wait() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            drop(center);
            // Four days later, with a retention of 72 hours.
            let center = open(dir.path(), 4 * 86_400)?;
            assert!(
                center.waiting.is_empty(),
                "edge a heartbeat of a member past the retention does not wait for a filing"
            );
            Ok(())
        }

        #[test]
        fn edge_a_record_without_a_heartbeat_does_not_wait() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[call(1)?])?;
            assert!(
                center.waiting.is_empty(),
                "edge a call record adds no heartbeat row"
            );
            drop(center);
            let center = open(dir.path(), 60)?;
            assert!(
                center.waiting.is_empty(),
                "edge and a start does not take the member's record for one"
            );
            Ok(())
        }

        #[test]
        fn edge_a_stop_between_a_rewrite_and_a_filing_loses_no_row() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let mut center = open(dir.path(), 0)?;
            take(&mut center, 1, &[beat(1)?])?;
            take(&mut center, 31, &[beat(2)?])?;
            // The upkeep rewrites the store file while the rows wait.
            let now = t("2026-11-11T12:01:00Z")?;
            apply_retention(&mut center, now, 72);
            drop(center);
            let center = open(dir.path(), 120)?;
            let (center, filed) = file(center);
            assert_eq!(
                filed?.rows, 2,
                "edge both rows are in the rewritten store file and are filed by the next start"
            );
            assert_eq!(filed_counts(&center)?, [2, 1], "edge each once");
            Ok(())
        }
    }
}
