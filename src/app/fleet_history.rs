// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fleet center's history store: call records in sealed Parquet files.
//!
//! `sipnab fleet serve` files the call records its intake holds
//! ([`super::fleet_intake`]) into Parquet files under a directory beside
//! its store, `<store>.parquet`, and answers `GET /v1/fleet/calls` from
//! them. This module is in builds with the `fleet-store` feature.
//!
//! # Layout
//!
//! `<class>/date=YYYY-MM-DD/<first>-<last>-h<mark>.sealed`
//! ([`IntervalName`]): one file for each filing and day, which holds the
//! rows of every member, so the number of files a day does not grow with
//! the number of members. The date is the UTC day the center received the
//! rows on, `<first>` and `<last>` are the earliest and the latest receive
//! time in the file in milliseconds, and `<mark>` tells the file's rows
//! from other rows of the same times ([`rows_mark`]). A path names no
//! member and states no count.
//!
//! A file holds its rows by member and then by receive time ([`sorted`]),
//! in row groups that end where the member changes ([`group_cuts`]). A
//! question for one day or one hour opens only the files whose path says
//! they can hold an answer ([`Query::wants_date`], [`Query::wants_span`]),
//! and a question for one member reads only the row groups whose least and
//! greatest member do not rule it out.
//!
//! # The layout of release 0.5.249
//!
//! Releases 0.5.249 and 0.5.250 wrote
//! `calls/date=YYYY-MM-DD/member=<id>/<first>-<last>-<stream>-<seq>.sealed`
//! ([`Partition`], [`FileName`]): one file for each day and member of a
//! filing, 2,880,000 files a day for 2,000 members at 60 seconds. No build
//! writes that layout any more. Its files are told apart by their depth
//! under the day, and are still listed, read, counted and removed with
//! their day ([`History::list`], [`History::expire_before`]); a filing
//! leaves out the rows one of them holds.
//!
//! # No clear text on disk
//!
//! A Parquet file is built in memory ([`encode`]) and written as a sealed
//! log of kind calls ([`super::fleet_seal`]): the first record is the
//! file's own path under the directory, the next records are the Parquet
//! bytes in pieces. A file moved to another path does not open
//! ([`unseal`]). The staged file a write goes through holds sealed bytes
//! only.
//!
//! # Compression
//!
//! Every column of a file this build writes is compressed with zstd at
//! [`ZSTD_LEVEL`] ([`codec`]). Releases 0.5.249 to 0.5.253 wrote the files
//! without a codec; they are read in place, and no file is rewritten. A
//! file in any other codec is refused whole, with the codec named.
//!
//! # Files are written once
//!
//! [`History::file`] writes a new file for each day that has rows; it
//! never changes a file. The center calls it with every row of
//! its intake and then empties the intake. When the center stops between
//! the two, the next start files the same rows again: rows a file of the
//! same day already holds are left out ([`without_stored`]),
//! so no row is filed twice.
//!
//! # What is pure and what is not
//!
//! [`Partition`], [`FileName`], [`Query`], [`encode`], [`decode`],
//! [`sealed_lines`], [`unseal`], [`without_stored`], [`expired`],
//! [`groups`] and [`newest`] work on values. [`History`] is the one type
//! that touches the file system.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, Utc};

use super::fleet_center::{MemberRecord, is_valid_id};
use super::fleet_intake::IntakeRecord;
use super::fleet_seal::{Keys, Kind};

/// The directory of the data class of call records.
pub const CLASS_CALLS: &str = "calls";

/// The directory of the data class of heartbeats: one row for each
/// heartbeat the center accepted.
pub const CLASS_MEMBERS: &str = "members";

/// The most files one question opens. The files are read from the latest
/// rows back; a question that rules in more is answered from these, and
/// the answer says how many files were not read.
pub const MAX_FILES_PER_QUESTION: usize = 4096;

/// One column of a row group, as a class writes and reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Column {
    /// 64-bit numbers.
    Longs(Vec<i64>),
    /// Byte texts.
    Texts(Vec<Vec<u8>>),
}

/// A row of one data class of the history store.
///
/// The filing, the listing, the reading and the retention of the store are
/// written once, over this trait: a class says where its files go, what
/// its Parquet schema is and how a row becomes columns and back.
pub trait Row: Clone + Sized {
    /// The directory of the class under the history directory.
    const CLASS: &'static str;
    /// The sealed kind of the class's files.
    const KIND: Kind;
    /// The Parquet schema of the class's files. The first column is the
    /// receive time in nanoseconds since 1970.
    const SCHEMA: &'static str;
    /// What a row is called in a message.
    const NOUN: &'static str;
    /// The name of the column that carries a filter for a point question,
    /// when the class has one.
    const FILTER_COLUMN: Option<&'static str>;

    /// The member the row came from.
    fn member(&self) -> &str;
    /// When the center received the row.
    fn received_at(&self) -> DateTime<Utc>;
    /// The stream a file that starts with this row is named by.
    fn stream(&self) -> &str;
    /// The number a file that starts with this row is named by.
    fn seq(&self) -> u64;
    /// What makes this row the same row as another of its member.
    fn identity(&self) -> (&str, u64, DateTime<Utc>);
    /// Whether the row answers what `query` asks of this class beyond the
    /// member and the time.
    fn answers(&self, query: &Query) -> bool;
    /// `rows` as the columns of [`Self::SCHEMA`], in order.
    ///
    /// # Errors
    ///
    /// A row holds a value the schema cannot carry.
    fn columns(rows: &[Self]) -> Result<Vec<Column>, String>;
    /// The `rows` rows the columns of one row group hold.
    ///
    /// # Errors
    ///
    /// The columns are not those of [`Self::SCHEMA`], or a value in them
    /// does not parse.
    fn from_columns(columns: Vec<Column>, rows: usize) -> Result<Vec<Self>, String>;
}

/// The most rows of one Parquet row group. A question reads only the row
/// groups whose statistics and Call-ID filter say they can hold an answer.
pub const ROWS_PER_GROUP: usize = 10_000;

/// The rows a row group holds before it ends where the member changes
/// ([`group_cuts`]): a file of many members has many row groups, and a
/// question about one member reads the one that holds it.
pub const GROUP_ROWS: usize = 128;

/// The column of the member in every class's schema.
const COL_MEMBER: usize = 1;

/// The bytes of Parquet one sealed record carries, under the sealed
/// layer's bound for a record ([`super::fleet_seal::MAX_RECORD_BYTES`]).
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// The rows `GET /v1/fleet/calls` returns when `limit` is not given.
pub const DEFAULT_LIMIT: usize = 100;

/// The most rows `GET /v1/fleet/calls` returns.
pub const MAX_LIMIT: usize = 1000;

/// The longest `call_id` a question may carry, in bytes.
pub const MAX_CALL_ID_BYTES: usize = 1024;

/// The Parquet schema of a call record file.
const CALLS_SCHEMA: &str = "message call {
    required int64 received_at (TIMESTAMP(NANOS,true));
    required binary member (STRING);
    required binary stream (STRING);
    required int64 seq (INTEGER(64,false));
    required binary sent_at (STRING);
    required binary selected_by (STRING);
    required binary call_id (STRING);
    required binary call (JSON);
}";

/// The Parquet schema of a heartbeat file.
const MEMBERS_SCHEMA: &str = "message heartbeat {
    required int64 received_at (TIMESTAMP(NANOS,true));
    required binary member (STRING);
    required binary peer (STRING);
    required int64 heartbeats (INTEGER(64,false));
    required binary stream (STRING);
    required int64 seq (INTEGER(64,false));
    required binary sent_at (STRING);
    required int64 heartbeat_secs (INTEGER(64,false));
    required int64 call_records (INTEGER(64,false));
    required binary calls (JSON);
    required binary inventory (JSON);
}";

/// The column of the receive time in every class's schema.
const COL_RECEIVED_AT: usize = 0;

/// A count as a Parquet column of unsigned 64-bit numbers holds it.
const fn long(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

/// The count a Parquet column of unsigned 64-bit numbers holds as `value`.
const fn count(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// The column at `column` of `columns` as numbers.
fn longs(columns: &[Column], column: usize) -> Result<&[i64], String> {
    match columns.get(column) {
        Some(Column::Longs(values)) => Ok(values),
        _ => Err(format!("parquet: column {column} is not a 64-bit number")),
    }
}

/// The column at `column` of `columns` as byte texts.
fn texts(columns: &[Column], column: usize) -> Result<&[Vec<u8>], String> {
    match columns.get(column) {
        Some(Column::Texts(values)) => Ok(values),
        _ => Err(format!("parquet: column {column} is not a byte text")),
    }
}

/// The text of row `row` of `column`.
fn text(column: &[Vec<u8>], row: usize) -> Result<String, String> {
    column
        .get(row)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string)
        .ok_or_else(|| format!("parquet: row {} holds text that is not UTF-8", row + 1))
}

/// The send time row `row` of `column` spells.
fn sent_time(column: &[Vec<u8>], row: usize) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(&text(column, row)?)
        .map(|at| at.with_timezone(&Utc))
        .map_err(|_| format!("parquet: row {} has a send time that is no time", row + 1))
}

/// The receive times of `rows`, each checked ([`received_ns`]).
fn received_column<R: Row>(rows: &[R]) -> Result<Column, String> {
    rows.iter()
        .map(received_ns)
        .collect::<Result<Vec<i64>, String>>()
        .map(Column::Longs)
}

/// A column of the texts `of` gives for each of `rows`.
fn text_column<R>(rows: &[R], of: impl Fn(&R) -> Vec<u8>) -> Column {
    Column::Texts(rows.iter().map(of).collect())
}

impl Row for IntakeRecord {
    const CLASS: &'static str = CLASS_CALLS;
    const KIND: Kind = Kind::Calls;
    const SCHEMA: &'static str = CALLS_SCHEMA;
    const NOUN: &'static str = "call record";
    const FILTER_COLUMN: Option<&'static str> = Some("call_id");

    fn member(&self) -> &str {
        &self.member
    }

    fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }

    fn stream(&self) -> &str {
        &self.stream
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn identity(&self) -> (&str, u64, DateTime<Utc>) {
        (&self.stream, self.seq, self.sent_at)
    }

    fn answers(&self, query: &Query) -> bool {
        query
            .call_id
            .as_ref()
            .is_none_or(|call_id| call_id == call_id_of(self))
    }

    fn columns(rows: &[Self]) -> Result<Vec<Column>, String> {
        let calls = rows
            .iter()
            .map(|row| serde_json::to_vec(&row.call).map_err(|e| e.to_string()))
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        Ok(vec![
            received_column(rows)?,
            text_column(rows, |row| row.member.clone().into_bytes()),
            text_column(rows, |row| row.stream.clone().into_bytes()),
            Column::Longs(rows.iter().map(|row| long(row.seq)).collect()),
            text_column(rows, |row| sent_text(row.sent_at).into_bytes()),
            text_column(rows, |row| row.selected_by.clone().into_bytes()),
            text_column(rows, |row| call_id_of(row).as_bytes().to_vec()),
            Column::Texts(calls),
        ])
    }

    fn from_columns(columns: Vec<Column>, rows: usize) -> Result<Vec<Self>, String> {
        let received = longs(&columns, 0)?;
        let members = texts(&columns, 1)?;
        let streams = texts(&columns, 2)?;
        let positions = longs(&columns, 3)?;
        let sent = texts(&columns, 4)?;
        let selected = texts(&columns, 5)?;
        let calls = texts(&columns, 7)?;
        (0..rows)
            .map(|row| {
                let call = serde_json::from_slice(&calls[row]).map_err(|e| {
                    format!("parquet: row {} has a call that is not JSON: {e}", row + 1)
                })?;
                Ok(Self {
                    member: text(members, row)?,
                    received_at: DateTime::from_timestamp_nanos(received[row]),
                    stream: text(streams, row)?,
                    seq: count(positions[row]),
                    sent_at: sent_time(sent, row)?,
                    selected_by: text(selected, row)?,
                    call,
                })
            })
            .collect()
    }
}

impl Row for MemberRecord {
    const CLASS: &'static str = CLASS_MEMBERS;
    const KIND: Kind = Kind::Members;
    const SCHEMA: &'static str = MEMBERS_SCHEMA;
    const NOUN: &'static str = "heartbeat";
    const FILTER_COLUMN: Option<&'static str> = None;

    fn member(&self) -> &str {
        &self.member
    }

    fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }

    fn stream(&self) -> &str {
        &self.cursor.stream
    }

    fn seq(&self) -> u64 {
        self.heartbeats
    }

    fn identity(&self) -> (&str, u64, DateTime<Utc>) {
        ("", self.heartbeats, self.received_at)
    }

    fn answers(&self, _query: &Query) -> bool {
        true
    }

    fn columns(rows: &[Self]) -> Result<Vec<Column>, String> {
        let json = |value: Result<Vec<u8>, serde_json::Error>| value.map_err(|e| e.to_string());
        let calls = rows
            .iter()
            .map(|row| json(serde_json::to_vec(&row.calls)))
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        let inventories = rows
            .iter()
            .map(|row| json(serde_json::to_vec(&row.inventory)))
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        let counts =
            |of: fn(&Self) -> u64| Column::Longs(rows.iter().map(|r| long(of(r))).collect());
        Ok(vec![
            received_column(rows)?,
            text_column(rows, |row| row.member.clone().into_bytes()),
            text_column(rows, |row| row.peer.clone().into_bytes()),
            counts(|row| row.heartbeats),
            text_column(rows, |row| row.cursor.stream.clone().into_bytes()),
            counts(|row| row.cursor.seq),
            text_column(rows, |row| sent_text(row.cursor.sent_at).into_bytes()),
            counts(|row| row.heartbeat_secs),
            counts(|row| row.call_records),
            Column::Texts(calls),
            Column::Texts(inventories),
        ])
    }

    fn from_columns(columns: Vec<Column>, rows: usize) -> Result<Vec<Self>, String> {
        let received = longs(&columns, 0)?;
        let members = texts(&columns, 1)?;
        let peers = texts(&columns, 2)?;
        let heartbeats = longs(&columns, 3)?;
        let streams = texts(&columns, 4)?;
        let positions = longs(&columns, 5)?;
        let sent = texts(&columns, 6)?;
        let intervals = longs(&columns, 7)?;
        let call_records = longs(&columns, 8)?;
        let calls = texts(&columns, 9)?;
        let inventories = texts(&columns, 10)?;
        (0..rows)
            .map(|row| {
                let calls = serde_json::from_slice(&calls[row]).map_err(|e| {
                    format!(
                        "parquet: row {} has call counts that do not parse: {e}",
                        row + 1
                    )
                })?;
                let inventory = serde_json::from_slice(&inventories[row]).map_err(|e| {
                    format!(
                        "parquet: row {} has an inventory that is not JSON: {e}",
                        row + 1
                    )
                })?;
                Ok(Self {
                    member: text(members, row)?,
                    received_at: DateTime::from_timestamp_nanos(received[row]),
                    peer: text(peers, row)?,
                    heartbeats: count(heartbeats[row]),
                    cursor: super::fleet_center::Cursor {
                        stream: text(streams, row)?,
                        seq: count(positions[row]),
                        sent_at: sent_time(sent, row)?,
                    },
                    heartbeat_secs: count(intervals[row]),
                    inventory,
                    call_records: count(call_records[row]),
                    calls,
                })
            })
            .collect()
    }
}

/// The directory of the history store beside the store file `store`.
#[must_use]
pub fn dir_for(store: &Path) -> PathBuf {
    let mut name = store.as_os_str().to_os_string();
    name.push(".parquet");
    PathBuf::from(name)
}

/// When the center received `record`, in nanoseconds since 1970.
///
/// # Errors
///
/// The time is before 1970 or past what 63 bits of nanoseconds hold (the
/// year 2262): the store keeps no such row.
pub fn received_ns<R: Row>(record: &R) -> Result<i64, String> {
    let at = record.received_at();
    if at < DateTime::<Utc>::UNIX_EPOCH {
        return Err(format!(
            "a {} of member '{}' was received at {at}, before 1970; the history store keeps no \
             such row",
            R::NOUN,
            record.member()
        ));
    }
    at.timestamp_nanos_opt().ok_or_else(|| {
        format!(
            "a {} of member '{}' was received at {at}, past the year 2262; the history store \
             keeps no such row",
            R::NOUN,
            record.member()
        )
    })
}

/// When the center received `record`, in milliseconds since 1970.
fn received_ms<R: Row>(record: &R) -> Result<u64, String> {
    Ok(u64::try_from(received_ns(record)?).unwrap_or(0) / 1_000_000)
}

/// The Call-ID of `record`: the `call_id` of its call, or nothing.
#[must_use]
pub fn call_id_of(record: &IntakeRecord) -> &str {
    record
        .call
        .get("call_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// What a day's directory name starts with.
const DATE_PREFIX: &str = "date=";

/// What a member's directory name starts with.
const MEMBER_PREFIX: &str = "member=";

/// How a day is spelled in its directory name.
const DATE_FORMAT: &str = "%Y-%m-%d";

/// What a file's name ends with.
const FILE_SUFFIX: &str = ".sealed";

/// The day the directory name `name` spells, if it is one this module
/// writes: no other spelling of the same day is one.
fn parse_date_dir(name: &str) -> Option<NaiveDate> {
    let text = name.strip_prefix(DATE_PREFIX)?;
    let date = NaiveDate::parse_from_str(text, DATE_FORMAT).ok()?;
    (date.format(DATE_FORMAT).to_string() == text).then_some(date)
}

/// The day and the member a file's rows belong to: one directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Partition {
    /// The UTC day the center received the rows on.
    pub date: NaiveDate,
    /// The member: its token's id.
    pub member: String,
}

impl Partition {
    /// The partition `record` belongs to.
    #[must_use]
    pub fn of<R: Row>(record: &R) -> Self {
        Self {
            date: record.received_at().date_naive(),
            member: record.member().to_string(),
        }
    }

    /// The partition's directory in the class `class` under the history
    /// directory, with `/` between its parts.
    #[must_use]
    pub fn rel_dir(&self, class: &str) -> String {
        format!(
            "{class}/{DATE_PREFIX}{}/{MEMBER_PREFIX}{}",
            self.date.format(DATE_FORMAT),
            self.member
        )
    }

    /// The partition the directory names `date_dir` and `member_dir` spell,
    /// if they are names this module writes.
    #[must_use]
    pub fn parse(date_dir: &str, member_dir: &str) -> Option<Self> {
        let date = parse_date_dir(date_dir)?;
        let member = member_dir.strip_prefix(MEMBER_PREFIX)?;
        is_valid_id(member).then(|| Self {
            date,
            member: member.to_string(),
        })
    }
}

/// What a file's name says about its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// The earliest receive time in the file, in milliseconds since 1970.
    pub first_ms: u64,
    /// The latest receive time in the file, in milliseconds since 1970.
    pub last_ms: u64,
    /// The delivery stream of the file's first row.
    pub stream: String,
    /// The position of the file's first row in that stream.
    pub seq: u64,
}

impl FileName {
    /// The name of the file that holds `rows`.
    ///
    /// # Errors
    ///
    /// `rows` is empty, or a row's receive time is refused
    /// ([`received_ns`]).
    pub fn of<R: Row>(rows: &[R]) -> Result<Self, String> {
        let first = rows.first().ok_or("no rows: a file holds at least one")?;
        let mut first_ms = u64::MAX;
        let mut last_ms = 0u64;
        for row in rows {
            let ms = received_ms(row)?;
            first_ms = first_ms.min(ms);
            last_ms = last_ms.max(ms);
        }
        Ok(Self {
            first_ms,
            last_ms,
            stream: first.stream().to_string(),
            seq: first.seq(),
        })
    }

    /// The file name.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{:013}-{:013}-{}-{}{FILE_SUFFIX}",
            self.first_ms, self.last_ms, self.stream, self.seq
        )
    }

    /// What `name` says, if it is a name this module writes.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(FILE_SUFFIX)?;
        let (first, rest) = stem.split_once('-')?;
        let (last, rest) = rest.split_once('-')?;
        let (stream, seq) = rest.rsplit_once('-')?;
        let parsed = Self {
            first_ms: first.parse().ok()?,
            last_ms: last.parse().ok()?,
            stream: stream.to_string(),
            seq: seq.parse().ok()?,
        };
        // Only the one spelling `text` writes is a name: no sign, no other
        // padding, and a first time that is not after the last.
        (is_valid_id(stream) && parsed.first_ms <= parsed.last_ms && parsed.text() == name)
            .then_some(parsed)
    }
}

/// What the name of a file that holds one filing of one day says: the
/// earliest and the latest receive time in it and a number that tells its
/// rows from any other rows of the same times. The name states neither a
/// member nor a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalName {
    /// The earliest receive time in the file, in milliseconds since 1970.
    pub first_ms: u64,
    /// The latest receive time in the file, in milliseconds since 1970.
    pub last_ms: u64,
    /// The mark of the file's rows ([`rows_mark`]).
    pub mark: u64,
}

impl IntervalName {
    /// The name of the file that holds `rows`, in any order.
    ///
    /// # Errors
    ///
    /// `rows` is empty, or a row's receive time is refused
    /// ([`received_ns`]).
    pub fn of<R: Row>(rows: &[R]) -> Result<Self, String> {
        if rows.is_empty() {
            return Err("no rows: a file holds at least one".to_string());
        }
        let mut first_ms = u64::MAX;
        let mut last_ms = 0u64;
        for row in rows {
            let ms = received_ms(row)?;
            first_ms = first_ms.min(ms);
            last_ms = last_ms.max(ms);
        }
        Ok(Self {
            first_ms,
            last_ms,
            mark: rows_mark(rows)?,
        })
    }

    /// The file name.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{:013}-{:013}-{MARK_PREFIX}{:016x}{FILE_SUFFIX}",
            self.first_ms, self.last_ms, self.mark
        )
    }

    /// What `name` says, if it is a name this module writes.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(FILE_SUFFIX)?;
        let (first, rest) = stem.split_once('-')?;
        let (last, mark) = rest.split_once('-')?;
        let parsed = Self {
            first_ms: first.parse().ok()?,
            last_ms: last.parse().ok()?,
            mark: u64::from_str_radix(mark.strip_prefix(MARK_PREFIX)?, 16).ok()?,
        };
        // Only the one spelling `text` writes is a name.
        (parsed.first_ms <= parsed.last_ms && parsed.text() == name).then_some(parsed)
    }
}

/// What the mark in a file's name starts with. No name of release 0.5.249
/// ends in a part that starts with a letter, so no name is one of both
/// layouts.
const MARK_PREFIX: char = 'h';

/// A number that is the same for the same rows in any order and, for
/// practical purposes, different for different rows: 64-bit FNV-1a over
/// each row's member, stream, position and receive time, in sorted order.
///
/// # Errors
///
/// A row's receive time is refused ([`received_ns`]).
pub fn rows_mark<R: Row>(rows: &[R]) -> Result<u64, String> {
    /// The FNV-1a offset basis and prime for 64 bits.
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut keys = rows
        .iter()
        .map(|row| Ok((row.member(), row.stream(), row.seq(), received_ns(row)?)))
        .collect::<Result<Vec<(&str, &str, u64, i64)>, String>>()?;
    keys.sort_unstable();
    let mut mark = BASIS;
    let mut take = |bytes: &[u8]| {
        for byte in bytes {
            mark = (mark ^ u64::from(*byte)).wrapping_mul(PRIME);
        }
    };
    for (member, stream, seq, received) in keys {
        // No id holds a zero byte, so one ends each text.
        take(member.as_bytes());
        take(&[0]);
        take(stream.as_bytes());
        take(&[0]);
        take(&seq.to_be_bytes());
        take(&received.to_be_bytes());
    }
    Ok(mark)
}

/// `rows` in the order a file holds them: by member, then by receive time,
/// then by stream and position.
#[must_use]
pub fn sorted<R: Row>(rows: Vec<R>) -> Vec<R> {
    let mut rows = rows;
    rows.sort_by(|a, b| {
        a.member()
            .cmp(b.member())
            .then_with(|| a.received_at().cmp(&b.received_at()))
            .then_with(|| a.stream().cmp(b.stream()))
            .then_with(|| a.seq().cmp(&b.seq()))
    });
    rows
}

/// How many rows each row group of a file takes, for rows whose members
/// are `members`, in file order: a group ends where the member changes
/// once it holds `least` rows, and at `most` rows wherever that falls. A
/// member with fewer than `most` rows after a group's end is in one group,
/// so the least and the greatest member a group records rule it out for a
/// question about another member.
#[must_use]
pub fn group_cuts(members: &[&str], least: usize, most: usize) -> Vec<usize> {
    let most = most.max(1);
    let mut cuts = Vec::new();
    let mut held = 0usize;
    for (index, member) in members.iter().enumerate() {
        held += 1;
        let ends_member = members.get(index + 1).is_none_or(|next| next != member);
        let is_last = index + 1 == members.len();
        if is_last || held >= most || (ends_member && held >= least) {
            cuts.push(held);
            held = 0;
        }
    }
    cuts
}

/// The rows of `records` by the UTC day the center received them on, each
/// day's rows in the order they came in.
#[must_use]
pub fn by_date<R: Row>(records: &[R]) -> BTreeMap<NaiveDate, Vec<R>> {
    let mut out: BTreeMap<NaiveDate, Vec<R>> = BTreeMap::new();
    for record in records {
        out.entry(record.received_at().date_naive())
            .or_default()
            .push(record.clone());
    }
    out
}

/// The rows of `records` by partition, each partition's rows in the order
/// they came in.
#[must_use]
pub fn groups<R: Row>(records: &[R]) -> BTreeMap<Partition, Vec<R>> {
    let mut out: BTreeMap<Partition, Vec<R>> = BTreeMap::new();
    for record in records {
        out.entry(Partition::of(record))
            .or_default()
            .push(record.clone());
    }
    out
}

/// What `GET /v1/fleet/calls` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// `member`: rows of this member only.
    pub member: Option<String>,
    /// `from`: rows received at this time or later.
    pub from: Option<DateTime<Utc>>,
    /// `to`: rows received before this time.
    pub to: Option<DateTime<Utc>>,
    /// `call_id`: rows of the call with this Call-ID only.
    pub call_id: Option<String>,
    /// `limit`: the most rows to return, newest first.
    pub limit: usize,
}

impl Query {
    /// The question that every row answers, with no limit on the rows.
    #[must_use]
    pub fn all() -> Self {
        Self {
            member: None,
            from: None,
            to: None,
            call_id: None,
            limit: usize::MAX,
        }
    }

    /// The question the query string's `pairs` ask.
    ///
    /// # Errors
    ///
    /// A parameter is not one of `member`, `from`, `to`, `call_id` and
    /// `limit`, is given twice, or has a value outside what it accepts.
    /// The message names the parameter and what it accepts.
    pub fn parse(pairs: &[(String, String)]) -> Result<Self, String> {
        let mut query = Self {
            limit: DEFAULT_LIMIT,
            ..Self::all()
        };
        let mut seen = BTreeSet::new();
        for (name, value) in pairs {
            if !seen.insert(name.as_str()) {
                return Err(format!("{} is given twice", shown(name)));
            }
            match name.as_str() {
                "member" => {
                    if !is_valid_id(value) {
                        return Err(format!(
                            "member must be 1 to {} letters, digits, '.', '_' or '-'",
                            super::fleet_center::MAX_ID_LEN
                        ));
                    }
                    query.member = Some(value.clone());
                }
                "from" => query.from = Some(instant("from", value)?),
                "to" => query.to = Some(instant("to", value)?),
                "call_id" => {
                    if value.is_empty() || value.len() > MAX_CALL_ID_BYTES {
                        return Err(format!("call_id must be 1 to {MAX_CALL_ID_BYTES} bytes"));
                    }
                    query.call_id = Some(value.clone());
                }
                "limit" => {
                    query.limit = value
                        .parse()
                        .ok()
                        .filter(|limit| (1..=MAX_LIMIT).contains(limit))
                        .ok_or_else(|| format!("limit must be a number from 1 to {MAX_LIMIT}"))?;
                }
                _ => {
                    return Err(format!(
                        "{} is not a parameter of this route; it takes member, from, to, \
                         call_id and limit",
                        shown(name)
                    ));
                }
            }
        }
        if let (Some(from), Some(to)) = (query.from, query.to)
            && to <= from
        {
            return Err("to must be after from".to_string());
        }
        Ok(query)
    }

    /// The question `GET /v1/fleet/members/{id}/history` asks about the
    /// member `member` with the query string's `pairs`.
    ///
    /// # Errors
    ///
    /// `member` is no member id, a parameter is not one of `from`, `to`
    /// and `limit`, is given twice, or has a value outside what it
    /// accepts. The message names the parameter and what it accepts.
    pub fn parse_heartbeats(member: &str, pairs: &[(String, String)]) -> Result<Self, String> {
        if let Some((name, _)) = pairs
            .iter()
            .find(|(name, _)| !matches!(name.as_str(), "from" | "to" | "limit"))
        {
            return Err(format!(
                "{} is not a parameter of this route; it takes from, to and limit",
                shown(name)
            ));
        }
        let mut all = vec![("member".to_string(), member.to_string())];
        all.extend_from_slice(pairs);
        Self::parse(&all)
    }

    /// Whether a file in `partition` can hold an answer.
    #[must_use]
    pub fn wants_partition(&self, partition: &Partition) -> bool {
        self.member
            .as_ref()
            .is_none_or(|member| *member == partition.member)
            && self
                .from
                .is_none_or(|from| partition.date >= from.date_naive())
            && self.to.is_none_or(|to| partition.date <= to.date_naive())
    }

    /// Whether a file of the day `date` can hold an answer.
    #[must_use]
    pub fn wants_date(&self, date: NaiveDate) -> bool {
        self.from.is_none_or(|from| date >= from.date_naive())
            && self.to.is_none_or(|to| date <= to.date_naive())
    }

    /// Whether a file named `name` can hold an answer.
    #[must_use]
    pub fn wants_file(&self, name: &FileName) -> bool {
        self.wants_span(name.first_ms, name.last_ms)
    }

    /// Whether a file whose rows were received from `first_ms` to
    /// `last_ms`, in milliseconds since 1970, can hold an answer.
    #[must_use]
    pub fn wants_span(&self, first_ms: u64, last_ms: u64) -> bool {
        // A name's times are whole milliseconds, rounded down, so a file is
        // ruled out only when every time it can hold is outside the window.
        self.from
            .is_none_or(|from| i128::from(last_ms) >= i128::from(from.timestamp_millis()))
            && self
                .to
                .is_none_or(|to| i128::from(first_ms) <= i128::from(to.timestamp_millis()))
    }

    /// Whether `record` is an answer.
    #[must_use]
    pub fn wants_row<R: Row>(&self, record: &R) -> bool {
        self.member
            .as_ref()
            .is_none_or(|member| member == record.member())
            && self.from.is_none_or(|from| record.received_at() >= from)
            && self.to.is_none_or(|to| record.received_at() < to)
            && record.answers(self)
    }
}

/// At most the first 64 characters of a parameter name a client sent, in
/// quotes, for a message.
fn shown(name: &str) -> String {
    let cut: String = name.chars().take(super::fleet_center::MAX_ID_LEN).collect();
    format!("{cut:?}")
}

/// The instant the value of the parameter `name` spells.
fn instant(name: &str, value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|at| at.with_timezone(&Utc))
        .map_err(|_| format!("{name} must be an RFC 3339 time such as 2026-11-11T00:00:00Z"))
}

/// `rows` as the bytes of one Parquet file, [`ROWS_PER_GROUP`] rows to a
/// row group.
///
/// # Errors
///
/// `rows` is empty, a row's receive time is refused ([`received_ns`]), or
/// the Parquet writer fails.
pub fn encode<R: Row>(rows: &[R]) -> Result<Vec<u8>, String> {
    encode_cut(rows, GROUP_ROWS, ROWS_PER_GROUP, codec()?)
}

/// [`encode`] with `per_group` rows to a row group, wherever a member's
/// rows end.
#[cfg(test)]
fn encode_grouped<R: Row>(rows: &[R], per_group: usize) -> Result<Vec<u8>, String> {
    encode_cut(rows, per_group, per_group, codec()?)
}

/// [`encode`] without a codec: the file releases 0.5.249 to 0.5.253 wrote
/// for `rows`. Tests build the files of those releases with it; no build
/// writes them.
///
/// Public and hidden, as the test helpers of `tui/test_api.rs` are: the
/// integration suite (`tests/fleet_history_test.rs`) is another crate and
/// builds the files of those releases through the one schema and the one
/// row-group rule of this module. It is not part of the library's API.
///
/// # Errors
///
/// As [`encode`].
#[doc(hidden)]
pub fn encode_uncompressed<R: Row>(rows: &[R]) -> Result<Vec<u8>, String> {
    encode_cut(
        rows,
        GROUP_ROWS,
        ROWS_PER_GROUP,
        parquet::basic::Compression::UNCOMPRESSED,
    )
}

/// The zstd level of every file this build writes. Measured on synthetic
/// heartbeats and call records at this module's row groups: level 1 gave
/// files of 11 to 13% of the uncompressed size; level 3 gave no smaller
/// files and level 9 took three times as long to write for 7% fewer bytes.
pub const ZSTD_LEVEL: i32 = 1;

/// zstd at `level`.
///
/// # Errors
///
/// zstd has no such level.
fn zstd(level: i32) -> Result<parquet::basic::Compression, String> {
    parquet::basic::ZstdLevel::try_new(level)
        .map(parquet::basic::Compression::ZSTD)
        .map_err(parquet_error)
}

/// The codec of every column of a file this build writes: zstd at
/// [`ZSTD_LEVEL`]. `Cargo.toml` links this one codec into `parquet`
/// (feature `zstd`), and the writer panics when it is asked for a codec
/// that is not linked, so the two change together.
///
/// # Errors
///
/// [`ZSTD_LEVEL`] is not a level of zstd.
pub fn codec() -> Result<parquet::basic::Compression, String> {
    zstd(ZSTD_LEVEL)
}

/// The name of `codec` in a message.
const fn codec_name(codec: parquet::basic::Compression) -> &'static str {
    use parquet::basic::Compression;
    match codec {
        Compression::UNCOMPRESSED => "uncompressed",
        Compression::SNAPPY => "snappy",
        Compression::GZIP(_) => "gzip",
        Compression::LZO => "lzo",
        Compression::BROTLI(_) => "brotli",
        Compression::LZ4 => "lz4",
        Compression::ZSTD(_) => "zstd",
        Compression::LZ4_RAW => "lz4_raw",
    }
}

/// Whether this build reads a column named `column` that is compressed
/// with `codec`: the files it writes are zstd, and the files releases
/// 0.5.249 to 0.5.253 wrote have no codec.
///
/// # Errors
///
/// `codec` is another codec; the message names the column and the codec.
fn codec_read(column: &str, codec: parquet::basic::Compression) -> Result<(), String> {
    use parquet::basic::Compression;
    match codec {
        Compression::UNCOMPRESSED | Compression::ZSTD(_) => Ok(()),
        other => {
            let codec = codec_name(other);
            Err(format!(
                "parquet: column {column} is compressed with {codec}; this build reads zstd and \
                 uncompressed files"
            ))
        }
    }
}

/// Whether this build reads every column of every row group `metadata`
/// lists ([`codec_read`]). A file is refused whole: a reader that met the
/// codec at the first page of a row group would answer for the row groups
/// before it and say nothing of the rest.
///
/// # Errors
///
/// The first column, in file order, in a codec this build does not read.
fn codecs_read(metadata: &parquet::file::metadata::ParquetMetaData) -> Result<(), String> {
    metadata
        .row_groups()
        .iter()
        .flat_map(|group| group.columns())
        .try_for_each(|column| {
            codec_read(column.column_path().string().as_str(), column.compression())
        })
}

/// [`encode`] with row groups of `least` to `most` rows ([`group_cuts`]),
/// every column compressed with `codec`.
fn encode_cut<R: Row>(
    rows: &[R],
    least: usize,
    most: usize,
    codec: parquet::basic::Compression,
) -> Result<Vec<u8>, String> {
    use parquet::file::properties::{EnabledStatistics, WriterProperties};
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::types::ColumnPath;
    if rows.is_empty() {
        return Err("no rows: a file holds at least one".to_string());
    }
    let schema = parquet::schema::parser::parse_message_type(R::SCHEMA).map_err(parquet_error)?;
    let mut properties = WriterProperties::builder()
        .set_created_by("sipnab".to_string())
        .set_statistics_enabled(EnabledStatistics::Chunk)
        .set_compression(codec);
    if let Some(column) = R::FILTER_COLUMN {
        properties = properties.set_column_bloom_filter_enabled(ColumnPath::from(column), true);
    }
    let mut writer =
        SerializedFileWriter::new(Vec::new(), Arc::new(schema), Arc::new(properties.build()))
            .map_err(parquet_error)?;
    let members: Vec<&str> = rows.iter().map(Row::member).collect();
    let mut rest = rows;
    for cut in group_cuts(&members, least, most) {
        let (chunk, after) = rest.split_at(cut.min(rest.len()));
        rest = after;
        let mut group = writer.next_row_group().map_err(parquet_error)?;
        for column in R::columns(chunk)? {
            match column {
                Column::Longs(values) => write_longs(&mut group, &values)?,
                Column::Texts(values) => {
                    write_texts(&mut group, values.iter().map(Vec::as_slice))?;
                }
            }
        }
        group.close().map_err(parquet_error)?;
    }
    writer.into_inner().map_err(parquet_error)
}

/// A send time as the file holds it: RFC 3339 in UTC with nine digits of
/// the second, so every time reads back as it was.
fn sent_text(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// A Parquet error as this module reports it.
fn parquet_error(e: parquet::errors::ParquetError) -> String {
    format!("parquet: {e}")
}

/// What gives the Parquet bytes of the rows of one file: [`encode`], or in
/// tests the encoding of an earlier release.
type Encoder<'a, R> = dyn Fn(&[R]) -> Result<Vec<u8>, String> + 'a;

/// The row group being written.
type GroupWriter<'a> = parquet::file::writer::SerializedRowGroupWriter<'a, Vec<u8>>;

/// Write `values` as the next column of `group`, a column of 64-bit
/// numbers.
fn write_longs(group: &mut GroupWriter<'_>, values: &[i64]) -> Result<(), String> {
    let mut column = group
        .next_column()
        .map_err(parquet_error)?
        .ok_or("parquet: the schema has fewer columns than a row")?;
    column
        .typed::<parquet::data_type::Int64Type>()
        .write_batch(values, None, None)
        .map_err(parquet_error)?;
    column.close().map_err(parquet_error)
}

/// Write `values` as the next column of `group`, a column of byte texts.
fn write_texts<'a>(
    group: &mut GroupWriter<'_>,
    values: impl Iterator<Item = &'a [u8]>,
) -> Result<(), String> {
    let values: Vec<parquet::data_type::ByteArray> =
        values.map(parquet::data_type::ByteArray::from).collect();
    let mut column = group
        .next_column()
        .map_err(parquet_error)?
        .ok_or("parquet: the schema has fewer columns than a row")?;
    column
        .typed::<parquet::data_type::ByteArrayType>()
        .write_batch(&values, None, None)
        .map_err(parquet_error)?;
    column.close().map_err(parquet_error)
}

/// What `decode` read.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded<R> {
    /// The rows that answer the question, in the file's order.
    pub rows: Vec<R>,
    /// The row groups the file holds.
    pub groups: usize,
    /// The row groups that were read: those whose receive times and
    /// Call-ID filter do not rule out an answer.
    pub groups_read: usize,
}

/// The rows of the Parquet file `bytes` that answer `query`.
///
/// # Errors
///
/// `bytes` is not a Parquet file of [`encode`]'s schema, or a row in it
/// does not parse.
pub fn decode<R: Row>(bytes: Vec<u8>, query: &Query) -> Result<Decoded<R>, String> {
    use parquet::file::properties::ReaderProperties;
    use parquet::file::reader::FileReader as _;
    use parquet::file::serialized_reader::{ReadOptionsBuilder, SerializedFileReader};
    let options = ReadOptionsBuilder::new()
        .with_reader_properties(
            ReaderProperties::builder()
                .set_read_bloom_filter(true)
                .build(),
        )
        .build();
    let reader = SerializedFileReader::new_with_options(bytes::Bytes::from(bytes), options)
        .map_err(parquet_error)?;
    let expected = parquet::schema::parser::parse_message_type(R::SCHEMA).map_err(parquet_error)?;
    let found = reader.metadata().file_metadata().schema();
    if *found != expected {
        return Err(format!(
            "parquet: the file's schema is not the {} schema this build reads",
            R::NOUN
        ));
    }
    codecs_read(reader.metadata())?;
    let filter = R::FILTER_COLUMN.and_then(|name| {
        expected
            .get_fields()
            .iter()
            .position(|field| field.name() == name)
    });
    let mut decoded = Decoded {
        rows: Vec::new(),
        groups: reader.num_row_groups(),
        groups_read: 0,
    };
    for index in 0..reader.num_row_groups() {
        let group = reader.get_row_group(index).map_err(parquet_error)?;
        if !may_answer(&*group, query, filter) {
            continue;
        }
        decoded.groups_read += 1;
        let rows = usize::try_from(group.metadata().num_rows())
            .map_err(|_| "parquet: a row group has a negative row count".to_string())?;
        for row in group_rows::<R>(&*group, rows)? {
            if query.wants_row(&row) {
                decoded.rows.push(row);
            }
        }
    }
    Ok(decoded)
}

/// Whether the row group `group` can hold an answer to `query`, by the
/// least and the greatest receive time it records and by its Call-ID
/// filter. A row group that records neither is read.
fn may_answer(
    group: &dyn parquet::file::reader::RowGroupReader,
    query: &Query,
    filter: Option<usize>,
) -> bool {
    use parquet::file::statistics::Statistics;
    // A file holds its rows by member, so the least and the greatest
    // member of a row group rule it out for a question about another.
    if let (Some(member), Some(Statistics::ByteArray(members))) = (
        query.member.as_ref(),
        group.metadata().column(COL_MEMBER).statistics(),
    ) {
        let asked = member.as_bytes();
        if members.min_opt().is_some_and(|min| asked < min.data())
            || members.max_opt().is_some_and(|max| asked > max.data())
        {
            return false;
        }
    }
    if let Some(Statistics::Int64(times)) = group.metadata().column(COL_RECEIVED_AT).statistics() {
        let before = |at: DateTime<Utc>| at.timestamp_nanos_opt();
        if let (Some(from), Some(max)) = (query.from.and_then(before), times.max_opt())
            && *max < from
        {
            return false;
        }
        if let (Some(to), Some(min)) = (query.to.and_then(before), times.min_opt())
            && *min >= to
        {
            return false;
        }
    }
    if let (Some(call_id), Some(filter)) = (
        query.call_id.as_ref(),
        filter.and_then(|column| group.get_column_bloom_filter(column)),
    ) && !filter.check(&parquet::data_type::ByteArray::from(call_id.as_str()))
    {
        return false;
    }
    true
}

/// The `rows` rows of the row group `group`.
fn group_rows<R: Row>(
    group: &dyn parquet::file::reader::RowGroupReader,
    rows: usize,
) -> Result<Vec<R>, String> {
    let columns = (0..group.num_columns())
        .map(
            |column| match group.metadata().column(column).column_type() {
                parquet::basic::Type::INT64 => read_longs(group, column, rows).map(Column::Longs),
                _ => read_texts(group, column, rows).map(|values| {
                    Column::Texts(values.iter().map(|value| value.data().to_vec()).collect())
                }),
            },
        )
        .collect::<Result<Vec<Column>, String>>()?;
    R::from_columns(columns, rows)
}

/// The `rows` values of column `column` of `group`, a column of 64-bit
/// numbers.
fn read_longs(
    group: &dyn parquet::file::reader::RowGroupReader,
    column: usize,
    rows: usize,
) -> Result<Vec<i64>, String> {
    use parquet::column::reader::ColumnReader;
    let ColumnReader::Int64ColumnReader(mut reader) =
        group.get_column_reader(column).map_err(parquet_error)?
    else {
        return Err(format!("parquet: column {column} is not a 64-bit number"));
    };
    let mut values = Vec::with_capacity(rows);
    while values.len() < rows {
        let (read, _, _) = reader
            .read_records(rows - values.len(), None, None, &mut values)
            .map_err(parquet_error)?;
        if read == 0 {
            return Err(format!(
                "parquet: column {column} holds {} of its {rows} rows",
                values.len()
            ));
        }
    }
    Ok(values)
}

/// The `rows` values of column `column` of `group`, a column of byte
/// texts.
fn read_texts(
    group: &dyn parquet::file::reader::RowGroupReader,
    column: usize,
    rows: usize,
) -> Result<Vec<parquet::data_type::ByteArray>, String> {
    use parquet::column::reader::ColumnReader;
    let ColumnReader::ByteArrayColumnReader(mut reader) =
        group.get_column_reader(column).map_err(parquet_error)?
    else {
        return Err(format!("parquet: column {column} is not a byte text"));
    };
    let mut values = Vec::with_capacity(rows);
    while values.len() < rows {
        let (read, _, _) = reader
            .read_records(rows - values.len(), None, None, &mut values)
            .map_err(parquet_error)?;
        if read == 0 {
            return Err(format!(
                "parquet: column {column} holds {} of its {rows} rows",
                values.len()
            ));
        }
    }
    Ok(values)
}

/// The records of the sealed file at `rel` that holds `parquet`: the path
/// first, then the Parquet bytes in pieces of at most `chunk` bytes.
#[must_use]
pub fn sealed_lines(rel: &str, parquet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    std::iter::once(rel.as_bytes().to_vec())
        .chain(parquet.chunks(chunk.max(1)).map(<[u8]>::to_vec))
        .collect()
}

/// The Parquet bytes the sealed file `bytes` holds, read at the path `rel`
/// under the history directory.
///
/// # Errors
///
/// The sealed layer refuses the file (not a sealed file of kind `kind`, key
/// not loaded, modified, truncated), or the file was written for another
/// path than `rel`. The message starts with `rel` and names the layer.
pub fn unseal(rel: &str, bytes: &[u8], keys: &Keys, kind: Kind) -> Result<Vec<u8>, String> {
    let log = super::fleet_seal::open_log(bytes, keys, kind)
        .map_err(|e| format!("{rel}: sealed layer: the file {e}"))?;
    if log.torn_tail {
        return Err(format!(
            "{rel}: sealed layer: the file was truncated: its last record is incomplete"
        ));
    }
    let Some((path, pieces)) = log.records.split_first() else {
        return Err(format!("{rel}: sealed layer: the file holds no path"));
    };
    if path != rel.as_bytes() {
        let written: String = String::from_utf8_lossy(path).chars().take(256).collect();
        return Err(format!(
            "{rel}: sealed layer: the file was written as '{written}' and is not at that path"
        ));
    }
    Ok(pieces.concat())
}

/// The rows of `rows` that `stored` does not hold, in order. A row is the
/// same row when its member and its identity are the same
/// ([`Row::identity`]): for a call record its stream, its position and its
/// send time, for a heartbeat its count and its receive time.
#[must_use]
pub fn without_stored<R: Row>(rows: Vec<R>, stored: &[R]) -> Vec<R> {
    /// A member and what tells one of its rows from another.
    type Key<'a> = (&'a str, (&'a str, u64, DateTime<Utc>));
    let held: BTreeSet<Key<'_>> = stored
        .iter()
        .map(|row| (row.member(), row.identity()))
        .collect();
    rows.into_iter()
        .filter(|row| !held.contains(&(row.member(), row.identity())))
        .collect()
}

/// The oldest day a retention of `days` days keeps on the day `today`.
#[must_use]
pub fn oldest_kept(today: NaiveDate, days: u32) -> NaiveDate {
    today
        .checked_sub_days(chrono::Days::new(u64::from(days)))
        .unwrap_or(NaiveDate::MIN)
}

/// The oldest day of heartbeats a member retention of `retention` keeps at
/// `now`: the day the oldest kept instant falls on, so a day is removed
/// only once every instant of it is past the retention.
#[must_use]
pub fn oldest_kept_at(now: DateTime<Utc>, retention: chrono::Duration) -> NaiveDate {
    now.checked_sub_signed(retention)
        .map_or(NaiveDate::MIN, |at| at.date_naive())
}

/// The days of `dates` that are past a retention of `days` days on the
/// day `today`: a day is kept while it is at most `days` days old.
#[must_use]
pub fn expired(dates: &[NaiveDate], today: NaiveDate, days: u32) -> Vec<NaiveDate> {
    let oldest_kept = oldest_kept(today, days);
    dates
        .iter()
        .copied()
        .filter(|date| *date < oldest_kept)
        .collect()
}

/// The newest `limit` rows of `rows`, newest first, each row once, and
/// whether there were more.
#[must_use]
pub fn newest<R: Row>(rows: Vec<R>, limit: usize) -> (Vec<R>, bool) {
    let mut rows = rows;
    rows.sort_by(|a, b| {
        let (a_stream, a_seq, a_at) = a.identity();
        let (b_stream, b_seq, b_at) = b.identity();
        b.received_at()
            .cmp(&a.received_at())
            .then_with(|| a.member().cmp(b.member()))
            .then_with(|| a_stream.cmp(b_stream))
            .then_with(|| b_seq.cmp(&a_seq))
            .then_with(|| b_at.cmp(&a_at))
    });
    rows.dedup_by(|a, b| a.member() == b.member() && a.identity() == b.identity());
    let more = rows.len() > limit;
    rows.truncate(limit);
    (rows, more)
}

/// What one [`History::file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Filed {
    /// The files written.
    pub files: usize,
    /// The rows in them.
    pub rows: usize,
    /// The rows left out because a file already held them.
    pub already: usize,
}

/// A file of the history store that can hold an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The file's path under the history directory, with `/` between its
    /// parts.
    pub rel: String,
    /// The earliest receive time its name states, in milliseconds since
    /// 1970.
    pub first_ms: u64,
    /// The latest receive time its name states.
    pub last_ms: u64,
    /// The member whose rows it holds, when its path names one: a file
    /// release 0.5.249 wrote, under `member=<id>`. A file of the layout
    /// this build writes holds every member's rows and names none.
    pub member: Option<String>,
}

/// What one [`History::expire`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Expired {
    /// The days whose directory was removed.
    pub days: usize,
    /// The files removed.
    pub files: usize,
    /// What was past the retention and was not removed, with the reason: a
    /// file this module did not write, or a file or directory the system
    /// refused to remove.
    pub left: Vec<String>,
}

/// The answer to one question.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer<R> {
    /// The rows, newest first, at most the question's limit.
    pub rows: Vec<R>,
    /// Whether more rows answer the question than were returned.
    pub more: bool,
    /// The files that could not be read, each with the reason.
    pub refused: Vec<(String, String)>,
    /// The files that were opened.
    pub files_read: usize,
    /// The files that were left unread because the question ruled in more
    /// than [`MAX_FILES_PER_QUESTION`].
    pub files_not_read: usize,
    /// The row groups the files that were opened hold.
    pub groups: usize,
    /// The row groups of them that were read: those whose member, receive
    /// times and Call-ID filter do not rule out an answer.
    pub groups_read: usize,
}

impl<R> Answer<R> {
    /// The answer as a route returns it, with the rows under `key`, each
    /// as `row` shows it. `complete` is true when every file the question
    /// needed was read.
    #[must_use]
    pub fn json_as(&self, key: &str, row: impl Fn(&R) -> serde_json::Value) -> serde_json::Value {
        let refused: Vec<serde_json::Value> = self
            .refused
            .iter()
            .map(|(file, reason)| serde_json::json!({"file": file, "reason": reason}))
            .collect();
        let rows: Vec<serde_json::Value> = self.rows.iter().map(row).collect();
        let mut answer = serde_json::json!({
            "count": self.rows.len(),
            "more": self.more,
            "complete": self.refused.is_empty() && self.files_not_read == 0,
            "refused": refused,
            "files_read": self.files_read,
            "files_not_read": self.files_not_read,
        });
        answer[key] = serde_json::Value::Array(rows);
        answer
    }
}

impl Answer<IntakeRecord> {
    /// The answer as `GET /v1/fleet/calls` returns it.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        self.json_as("calls", |row| {
            serde_json::to_value(row).unwrap_or(serde_json::Value::Null)
        })
    }
}

/// Create the directory `path`, and those above it that are missing, for
/// the owner alone.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// The names in the directory `path`, sorted, each with whether it is a
/// directory; none when `path` is absent.
fn names(path: &Path) -> std::io::Result<Vec<(String, bool)>> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            out.push((name.to_string(), entry.file_type()?.is_dir()));
        }
    }
    out.sort();
    Ok(out)
}

/// Whether `name` is a staged file a write goes through.
fn is_staged(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(".partial")
}

/// The history store's directory and the keys its files are sealed under.
#[derive(Debug, Clone)]
pub struct History {
    /// The directory, `<store>.parquet`.
    dir: PathBuf,
    /// The current key to write under, the old ones to read under.
    keys: Arc<Keys>,
}

impl History {
    /// The history store beside the store file `store`, its directory
    /// created when absent. A staged file that a stopped write left is
    /// removed: it was never part of the store.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or read. The message names it.
    pub fn open(store: &Path, keys: Arc<Keys>) -> Result<Self, String> {
        let dir = dir_for(store);
        let refused = |e: std::io::Error| format!("the history store '{}': {e}", dir.display());
        create_private_dir(&dir).map_err(refused)?;
        let history = Self {
            dir: dir.clone(),
            keys,
        };
        for class in [CLASS_CALLS, CLASS_MEMBERS] {
            for (_, day) in history.day_dirs(class).map_err(refused)? {
                // A day's own files, and those of the member directories
                // release 0.5.249 wrote in it.
                let mut dirs = vec![day.clone()];
                for (name, is_dir) in names(&day).map_err(refused)? {
                    if is_dir {
                        dirs.push(day.join(name));
                    }
                }
                for dir in dirs {
                    for (name, is_dir) in names(&dir).map_err(refused)? {
                        if !is_dir && is_staged(&name) {
                            std::fs::remove_file(dir.join(&name)).map_err(refused)?;
                        }
                    }
                }
            }
        }
        Ok(history)
    }

    /// The history store beside the store file `store`, for a reader:
    /// nothing is created and nothing is removed.
    #[must_use]
    pub fn reader(store: &Path, keys: Arc<Keys>) -> Self {
        Self {
            dir: dir_for(store),
            keys,
        }
    }

    /// Every directory of the class `class`, each with its name and its
    /// path: the days, and directories under names this module does not
    /// write, for the caller to rule out.
    fn day_dirs(&self, class: &str) -> std::io::Result<Vec<(String, PathBuf)>> {
        let class = self.dir.join(class);
        Ok(names(&class)?
            .into_iter()
            .filter(|(_, is_dir)| *is_dir)
            .map(|(name, _)| {
                let path = class.join(&name);
                (name, path)
            })
            .collect())
    }

    /// The files of the day at `day`, whose directory is named `date_dir`
    /// in the class `class`, that pass `wants`: the files of the day
    /// itself, which hold every member's rows, and the files release
    /// 0.5.249 wrote under `member=<id>` for the members `member` passes.
    fn day_files(
        class: &str,
        date_dir: &str,
        day: &Path,
        member: &dyn Fn(&str) -> bool,
        wants: &dyn Fn(u64, u64) -> bool,
    ) -> std::io::Result<Vec<Listed>> {
        let mut out = Vec::new();
        for (entry, is_dir) in names(day)? {
            if !is_dir {
                if let Some(name) = IntervalName::parse(&entry)
                    && wants(name.first_ms, name.last_ms)
                {
                    out.push(Listed {
                        rel: format!("{class}/{date_dir}/{entry}"),
                        first_ms: name.first_ms,
                        last_ms: name.last_ms,
                        member: None,
                    });
                }
                continue;
            }
            let Some(partition) =
                Partition::parse(date_dir, &entry).filter(|partition| member(&partition.member))
            else {
                continue;
            };
            for (file, is_dir) in names(&day.join(&entry))? {
                if let Some(name) = FileName::parse(&file).filter(|_| !is_dir)
                    && wants(name.first_ms, name.last_ms)
                {
                    out.push(Listed {
                        rel: format!("{}/{file}", partition.rel_dir(class)),
                        first_ms: name.first_ms,
                        last_ms: name.last_ms,
                        member: Some(partition.member.clone()),
                    });
                }
            }
        }
        Ok(out)
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// File `records`: one new file for each day with rows that no file of
    /// that day already holds, whatever the number of members the rows
    /// came from. A file holds its rows by member and then by receive
    /// time ([`sorted`]). Every file is on disk before this returns.
    ///
    /// # Errors
    ///
    /// A row's receive time is refused, a directory or file cannot be
    /// written, or a file that may already hold some of the rows cannot be
    /// read. Files written before the error stay; filing the same records
    /// again leaves their rows out.
    pub fn file<R: Row>(&self, records: &[R]) -> Result<Filed, String> {
        self.file_as(records, &encode)
    }

    /// [`History::file`] as releases 0.5.251 to 0.5.253 did: the same
    /// layout, without a codec. Tests build the files of those releases
    /// with it; no build writes them.
    ///
    /// # Errors
    ///
    /// As [`History::file`].
    #[cfg(test)]
    pub(crate) fn file_plain<R: Row>(&self, records: &[R]) -> Result<Filed, String> {
        self.file_as(records, &encode_uncompressed)
    }

    /// [`History::file`] with `encoder` giving the Parquet bytes of the
    /// rows of one file.
    fn file_as<R: Row>(&self, records: &[R], encoder: &Encoder<'_, R>) -> Result<Filed, String> {
        let mut filed = Filed::default();
        for (date, rows) in by_date(records) {
            let date_dir = format!("{DATE_PREFIX}{}", date.format(DATE_FORMAT));
            let rel_dir = format!("{}/{date_dir}", R::CLASS);
            let dir = self.dir.join(&rel_dir);
            let refused = |e: std::io::Error| format!("the history store: {rel_dir}: {e}");
            let asked = rows.len();
            let earliest = IntervalName::of(&rows)?.first_ms;
            create_private_dir(&dir).map_err(refused)?;
            // A row given twice is filed once: the first given stays.
            let mut given = BTreeSet::new();
            let mut rows: Vec<R> = rows
                .into_iter()
                .filter(|row| {
                    let (stream, seq, at) = row.identity();
                    given.insert((row.member().to_string(), stream.to_string(), seq, at))
                })
                .collect();
            // A file whose latest row is not before these rows' earliest
            // may hold some of them: after a stop between filing and
            // emptying the intake, it holds all of them. That is so for a
            // file of this layout and for a file release 0.5.249 wrote for
            // one of these rows' members.
            let members: BTreeSet<&str> = rows.iter().map(Row::member).collect();
            let may_hold = Self::day_files(
                R::CLASS,
                &date_dir,
                &dir,
                &|member| members.contains(member),
                &|_, last_ms| last_ms >= earliest,
            )
            .map_err(refused)?;
            drop(members);
            for file in may_hold {
                let stored = self.read::<R>(&file.rel, &Query::all())?;
                rows = without_stored(rows, &stored.rows);
            }
            filed.already += asked - rows.len();
            if rows.is_empty() {
                continue;
            }
            let rows = sorted(rows);
            let name = IntervalName::of(&rows)?.text();
            let rel = format!("{rel_dir}/{name}");
            let path = dir.join(&name);
            if path.exists() {
                return Err(format!(
                    "the history store: {rel} exists and holds other rows; it is not replaced"
                ));
            }
            let lines = sealed_lines(&rel, &encoder(&rows)?, CHUNK_BYTES);
            super::fleet_center::write_sealed_reading(
                &path,
                &self.keys,
                R::KIND,
                lines.into_iter().map(Ok),
                &|staged| std::fs::read(staged),
            )
            .and_then(|_| std::fs::File::open(&dir)?.sync_all())
            .map_err(|e| format!("the history store: {rel}: {e}"))?;
            filed.files += 1;
            filed.rows += rows.len();
        }
        Ok(filed)
    }

    /// File `records` as release 0.5.249 did: one new file for each day
    /// and member, under `member=<id>`. Tests build the files of that
    /// release with it; no build writes them.
    ///
    /// # Errors
    ///
    /// As [`History::file`].
    #[cfg(test)]
    pub(crate) fn file_per_member<R: Row>(&self, records: &[R]) -> Result<Filed, String> {
        let mut filed = Filed::default();
        for (partition, rows) in groups(records) {
            let rel_dir = partition.rel_dir(R::CLASS);
            let dir = self.dir.join(&rel_dir);
            let refused = |e: std::io::Error| format!("the history store: {rel_dir}: {e}");
            let asked = rows.len();
            let earliest = FileName::of(&rows)?.first_ms;
            create_private_dir(&dir).map_err(refused)?;
            // A row given twice is filed once: the first given stays.
            let mut given = BTreeSet::new();
            let mut rows: Vec<R> = rows
                .into_iter()
                .filter(|row| {
                    let (stream, seq, at) = row.identity();
                    given.insert((stream.to_string(), seq, at))
                })
                .collect();
            // A file whose latest row is not before this group's earliest
            // may hold some of the group: after a stop between filing and
            // emptying the intake, it holds all of it.
            for (name, is_dir) in names(&dir).map_err(refused)? {
                let may_hold = !is_dir
                    && FileName::parse(&name).is_some_and(|stored| stored.last_ms >= earliest);
                if may_hold {
                    let stored = self.read::<R>(&format!("{rel_dir}/{name}"), &Query::all())?;
                    rows = without_stored(rows, &stored.rows);
                }
            }
            filed.already += asked - rows.len();
            if rows.is_empty() {
                continue;
            }
            let name = FileName::of(&rows)?.text();
            let rel = format!("{rel_dir}/{name}");
            let path = dir.join(&name);
            if path.exists() {
                return Err(format!(
                    "the history store: {rel} exists and holds other rows; it is not replaced"
                ));
            }
            let lines = sealed_lines(&rel, &encode_uncompressed(&rows)?, CHUNK_BYTES);
            super::fleet_center::write_sealed_reading(
                &path,
                &self.keys,
                R::KIND,
                lines.into_iter().map(Ok),
                &|staged| std::fs::read(staged),
            )
            .and_then(|_| std::fs::File::open(&dir)?.sync_all())
            .map_err(|e| format!("the history store: {rel}: {e}"))?;
            filed.files += 1;
            filed.rows += rows.len();
        }
        Ok(filed)
    }

    /// The files of the class `class` that can hold an answer to `query`,
    /// by their paths alone, the file with the latest rows first.
    ///
    /// # Errors
    ///
    /// A directory of the store cannot be read.
    pub fn list(&self, class: &str, query: &Query) -> Result<Vec<Listed>, String> {
        let refused = |e: std::io::Error| format!("the history store: {e}");
        let mut out = Vec::new();
        for (date_dir, day) in self.day_dirs(class).map_err(refused)? {
            if !parse_date_dir(&date_dir).is_some_and(|date| query.wants_date(date)) {
                continue;
            }
            out.extend(
                Self::day_files(
                    class,
                    &date_dir,
                    &day,
                    &|member| query.member.as_deref().is_none_or(|asked| asked == member),
                    &|first_ms, last_ms| query.wants_span(first_ms, last_ms),
                )
                .map_err(refused)?,
            );
        }
        out.sort_by(|a, b| b.last_ms.cmp(&a.last_ms).then_with(|| a.rel.cmp(&b.rel)));
        Ok(out)
    }

    /// The rows of the file at `rel` that answer `query`.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the sealed layer refuses it, or its
    /// Parquet does not parse. The message starts with `rel`.
    pub fn read<R: Row>(&self, rel: &str, query: &Query) -> Result<Decoded<R>, String> {
        self.read_io(rel, query).map_err(|e| e.to_string())
    }

    /// [`History::read`], with a file that is absent told apart.
    fn read_io<R: Row>(&self, rel: &str, query: &Query) -> std::io::Result<Decoded<R>> {
        let bytes = match std::fs::read(self.dir.join(rel)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
            Err(e) => return Err(std::io::Error::other(format!("{rel}: {e}"))),
        };
        let parquet = unseal(rel, &bytes, &self.keys, R::KIND).map_err(std::io::Error::other)?;
        decode(parquet, query).map_err(|e| std::io::Error::other(format!("{rel}: {e}")))
    }

    /// Remove the days of the class `class` past a retention of `days` days
    /// on the day `today` ([`expired`]): the files this module wrote in
    /// them, and then their directories.
    ///
    /// # Errors
    ///
    /// The store's directory cannot be read.
    pub fn expire(&self, class: &str, today: NaiveDate, days: u32) -> Result<Expired, String> {
        self.expire_before(class, oldest_kept(today, days))
    }

    /// Remove the days of the class `class` before the day `oldest_kept`:
    /// the files this module wrote in them, and then their directories.
    ///
    /// # Errors
    ///
    /// The store's directory cannot be read.
    pub fn expire_before(
        &self,
        class_name: &str,
        oldest_kept: NaiveDate,
    ) -> Result<Expired, String> {
        let refused = |e: std::io::Error| format!("the history store: {e}");
        let class = self.dir.join(class_name);
        let dated: Vec<(NaiveDate, String)> = names(&class)
            .map_err(refused)?
            .into_iter()
            .filter(|(_, is_dir)| *is_dir)
            .filter_map(|(name, _)| parse_date_dir(&name).map(|date| (date, name)))
            .collect();
        let mut out = Expired::default();
        for (_, date_dir) in dated.iter().filter(|(date, _)| *date < oldest_kept) {
            let day = class.join(date_dir);
            for (member_dir, is_dir) in names(&day).map_err(refused)? {
                let rel = format!("{class_name}/{date_dir}/{member_dir}");
                if !is_dir {
                    // A file of the day itself: one that holds every
                    // member's rows, or a staged one.
                    let ours = IntervalName::parse(&member_dir).is_some() || is_staged(&member_dir);
                    if !ours {
                        out.left.push(format!("{rel}: not a file of the store"));
                    } else if let Err(e) = std::fs::remove_file(day.join(&member_dir)) {
                        out.left.push(format!("{rel}: {e}"));
                    } else if !is_staged(&member_dir) {
                        out.files += 1;
                    }
                    continue;
                }
                let member = day.join(&member_dir);
                for (file, is_dir) in names(&member).map_err(refused)? {
                    let ours = !is_dir && (FileName::parse(&file).is_some() || is_staged(&file));
                    if !ours {
                        out.left
                            .push(format!("{rel}/{file}: not a file of the store"));
                    } else if let Err(e) = std::fs::remove_file(member.join(&file)) {
                        out.left.push(format!("{rel}/{file}: {e}"));
                    } else if !is_staged(&file) {
                        out.files += 1;
                    }
                }
                // Fails, and leaves the directory, when a file was left.
                let _ = std::fs::remove_dir(&member);
            }
            if std::fs::remove_dir(&day).is_ok() {
                out.days += 1;
            }
        }
        Ok(out)
    }

    /// The answer to `query` from `files`, which [`History::list`] gave
    /// for it, and `waiting`, the rows the intake holds. A file that was
    /// removed since it was listed is passed over. Files are read from the
    /// latest rows back, and reading stops once no file left can hold a
    /// row among the newest the limit allows.
    #[must_use]
    pub fn answer<R: Row>(&self, query: &Query, files: &[Listed], waiting: Vec<R>) -> Answer<R> {
        self.answer_within(query, files, waiting, MAX_FILES_PER_QUESTION)
    }

    /// [`History::answer`] that opens at most `max_files` files: the files
    /// left when that many were opened are counted in
    /// [`Answer::files_not_read`].
    #[must_use]
    pub fn answer_within<R: Row>(
        &self,
        query: &Query,
        files: &[Listed],
        waiting: Vec<R>,
        max_files: usize,
    ) -> Answer<R> {
        let mut answer = Answer {
            rows: waiting
                .into_iter()
                .filter(|row| query.wants_row(row))
                .collect(),
            more: false,
            refused: Vec::new(),
            files_read: 0,
            files_not_read: 0,
            groups: 0,
            groups_read: 0,
        };
        let keep = query.limit.saturating_add(1);
        for (index, file) in files.iter().enumerate() {
            if answer.rows.len() >= keep {
                // The rows held are the newest `keep` so far. A file whose
                // latest row is older than the oldest of them adds none to
                // the answer, and neither does any file after it.
                let (rows, _) = newest(std::mem::take(&mut answer.rows), keep);
                answer.rows = rows;
                let oldest = answer.rows.last().map(Row::received_at);
                if answer.rows.len() >= keep
                    && oldest.is_some_and(|at| {
                        i128::from(file.last_ms) < i128::from(at.timestamp_millis())
                    })
                {
                    break;
                }
            }
            if answer.files_read + answer.refused.len() >= max_files {
                answer.files_not_read = files.len() - index;
                break;
            }
            match self.read_io(&file.rel, query) {
                Ok(decoded) => {
                    answer.files_read += 1;
                    answer.groups += decoded.groups;
                    answer.groups_read += decoded.groups_read;
                    answer.rows.extend(decoded.rows);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => answer
                    .refused
                    .push((file.rel.clone(), reason(&file.rel, &e))),
            }
        }
        let (rows, more) = newest(answer.rows, query.limit);
        answer.rows = rows;
        answer.more = more;
        answer
    }

    /// The newest heartbeat the store holds of each member, for a registry
    /// that `known` describes: the members the store file names, each with
    /// the receive time of the heartbeat it holds of that member.
    ///
    /// The files of the days from `oldest` on are read from the latest
    /// rows back, each once, whatever the number of members. Reading stops
    /// at the first file that ends before the newest receive time in
    /// `known`, since the store file is written before a heartbeat waits
    /// for a filing; when every member of `known` has a row; when the
    /// files of the days from `oldest` on are read; or when `max_files`
    /// files were opened,
    /// and then the files left are counted in
    /// [`Restored::files_not_read`]. With no member in `known`, a lost
    /// store file, every file up to the bound is read.
    ///
    /// # Errors
    ///
    /// A directory of the store cannot be read.
    pub fn newest_heartbeats(
        &self,
        oldest: NaiveDate,
        known: &BTreeMap<String, DateTime<Utc>>,
        max_files: usize,
    ) -> Result<Restored, String> {
        let query = Query {
            from: oldest.and_hms_opt(0, 0, 0).map(|at| at.and_utc()),
            ..Query::all()
        };
        let files = self.list(CLASS_MEMBERS, &query)?;
        let store_ms = known
            .values()
            .max()
            .map(|at| i128::from(at.timestamp_millis()));
        let mut newest: BTreeMap<String, MemberRecord> = BTreeMap::new();
        let mut out = Restored::default();
        for (index, file) in files.iter().enumerate() {
            let last_ms = i128::from(file.last_ms);
            if store_ms.is_some_and(|store_ms| last_ms < store_ms) {
                break;
            }
            let has_all =
                !known.is_empty() && known.keys().all(|member| newest.contains_key(member));
            if has_all {
                break;
            }
            if out.files_read + out.refused.len() >= max_files {
                out.files_not_read = files.len() - index;
                break;
            }
            match self.read_io::<MemberRecord>(&file.rel, &Query::all()) {
                Ok(decoded) => {
                    out.files_read += 1;
                    for row in decoded.rows {
                        let is_newer = newest.get(&row.member).is_none_or(|held| {
                            (row.received_at, row.heartbeats) > (held.received_at, held.heartbeats)
                        });
                        if is_newer {
                            newest.insert(row.member.clone(), row);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => out.refused.push((file.rel.clone(), reason(&file.rel, &e))),
            }
        }
        // A heartbeat that is not later than the one the store file holds
        // of its member restores nothing.
        out.members = newest
            .into_values()
            .filter(|row| {
                known
                    .get(&row.member)
                    .is_none_or(|at| row.received_at > *at)
            })
            .collect();
        Ok(out)
    }

    /// The call records the store holds of each member of `since` that the
    /// center received at that member's instant or later, oldest first.
    /// Every file is read once, whatever the number of members, from the
    /// latest rows back, and at most `max_files` files are opened; the
    /// files left are counted in [`CallsAfter::files_not_read`].
    ///
    /// # Errors
    ///
    /// A directory of the store cannot be read.
    pub fn calls_after(
        &self,
        since: &BTreeMap<String, DateTime<Utc>>,
        max_files: usize,
    ) -> Result<CallsAfter, String> {
        let mut out = CallsAfter::default();
        let Some(earliest) = since.values().min().copied() else {
            return Ok(out);
        };
        let query = Query {
            from: Some(earliest),
            ..Query::all()
        };
        // A file release 0.5.249 wrote for a member that was not asked for
        // is ruled out by its path.
        let files: Vec<Listed> = self
            .list(CLASS_CALLS, &query)?
            .into_iter()
            .filter(|file| {
                file.member
                    .as_ref()
                    .is_none_or(|member| since.contains_key(member))
            })
            .collect();
        for (index, file) in files.iter().enumerate() {
            if out.files_read + out.refused.len() >= max_files {
                out.files_not_read = files.len() - index;
                break;
            }
            match self.read_io::<IntakeRecord>(&file.rel, &query) {
                Ok(decoded) => {
                    out.files_read += 1;
                    out.rows.extend(decoded.rows.into_iter().filter(|row| {
                        since
                            .get(&row.member)
                            .is_some_and(|at| row.received_at >= *at)
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => out.refused.push((file.rel.clone(), reason(&file.rel, &e))),
            }
        }
        out.rows.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then_with(|| a.member.cmp(&b.member))
                .then_with(|| a.stream.cmp(&b.stream))
                .then_with(|| a.seq.cmp(&b.seq))
        });
        Ok(out)
    }
}

/// What [`History::calls_after`] found.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CallsAfter {
    /// The call records, oldest first.
    pub rows: Vec<IntakeRecord>,
    /// The files that could not be read, each with the reason.
    pub refused: Unread,
    /// The files that were opened.
    pub files_read: usize,
    /// The files left unread because more than the bound could hold rows.
    pub files_not_read: usize,
}

/// The files that could not be read, each with the reason.
pub type Unread = Vec<(String, String)>;

/// Why the file at `rel` was not read, without the path: a read's error
/// starts with the path, which an answer holds in a field of its own.
fn reason(rel: &str, e: &std::io::Error) -> String {
    let text = e.to_string();
    text.strip_prefix(rel)
        .and_then(|rest| rest.strip_prefix(": "))
        .map_or(text.clone(), str::to_string)
}

/// What [`History::newest_heartbeats`] found.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Restored {
    /// The newest heartbeat of each member it read a file for.
    pub members: Vec<MemberRecord>,
    /// The files that could not be read, each with the reason.
    pub refused: Vec<(String, String)>,
    /// The files that were opened.
    pub files_read: usize,
    /// The files left unread because the bound on the files of one
    /// rebuild was reached before the rebuild had what it looked for.
    pub files_not_read: usize,
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::app::fleet_seal::MasterKey;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    /// One day in milliseconds.
    const DAY: i64 = 86_400_000;

    /// The row at `seq` of `member`'s stream `s`, received `ms`
    /// milliseconds into 2026-11-11.
    fn row(member: &str, ms: i64, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            stream: "s".to_string(),
            seq,
            sent_at: at_ms(ms - 250),
            selected_by: "failed".to_string(),
            call: serde_json::json!({
                "call_id": format!("call-{seq}@example.com"),
                "from": "sip:+12025550101@example.com",
            }),
        }
    }

    /// Rows `from` to `to` of `member`, one a second.
    fn rows(member: &str, from: u64, to: u64) -> Vec<IntakeRecord> {
        (from..=to)
            .map(|seq| row(member, i64::try_from(seq).unwrap_or(0) * 1000, seq))
            .collect()
    }

    /// A history store in a new directory, under key 1.
    fn store() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let history = History::open(&dir.path().join("center.store"), keys(1))?;
        Ok((dir, history))
    }

    /// Every file under `dir`, as paths relative to it, sorted.
    fn tree(dir: &Path) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(&at)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                } else if let Ok(rel) = entry.path().strip_prefix(dir) {
                    out.push(rel.to_string_lossy().into_owned());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// The positions of every row the store answers `query` with, with no
    /// row waiting.
    fn seqs(history: &History, query: &Query) -> Result<Vec<u64>, String> {
        let answer = history.answer(
            query,
            &history.list(CLASS_CALLS, query)?,
            Vec::<IntakeRecord>::new(),
        );
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}"));
        }
        Ok(answer.rows.iter().map(|r| r.seq).collect())
    }

    /// The question with `limit` rows and nothing else asked.
    fn limit(limit: usize) -> Query {
        Query {
            limit,
            ..Query::all()
        }
    }

    #[test]
    fn success_rows_are_filed_at_the_layout_path() -> TestResult {
        let (_dir, history) = store()?;
        let filed = history.file_per_member(&rows("edge-a", 1, 3))?;
        assert_eq!(
            filed,
            Filed {
                files: 1,
                rows: 3,
                already: 0
            },
            "success three rows of one day and member are one file"
        );
        assert_eq!(
            tree(history.dir())?,
            vec![
                "calls/date=2026-11-11/member=edge-a/1794355201000-1794355203000-s-1.sealed"
                    .to_string()
            ],
            "success the file is at class, day, member, name; no staged file is left"
        );
        Ok(())
    }

    #[test]
    fn success_filed_rows_read_back_equal() -> TestResult {
        let (_dir, history) = store()?;
        let written = rows("edge-a", 1, 5);
        history.file(&written)?;
        let listed = history.list(CLASS_CALLS, &Query::all())?;
        assert_eq!(listed.len(), 1, "success one file is listed");
        let decoded = history.read::<IntakeRecord>(&listed[0].rel, &Query::all())?;
        assert_eq!(
            decoded.rows, written,
            "success a row read from the store is the row that was filed"
        );
        Ok(())
    }

    #[test]
    fn success_each_day_and_member_gets_its_own_file() -> TestResult {
        let (_dir, history) = store()?;
        let mut all = rows("edge-a", 1, 2);
        all.extend(rows("edge-b", 1, 2));
        all.push(row("edge-a", DAY + 1000, 3));
        let filed = history.file_per_member(&all)?;
        assert_eq!(
            (filed.files, filed.rows),
            (3, 5),
            "success two members and two days: three files"
        );
        let dirs: BTreeSet<String> = tree(history.dir())?
            .iter()
            .filter_map(|p| p.rsplit_once('/').map(|(d, _)| d.to_string()))
            .collect();
        assert_eq!(
            dirs.into_iter().collect::<Vec<_>>(),
            vec![
                "calls/date=2026-11-11/member=edge-a",
                "calls/date=2026-11-11/member=edge-b",
                "calls/date=2026-11-12/member=edge-a",
            ],
            "success one directory for each day and member"
        );
        Ok(())
    }

    #[test]
    fn success_later_rows_are_filed_in_a_new_file() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        let filed = history.file(&rows("edge-a", 4, 6))?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (1, 3, 0),
            "success the second three rows are a second file"
        );
        assert_eq!(tree(history.dir())?.len(), 2, "success two files");
        assert_eq!(
            seqs(&history, &limit(100))?,
            vec![6, 5, 4, 3, 2, 1],
            "success every row is answered, newest first"
        );
        Ok(())
    }

    #[test]
    fn success_an_answer_joins_waiting_rows_and_filed_rows() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        let query = limit(100);
        let answer = history.answer(
            &query,
            &history.list(CLASS_CALLS, &query)?,
            rows("edge-a", 4, 5),
        );
        assert_eq!(
            answer.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![5, 4, 3, 2, 1],
            "success rows still in the intake come with the rows in files"
        );
        assert!(
            !answer.more && answer.refused.is_empty(),
            "success whole and complete"
        );
        let json = answer.json();
        assert_eq!(json["count"], 5, "success the count is the rows returned");
        assert_eq!(json["complete"], true, "success complete");
        assert_eq!(json["more"], false, "success no more");
        assert_eq!(
            json["calls"][0]["call"]["call_id"], "call-5@example.com",
            "success a row carries its call"
        );
        assert_eq!(
            json["calls"][0]["member"], "edge-a",
            "success and its member"
        );
        Ok(())
    }

    #[test]
    fn success_days_past_the_retention_are_removed_and_no_other() -> TestResult {
        let (_dir, history) = store()?;
        let mut all = rows("edge-a", 1, 2);
        all.push(row("edge-a", DAY + 1000, 3));
        all.push(row("edge-b", 2 * DAY + 1000, 4));
        all.push(row("edge-a", 3 * DAY + 1000, 5));
        history.file(&all)?;
        let today = at_ms(3 * DAY).date_naive();
        let expired = history.expire(CLASS_CALLS, today, 1)?;
        assert_eq!(
            (expired.days, expired.files, expired.left.len()),
            (2, 2, 0),
            "success the two days more than one day old go, with their two files"
        );
        let left = tree(history.dir())?;
        assert_eq!(left.len(), 2, "success two files stay: {left:?}");
        assert!(
            left.iter()
                .all(|p| p.contains("date=2026-11-13") || p.contains("date=2026-11-14")),
            "success the files of yesterday and today: {left:?}"
        );
        assert!(
            !history.dir().join("calls/date=2026-11-11").exists(),
            "success the expired day's directory is gone"
        );
        Ok(())
    }

    #[test]
    fn success_the_store_is_private_to_its_owner() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 2))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(
                mode(history.dir())?,
                0o700,
                "success the directory is the owner's alone"
            );
            assert_eq!(
                mode(&history.dir().join("calls/date=2026-11-11/member=edge-a"))?,
                0o700,
                "success so is a member's directory"
            );
            let file = tree(history.dir())?.remove(0);
            assert_eq!(
                mode(&history.dir().join(file))?,
                0o600,
                "success and a file"
            );
        }
        Ok(())
    }

    #[test]
    fn success_a_question_for_a_call_id_finds_the_call_across_files() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        history.file(&rows("edge-b", 1, 3))?;
        history.file(&rows("edge-a", 4, 6))?;
        let query = Query {
            call_id: Some("call-5@example.com".to_string()),
            ..limit(10)
        };
        assert_eq!(
            seqs(&history, &query)?,
            vec![5],
            "success the call is found in the file that holds it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_store_path_that_is_a_file_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = dir.path().join("center.store");
        std::fs::write(dir_for(&store), b"in the way")?;
        let got = History::open(&store, keys(1));
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("center.store.parquet")),
            "failure a file where the directory goes is named: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_changed_file_is_refused_by_name_and_the_rest_is_answered() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 3))?;
        history.file_per_member(&rows("edge-b", 1, 3))?;
        let bad = tree(history.dir())?.remove(0);
        let path = history.dir().join(&bad);
        let mut bytes = std::fs::read(&path)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let read = history.read::<IntakeRecord>(&bad, &Query::all());
        assert!(
            read.as_ref()
                .is_err_and(|e| e.starts_with(&bad) && e.contains("sealed layer")),
            "failure the changed file is refused with its path and the layer: {read:?}"
        );
        let query = limit(100);
        let answer = history.answer(
            &query,
            &history.list(CLASS_CALLS, &query)?,
            Vec::<IntakeRecord>::new(),
        );
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.member.as_str())
                .collect::<Vec<_>>(),
            vec!["edge-b"; 3],
            "failure the other member's rows are still answered"
        );
        assert_eq!(
            answer.refused.len(),
            1,
            "failure the refused file is reported"
        );
        assert_eq!(answer.refused[0].0, bad, "failure by its path");
        let json = answer.json();
        assert_eq!(
            json["complete"], false,
            "failure the answer says it is not complete"
        );
        assert_eq!(
            json["refused"][0]["file"],
            bad.as_str(),
            "failure and names the file"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_moved_to_another_member_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 3))?;
        let from = tree(history.dir())?.remove(0);
        let to = from.replace("member=edge-a", "member=edge-b");
        let target = history.dir().join(&to);
        std::fs::create_dir_all(target.parent().ok_or("a parent")?)?;
        std::fs::rename(history.dir().join(&from), &target)?;
        let got = history.read::<IntakeRecord>(&to, &Query::all());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("was written as") && e.contains("member=edge-a")),
            "failure rows of edge-a do not open as rows of edge-b: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_store_under_another_key_is_not_read() -> TestResult {
        let (dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        let other = History::open(&dir.path().join("center.store"), keys(2))?;
        let query = limit(100);
        let answer = other.answer(
            &query,
            &other.list(CLASS_CALLS, &query)?,
            Vec::<IntakeRecord>::new(),
        );
        assert!(answer.rows.is_empty(), "failure no row is read");
        assert!(
            answer
                .refused
                .first()
                .is_some_and(|(_, why)| why.contains("not loaded")),
            "failure the key that is not loaded is the reason: {:?}",
            answer.refused
        );
        Ok(())
    }

    #[test]
    fn failure_filing_stops_when_a_file_that_may_hold_the_rows_cannot_be_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        let bad = tree(history.dir())?.remove(0);
        let path = history.dir().join(&bad);
        let mut bytes = std::fs::read(&path)?;
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, bytes)?;
        // Rows 2 to 5 again: the file may hold some of them.
        let got = history.file(&rows("edge-a", 2, 5));
        assert!(
            got.as_ref().is_err_and(|e| e.contains(&bad)),
            "failure the file that cannot be read is named: {got:?}"
        );
        assert_eq!(
            tree(history.dir())?,
            vec![bad],
            "failure and nothing was written beside it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_that_is_not_the_stores_is_left_when_its_day_expires() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 2))?;
        let notes = history
            .dir()
            .join("calls/date=2026-11-11/member=edge-a/notes.txt");
        std::fs::write(&notes, b"an operator's file")?;
        let expired = history.expire(CLASS_CALLS, at_ms(30 * DAY).date_naive(), 1)?;
        assert_eq!(expired.files, 1, "failure the store's own file is removed");
        assert_eq!(expired.days, 0, "failure the day's directory is not");
        assert!(
            notes.exists(),
            "failure a file the store did not write stays"
        );
        assert!(
            expired.left.iter().any(|l| l.contains("notes.txt")),
            "failure and is reported: {:?}",
            expired.left
        );
        Ok(())
    }

    #[test]
    fn failure_a_row_that_cannot_be_filed_files_nothing_of_its_group() -> TestResult {
        let (_dir, history) = store()?;
        let mut early = row("edge-a", 0, 1);
        early.received_at = DateTime::<Utc>::UNIX_EPOCH - chrono::TimeDelta::days(1);
        let got = history.file(&[early]);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("1970")),
            "failure a row from before 1970 is refused: {got:?}"
        );
        assert!(
            tree(history.dir())?.is_empty(),
            "failure and no file was written for it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_directory_that_cannot_be_written_fails_the_filing() -> TestResult {
        let (_dir, history) = store()?;
        // A file where the day's directory goes.
        std::fs::create_dir_all(history.dir().join("calls"))?;
        std::fs::write(history.dir().join("calls/date=2026-11-11"), b"in the way")?;
        let got = history.file(&rows("edge-a", 1, 2));
        assert!(
            got.as_ref().is_err_and(|e| e.contains("date=2026-11-11")),
            "failure the directory that cannot be made is named: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_filing_the_same_rows_again_writes_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 4))?;
        let before = tree(history.dir())?;
        let again = history.file(&rows("edge-a", 1, 4))?;
        assert_eq!(
            again,
            Filed {
                files: 0,
                rows: 0,
                already: 4
            },
            "edge a start after a stop between filing and emptying the intake files nothing twice"
        );
        assert_eq!(tree(history.dir())?, before, "edge the files are unchanged");
        Ok(())
    }

    #[test]
    fn edge_a_replay_that_lost_its_first_rows_files_only_the_new_ones() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 5))?;
        // The intake was trimmed of rows 1 and 2 before the replay, and took
        // rows 6 and 7 after it: the group no longer starts at the same row.
        let again = history.file(&rows("edge-a", 3, 7))?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (1, 2, 3),
            "edge rows 3 to 5 are in a file already; 6 and 7 are new"
        );
        assert_eq!(
            seqs(&history, &limit(100))?,
            vec![7, 6, 5, 4, 3, 2, 1],
            "edge every row is in the store once"
        );
        Ok(())
    }

    #[test]
    fn edge_waiting_rows_that_do_not_answer_the_question_are_left_out() -> TestResult {
        let (_dir, history) = store()?;
        let mut waiting = rows("edge-a", 1, 3);
        waiting.extend(rows("edge-b", 1, 2));
        let query = Query {
            member: Some("edge-b".to_string()),
            call_id: Some("call-2@example.com".to_string()),
            ..limit(10)
        };
        let answer = history.answer(&query, &[], waiting);
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| (r.member.as_str(), r.seq))
                .collect::<Vec<_>>(),
            vec![("edge-b", 2)],
            "edge a row still in the intake is answered only when it answers the question"
        );
        Ok(())
    }

    #[test]
    fn edge_a_row_of_the_millisecond_a_file_ends_at_is_not_filed_twice() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[row("edge-a", 1000, 1)])?;
        // The same row again, with one received in the same millisecond.
        let again = history.file(&[row("edge-a", 1000, 1), row("edge-a", 1000, 2)])?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (1, 1, 1),
            "edge a file whose last row is of the group's first millisecond is read for rows \
             already filed"
        );
        assert_eq!(
            seqs(&history, &limit(100))?,
            vec![2, 1],
            "edge each row is in the store once"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_is_not_replaced_by_other_rows_under_its_name() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[row("edge-a", 1000, 1)])?;
        let name = tree(history.dir())?.remove(0);
        let before = std::fs::read(history.dir().join(&name))?;
        // Another row of the same stream, position and millisecond: the
        // member sent it at another time, so it is another row.
        let mut other = row("edge-a", 1000, 1);
        other.sent_at += chrono::TimeDelta::seconds(5);
        let got = history.file(&[other]);
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains(&name) && e.contains("is not replaced")),
            "failure the file that is in the way is named: {got:?}"
        );
        assert_eq!(
            std::fs::read(history.dir().join(&name))?,
            before,
            "failure and it is as it was"
        );
        Ok(())
    }

    #[test]
    fn edge_a_staged_file_from_a_stopped_write_is_removed_at_open() -> TestResult {
        let (dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 2))?;
        let staged = history.dir().join(
            "calls/date=2026-11-11/member=edge-a/.1794355209000-1794355209000-s-9.sealed.partial",
        );
        std::fs::write(&staged, b"half a file")?;
        let again = History::open(&dir.path().join("center.store"), keys(1))?;
        assert!(!staged.exists(), "edge the staged file is gone");
        assert_eq!(
            tree(again.dir())?.len(),
            1,
            "edge the finished file is still there"
        );
        Ok(())
    }

    #[test]
    fn edge_a_question_lists_only_the_files_its_path_rules_in() -> TestResult {
        let (_dir, history) = store()?;
        let mut all = rows("edge-a", 1, 2);
        all.extend(rows("edge-b", 1, 2));
        all.push(row("edge-a", DAY + 1000, 3));
        history.file_per_member(&all)?;
        let by_member = Query {
            member: Some("edge-b".to_string()),
            ..limit(10)
        };
        assert_eq!(
            history.list(CLASS_CALLS, &by_member)?.len(),
            1,
            "edge one member: one of three files"
        );
        let by_day = Query {
            from: Some(at_ms(DAY)),
            ..limit(10)
        };
        let listed = history.list(CLASS_CALLS, &by_day)?;
        assert_eq!(listed.len(), 1, "edge from the second day on: one file");
        assert!(
            listed[0].rel.contains("date=2026-11-12"),
            "edge the file of that day: {}",
            listed[0].rel
        );
        let by_time = Query {
            to: Some(at_ms(500)),
            ..limit(10)
        };
        assert!(
            history.list(CLASS_CALLS, &by_time)?.is_empty(),
            "edge a window before every file's first row: no file"
        );
        Ok(())
    }

    #[test]
    fn edge_names_the_store_did_not_write_are_not_listed() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 2))?;
        let member = history.dir().join("calls/date=2026-11-11/member=edge-a");
        std::fs::write(member.join("notes.txt"), b"x")?;
        std::fs::write(member.join("copy.sealed"), b"x")?;
        std::fs::create_dir_all(history.dir().join("calls/tmp/member=edge-a"))?;
        std::fs::create_dir_all(history.dir().join("calls/date=2026-11-11/other"))?;
        std::fs::write(history.dir().join("calls/readme"), b"x")?;
        assert_eq!(
            history.list(CLASS_CALLS, &Query::all())?.len(),
            1,
            "edge only the file the store wrote is listed"
        );
        Ok(())
    }

    #[test]
    fn edge_no_rows_file_nothing_and_an_empty_store_answers_nothing() -> TestResult {
        let (_dir, history) = store()?;
        assert_eq!(
            history.file::<IntakeRecord>(&[])?,
            Filed::default(),
            "edge no rows: no file"
        );
        assert!(
            history.list(CLASS_CALLS, &Query::all())?.is_empty(),
            "edge an empty store lists nothing"
        );
        assert_eq!(
            history.expire(CLASS_CALLS, at_ms(0).date_naive(), 1)?,
            Expired::default(),
            "edge and has nothing to expire"
        );
        let json = history.answer(&limit(5), &[], Vec::new()).json();
        assert_eq!(json["count"], 0, "edge the answer is empty");
        assert_eq!(json["complete"], true, "edge and complete");
        Ok(())
    }

    #[test]
    fn edge_a_file_removed_after_it_was_listed_is_passed_over() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 3))?;
        history.file(&rows("edge-b", 1, 3))?;
        let query = limit(100);
        let listed = history.list(CLASS_CALLS, &query)?;
        std::fs::remove_file(history.dir().join(&listed[0].rel))?;
        let answer = history.answer(&query, &listed, Vec::<IntakeRecord>::new());
        assert_eq!(
            answer.rows.len(),
            3,
            "edge the rows of the file that is left"
        );
        assert!(
            answer.refused.is_empty(),
            "edge a file retention removed meanwhile is not a refusal: {:?}",
            answer.refused
        );
        Ok(())
    }

    #[test]
    fn edge_a_limit_stops_the_reading_of_older_files() -> TestResult {
        let (_dir, history) = store()?;
        for start in [1u64, 11, 21, 31] {
            history.file(&rows("edge-a", start, start + 9))?;
        }
        let query = limit(5);
        let listed = history.list(CLASS_CALLS, &query)?;
        assert_eq!(listed.len(), 4, "edge four files can hold an answer");
        let answer = history.answer(&query, &listed, Vec::<IntakeRecord>::new());
        assert_eq!(
            answer.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![40, 39, 38, 37, 36],
            "edge the five newest rows"
        );
        assert_eq!(answer.files_read, 1, "edge only the newest file was opened");
        assert!(answer.more, "edge and the answer says there are more rows");
        Ok(())
    }

    #[test]
    fn edge_files_whose_times_interleave_are_all_read_for_the_newest_rows() -> TestResult {
        let (_dir, history) = store()?;
        // edge-a holds seconds 1, 3, 5, 7; edge-b holds 2, 4, 6, 8.
        let a: Vec<_> = [1i64, 3, 5, 7]
            .iter()
            .map(|s| row("edge-a", s * 1000, u64::try_from(*s).unwrap_or(0)))
            .collect();
        let b: Vec<_> = [2i64, 4, 6, 8]
            .iter()
            .map(|s| row("edge-b", s * 1000, u64::try_from(*s).unwrap_or(0)))
            .collect();
        history.file(&a)?;
        history.file(&b)?;
        assert_eq!(
            seqs(&history, &limit(3))?,
            vec![8, 7, 6],
            "edge the newest three come from both files"
        );
        Ok(())
    }

    #[test]
    fn edge_no_file_of_the_store_holds_a_number_in_clear() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 50))?;
        let needle = b"+12025550101";
        for file in tree(history.dir())? {
            let bytes = std::fs::read(history.dir().join(&file))?;
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "edge {file} holds the caller's number in clear"
            );
            assert!(
                !bytes.windows(4).any(|w| w == b"PAR1"),
                "edge {file} holds a Parquet magic in clear"
            );
        }
        Ok(())
    }

    #[test]
    fn edge_expiring_removes_staged_files_and_empty_directories() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&rows("edge-a", 1, 2))?;
        let member = history.dir().join("calls/date=2026-11-11/member=edge-a");
        std::fs::write(member.join(".x.sealed.partial"), b"half")?;
        std::fs::create_dir_all(history.dir().join("calls/date=2026-11-11/member=edge-z"))?;
        let expired = history.expire(CLASS_CALLS, at_ms(30 * DAY).date_naive(), 1)?;
        assert_eq!(
            (expired.days, expired.left.len()),
            (1, 0),
            "edge the day goes whole: {:?}",
            expired.left
        );
        assert!(
            tree(history.dir())?.is_empty(),
            "edge no file is left in the store"
        );
        assert!(
            history.dir().join("calls").exists(),
            "edge the class directory stays"
        );
        Ok(())
    }

    #[test]
    fn edge_write_and_read_time_of_a_large_file_are_measured() -> TestResult {
        // 20,000 rows of the size of a real call record (about 1.3 kB).
        let filler = "x".repeat(1100);
        let many: Vec<IntakeRecord> = (1..=20_000u64)
            .map(|seq| {
                let mut r = row("edge-a", i64::try_from(seq).unwrap_or(0), seq);
                r.call["detail"] = serde_json::Value::String(filler.clone());
                r
            })
            .collect();
        let (_dir, history) = store()?;
        let started = std::time::Instant::now();
        let filed = history.file(&many)?;
        let wrote = started.elapsed();
        assert_eq!(filed.rows, 20_000, "edge every row is filed");
        let listed = history.list(CLASS_CALLS, &Query::all())?;
        let bytes = std::fs::metadata(history.dir().join(&listed[0].rel))?.len();
        let started = std::time::Instant::now();
        let all = history.read::<IntakeRecord>(&listed[0].rel, &Query::all())?;
        let read_all = started.elapsed();
        assert_eq!(all.rows.len(), 20_000, "edge every row reads back");
        let one = Query {
            call_id: Some("call-15000@example.com".to_string()),
            ..limit(1)
        };
        let started = std::time::Instant::now();
        let found = history.read::<IntakeRecord>(&listed[0].rel, &one)?;
        let read_one = started.elapsed();
        assert_eq!(found.rows.len(), 1, "edge the one call is found");
        assert!(
            found.groups_read < found.groups,
            "edge without reading every row group: {} of {}",
            found.groups_read,
            found.groups
        );
        stderr_line!(
            "fleet history measurement: 20,000 rows, file {bytes} B, write {wrote:?}, read all \
             {read_all:?}, read one Call-ID {read_one:?} ({} of {} row groups)",
            found.groups_read,
            found.groups
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fleet_seal::{LogSealer, MasterKey, system_draw};

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// [`super::decode`] for a file of call records.
    fn decode(bytes: Vec<u8>, query: &Query) -> Result<Decoded<IntakeRecord>, String> {
        super::decode(bytes, query)
    }

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Keys {
        Keys::new(MasterKey::from_bytes([b; 32]), Vec::new())
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    /// The row at `seq` of `member`'s stream `s`, received `ms`
    /// milliseconds into 2026-11-11.
    fn row(member: &str, ms: i64, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            stream: "s".to_string(),
            seq,
            sent_at: at_ms(ms - 250),
            selected_by: "failed".to_string(),
            call: serde_json::json!({
                "call_id": format!("call-{seq}@example.com"),
                "from": "sip:+12025550101@example.com",
                "to": "sip:+12025550102@example.com",
            }),
        }
    }

    /// `count` rows of `edge-a`, one a second, from position 1.
    fn rows(count: u64) -> Vec<IntakeRecord> {
        (1..=count)
            .map(|seq| row("edge-a", i64::try_from(seq).unwrap_or(0) * 1000, seq))
            .collect()
    }

    /// The question the query string `text` asks.
    fn ask(text: &[(&str, &str)]) -> Result<Query, String> {
        let pairs: Vec<(String, String)> = text
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Query::parse(&pairs)
    }

    /// The sealed file at `rel` holding `parquet` under key `b`, in pieces
    /// of `chunk` bytes, built the way [`History`] writes one.
    fn seal(rel: &str, parquet: &[u8], b: u8, chunk: usize) -> Result<Vec<u8>, String> {
        let (mut sealer, header) =
            LogSealer::new(&MasterKey::from_bytes([b; 32]), Kind::Calls, &system_draw)?;
        let mut out = header.to_vec();
        for line in sealed_lines(rel, parquet, chunk) {
            out.extend(sealer.record(&line)?);
        }
        out.extend(sealer.base_end()?);
        Ok(out)
    }

    /// The path the tests seal their file for.
    const REL: &str = "calls/date=2026-11-11/member=edge-a/x.sealed";

    // ----- partitions and file names -----

    #[test]
    fn success_a_partition_spells_its_directory() {
        let partition = Partition::of(&row("edge-a", 0, 1));
        assert_eq!(
            partition.rel_dir(CLASS_CALLS),
            "calls/date=2026-11-11/member=edge-a",
            "success a partition spells class, day and member"
        );
    }

    #[test]
    fn success_a_partition_reads_back_from_its_directory_names() {
        let partition = Partition::of(&row("edge-a", 0, 1));
        assert_eq!(
            Partition::parse("date=2026-11-11", "member=edge-a"),
            Some(partition),
            "success the directory names give the partition back"
        );
    }

    #[test]
    fn success_a_file_name_carries_first_and_last_time_and_first_row() -> TestResult {
        let name = FileName::of(&rows(3))?;
        assert_eq!(
            name.text(),
            "1794355201000-1794355203000-s-1.sealed",
            "success a name is first ms, last ms, stream, position"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_name_reads_back() -> TestResult {
        let name = FileName::of(&rows(3))?;
        assert_eq!(
            FileName::parse(&name.text()),
            Some(name),
            "success a name parses to what wrote it"
        );
        Ok(())
    }

    #[test]
    fn success_rows_are_grouped_by_day_and_member_in_order() {
        let day = 86_400_000;
        let all = vec![
            row("edge-b", 10, 1),
            row("edge-a", 20, 1),
            row("edge-a", day + 5, 2),
            row("edge-a", 30, 3),
        ];
        let got = groups(&all);
        let shape: Vec<(String, Vec<u64>)> = got
            .iter()
            .map(|(p, rows)| (p.rel_dir(CLASS_CALLS), rows.iter().map(|r| r.seq).collect()))
            .collect();
        assert_eq!(
            shape,
            vec![
                (
                    "calls/date=2026-11-11/member=edge-a".to_string(),
                    vec![1, 3]
                ),
                ("calls/date=2026-11-11/member=edge-b".to_string(), vec![1]),
                ("calls/date=2026-11-12/member=edge-a".to_string(), vec![2]),
            ],
            "success rows go to their day and member, in arrival order"
        );
    }

    #[test]
    fn failure_directory_names_this_module_does_not_write_are_no_partition() {
        for (date, member) in [
            ("2026-11-11", "member=edge-a"),
            ("date=2026-11-11", "edge-a"),
            ("date=2026-13-01", "member=edge-a"),
            ("date=2026-1-1", "member=edge-a"),
            ("date=2026-11-11", "member="),
            ("date=2026-11-11", "member=a/b"),
            ("date=", "member=edge-a"),
            ("date=2026-11-11 ", "member=edge-a"),
        ] {
            assert_eq!(
                Partition::parse(date, member),
                None,
                "failure {date:?} / {member:?} is not a partition"
            );
        }
    }

    #[test]
    fn failure_names_this_module_does_not_write_are_no_file_name() {
        for name in [
            "",
            "x.sealed",
            "1794355201000-1794355203000-s-1",
            "1794355201000-1794355203000-s-1.parquet",
            "1794355201000-1794355203000-s-x.sealed",
            "1794355201000-1794355203000--1.sealed",
            "1794355201000-s-1.sealed",
            "1794355203000-1794355201000-s-1.sealed",
            "1794355201000-1794355203000-s-01.sealed",
            "+794355201000-1794355203000-s-1.sealed",
            "1794355201000-1794355203000-s/t-1.sealed",
            ".1794355201000-1794355203000-s-1.sealed.partial",
        ] {
            assert_eq!(
                FileName::parse(name),
                None,
                "failure {name:?} is not a file name"
            );
        }
    }

    #[test]
    fn failure_no_rows_have_no_file_name() {
        let got = FileName::of::<IntakeRecord>(&[]);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("no rows")),
            "failure a file of no rows has no name: {got:?}"
        );
    }

    #[test]
    fn failure_a_row_received_before_1970_is_refused() {
        let mut early = row("edge-a", 0, 1);
        early.received_at = DateTime::<Utc>::UNIX_EPOCH - chrono::TimeDelta::seconds(1);
        let got = FileName::of(&[early.clone()]);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("1970")),
            "failure a row from before 1970 has no file name: {got:?}"
        );
        let encoded = encode(&[early]);
        assert!(
            encoded.as_ref().is_err_and(|e| e.contains("1970")),
            "failure and is not encoded: {encoded:?}"
        );
    }

    #[test]
    fn failure_a_row_received_past_the_nanosecond_range_is_refused() {
        let mut late = row("edge-a", 0, 1);
        late.received_at = DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::days(365 * 300);
        let got = received_ns(&late);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("2262")),
            "failure a row past 2262 is refused: {got:?}"
        );
    }

    #[test]
    fn edge_a_stream_with_dashes_reads_back_whole() {
        let mut first = row("edge-a", 5, 7);
        first.stream = "a-b-9-c".to_string();
        let name = FileName::of(&[first]).ok();
        let text = name.as_ref().map(FileName::text).unwrap_or_default();
        assert_eq!(
            text, "1794355200005-1794355200005-a-b-9-c-7.sealed",
            "edge the stream keeps its dashes in the name"
        );
        assert_eq!(
            FileName::parse(&text),
            name,
            "edge and the name still parses: the times are the first two parts, the position \
             the last"
        );
    }

    #[test]
    fn edge_rows_out_of_time_order_name_the_earliest_and_latest() -> TestResult {
        let name = FileName::of(&[
            row("edge-a", 500, 4),
            row("edge-a", 100, 5),
            row("edge-a", 900, 6),
            row("edge-a", 300, 7),
        ])?;
        assert_eq!(
            (name.first_ms, name.last_ms, name.seq),
            (1_794_355_200_100, 1_794_355_200_900, 4),
            "edge first and last are the least and the greatest time; the row is the first row"
        );
        Ok(())
    }

    #[test]
    fn edge_the_last_millisecond_of_a_day_stays_in_that_day() {
        let day = 86_400_000;
        assert_eq!(
            Partition::of(&row("edge-a", day - 1, 1)).rel_dir(CLASS_CALLS),
            "calls/date=2026-11-11/member=edge-a",
            "edge 23:59:59.999 is the day it is in"
        );
        assert_eq!(
            Partition::of(&row("edge-a", day, 1)).rel_dir(CLASS_CALLS),
            "calls/date=2026-11-12/member=edge-a",
            "edge 00:00:00.000 is the next day"
        );
    }

    #[test]
    fn edge_a_member_named_with_dots_stays_one_directory() {
        let partition = Partition::of(&row("..", 0, 1));
        assert_eq!(
            partition.rel_dir(CLASS_CALLS),
            "calls/date=2026-11-11/member=..",
            "edge the member is one path part that is not the parent directory"
        );
        assert_eq!(
            Partition::parse("date=2026-11-11", "member=.."),
            Some(partition),
            "edge and it reads back"
        );
    }

    // ----- questions -----

    #[test]
    fn success_no_parameters_ask_for_the_newest_rows() -> TestResult {
        let query = ask(&[])?;
        assert_eq!(
            query,
            Query {
                member: None,
                from: None,
                to: None,
                call_id: None,
                limit: DEFAULT_LIMIT
            },
            "success an empty query string is every row, up to the default limit"
        );
        Ok(())
    }

    #[test]
    fn success_every_parameter_is_read() -> TestResult {
        let query = ask(&[
            ("member", "edge-a"),
            ("from", "2026-11-11T00:00:01Z"),
            ("to", "2026-11-11T00:00:03Z"),
            ("call_id", "call-2@example.com"),
            ("limit", "7"),
        ])?;
        assert_eq!(
            query,
            Query {
                member: Some("edge-a".to_string()),
                from: Some(at_ms(1000)),
                to: Some(at_ms(3000)),
                call_id: Some("call-2@example.com".to_string()),
                limit: 7
            },
            "success member, from, to, call_id and limit are read"
        );
        Ok(())
    }

    #[test]
    fn success_a_question_selects_its_rows() -> TestResult {
        let query = ask(&[
            ("member", "edge-a"),
            ("from", "2026-11-11T00:00:02Z"),
            ("to", "2026-11-11T00:00:04Z"),
        ])?;
        let got: Vec<u64> = rows(5)
            .iter()
            .filter(|r| query.wants_row(*r))
            .map(|r| r.seq)
            .collect();
        assert_eq!(got, vec![2, 3], "success from is included and to is not");
        assert!(
            !query.wants_row(&row("edge-b", 2000, 2)),
            "success another member's row is not an answer"
        );
        Ok(())
    }

    #[test]
    fn success_a_call_id_selects_one_call() -> TestResult {
        let query = ask(&[("call_id", "call-4@example.com")])?;
        let got: Vec<u64> = rows(5)
            .iter()
            .filter(|r| query.wants_row(*r))
            .map(|r| r.seq)
            .collect();
        assert_eq!(got, vec![4], "success only the call with that Call-ID");
        Ok(())
    }

    #[test]
    fn failure_a_question_with_a_bad_parameter_is_refused_by_name() {
        for (pairs, needle) in [
            (vec![("membr", "edge-a")], "membr"),
            (vec![("member", "a/b")], "member"),
            (vec![("member", "")], "member"),
            (vec![("from", "yesterday")], "from"),
            (vec![("to", "2026-11-11")], "to"),
            (vec![("limit", "0")], "limit"),
            (vec![("limit", "1001")], "limit"),
            (vec![("limit", "ten")], "limit"),
            (vec![("limit", "-1")], "limit"),
            (vec![("call_id", "")], "call_id"),
            (vec![("member", "a"), ("member", "b")], "member"),
        ] {
            let got = ask(&pairs);
            assert!(
                got.as_ref().is_err_and(|e| e.contains(needle)),
                "failure {pairs:?} is refused naming {needle}: {got:?}"
            );
        }
    }

    #[test]
    fn failure_a_window_that_ends_at_or_before_its_start_is_refused() {
        for (from, to) in [
            ("2026-11-11T00:00:03Z", "2026-11-11T00:00:03Z"),
            ("2026-11-11T00:00:04Z", "2026-11-11T00:00:03Z"),
        ] {
            let got = ask(&[("from", from), ("to", to)]);
            assert!(
                got.as_ref().is_err_and(|e| e.contains("after")),
                "failure from {from} to {to} holds no time: {got:?}"
            );
        }
    }

    #[test]
    fn failure_a_call_id_past_its_bound_is_refused() {
        let long = "x".repeat(MAX_CALL_ID_BYTES + 1);
        let got = ask(&[("call_id", &long)]);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("call_id")),
            "failure a call_id of {} bytes is refused",
            long.len()
        );
        let most = "x".repeat(MAX_CALL_ID_BYTES);
        assert!(
            ask(&[("call_id", &most)]).is_ok(),
            "failure the bound itself is accepted"
        );
    }

    #[test]
    fn edge_the_limit_bounds_are_accepted() -> TestResult {
        assert_eq!(ask(&[("limit", "1")])?.limit, 1, "edge a limit of 1");
        assert_eq!(
            ask(&[("limit", "1000")])?.limit,
            MAX_LIMIT,
            "edge the greatest limit"
        );
        Ok(())
    }

    #[test]
    fn edge_a_question_prunes_partitions_by_member_and_day() -> TestResult {
        let query = ask(&[
            ("member", "edge-a"),
            ("from", "2026-11-11T23:00:00Z"),
            ("to", "2026-11-12T01:00:00Z"),
        ])?;
        let wanted = |date: &str, member: &str| {
            Partition::parse(date, member).is_some_and(|p| query.wants_partition(&p))
        };
        assert!(
            wanted("date=2026-11-11", "member=edge-a"),
            "edge the day of from is read"
        );
        assert!(
            wanted("date=2026-11-12", "member=edge-a"),
            "edge the day of to is read"
        );
        assert!(
            !wanted("date=2026-11-10", "member=edge-a"),
            "edge the day before from is not"
        );
        assert!(
            !wanted("date=2026-11-13", "member=edge-a"),
            "edge the day after to is not"
        );
        assert!(
            !wanted("date=2026-11-11", "member=edge-b"),
            "edge another member is not"
        );
        Ok(())
    }

    #[test]
    fn edge_a_question_prunes_files_by_the_times_in_their_names() -> TestResult {
        let query = ask(&[
            ("from", "2026-11-11T00:00:02Z"),
            ("to", "2026-11-11T00:00:04Z"),
        ])?;
        let wanted = |first: u64, last: u64| {
            query.wants_file(&FileName {
                first_ms: 1_794_355_200_000 + first,
                last_ms: 1_794_355_200_000 + last,
                stream: "s".to_string(),
                seq: 1,
            })
        };
        assert!(wanted(0, 2000), "edge a file that ends at from is read");
        assert!(!wanted(0, 1999), "edge a file that ends before from is not");
        assert!(
            wanted(3999, 9000),
            "edge a file that starts before to is read"
        );
        assert!(
            !wanted(4001, 9000),
            "edge a file that starts after to is not"
        );
        assert!(wanted(0, 9000), "edge a file around the window is read");
        Ok(())
    }

    #[test]
    fn edge_a_question_without_a_window_wants_every_partition_and_file() -> TestResult {
        let query = ask(&[])?;
        assert!(
            Partition::parse("date=1999-01-01", "member=x")
                .is_some_and(|p| query.wants_partition(&p)),
            "edge no member and no window: every partition"
        );
        assert!(
            query.wants_file(&FileName {
                first_ms: 0,
                last_ms: u64::MAX,
                stream: "s".to_string(),
                seq: 1
            }),
            "edge and every file"
        );
        Ok(())
    }

    #[test]
    fn edge_from_with_an_offset_is_the_same_instant() -> TestResult {
        let query = ask(&[("from", "2026-11-11T01:00:02+01:00")])?;
        assert_eq!(
            query.from,
            Some(at_ms(2000)),
            "edge an offset time is read as its instant"
        );
        Ok(())
    }

    // ----- Parquet -----

    #[test]
    fn success_rows_read_back_equal() -> TestResult {
        let written = rows(25);
        let decoded = decode(encode(&written)?, &Query::all())?;
        assert_eq!(
            decoded.rows, written,
            "success every row reads back as it was filed"
        );
        assert_eq!(
            (decoded.groups, decoded.groups_read),
            (1, 1),
            "success in one row group"
        );
        Ok(())
    }

    #[test]
    fn success_rows_in_several_row_groups_read_back_in_order() -> TestResult {
        let written = rows(25);
        let decoded = decode(encode_grouped(&written, 10)?, &Query::all())?;
        assert_eq!(decoded.rows, written, "success 25 rows in groups of 10");
        assert_eq!(
            (decoded.groups, decoded.groups_read),
            (3, 3),
            "success three row groups, all read"
        );
        Ok(())
    }

    #[test]
    fn success_a_call_id_is_found_in_a_file() -> TestResult {
        let written = rows(25);
        let query = ask(&[("call_id", "call-17@example.com")])?;
        let decoded = decode(encode_grouped(&written, 10)?, &query)?;
        assert_eq!(
            decoded.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![17],
            "success the one call with that Call-ID"
        );
        Ok(())
    }

    #[test]
    fn success_a_parquet_file_starts_and_ends_with_the_format_magic() -> TestResult {
        let bytes = encode(&rows(2))?;
        assert_eq!(&bytes[..4], b"PAR1", "success the file starts with PAR1");
        assert_eq!(
            &bytes[bytes.len() - 4..],
            b"PAR1",
            "success and ends with it: a reader of the format reads the unsealed bytes"
        );
        Ok(())
    }

    #[test]
    fn failure_no_rows_are_not_encoded() {
        let got = encode::<IntakeRecord>(&[]);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("no rows")),
            "failure a file is never empty: {got:?}"
        );
    }

    #[test]
    fn failure_bytes_that_are_not_parquet_are_refused() {
        for bytes in [Vec::new(), b"PAR1".to_vec(), vec![0u8; 64]] {
            let got = decode(bytes.clone(), &Query::all());
            assert!(
                got.as_ref().is_err_and(|e| e.contains("parquet")),
                "failure {} byte(s) that are no Parquet file: {got:?}",
                bytes.len()
            );
        }
    }

    #[test]
    fn failure_a_cut_parquet_file_is_refused() -> TestResult {
        let mut bytes = encode(&rows(5))?;
        bytes.truncate(bytes.len() - 9);
        let got = decode(bytes, &Query::all());
        assert!(
            got.as_ref().is_err_and(|e| e.contains("parquet")),
            "failure a file without its end is refused: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_parquet_file_of_another_schema_is_refused() -> TestResult {
        use parquet::data_type::Int64Type;
        use parquet::file::writer::SerializedFileWriter;
        let schema = Arc::new(parquet::schema::parser::parse_message_type(
            "message other { required int64 n; }",
        )?);
        let mut writer = SerializedFileWriter::new(Vec::new(), schema, Arc::default())?;
        let mut group = writer.next_row_group()?;
        let mut column = group.next_column()?.ok_or("a column")?;
        column
            .typed::<Int64Type>()
            .write_batch(&[1, 2], None, None)?;
        column.close()?;
        group.close()?;
        let got = decode(writer.into_inner()?, &Query::all());
        assert!(
            got.as_ref().is_err_and(|e| e.contains("schema")),
            "failure a Parquet file that is no call record file: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_id_question_reads_only_the_row_groups_that_may_hold_it() -> TestResult {
        let written = rows(40);
        let query = ask(&[("call_id", "call-17@example.com")])?;
        let decoded = decode(encode_grouped(&written, 10)?, &query)?;
        assert_eq!(decoded.groups, 4, "edge four row groups");
        assert!(
            (1..4).contains(&decoded.groups_read),
            "edge the Call-ID filter rules row groups out: read {} of 4",
            decoded.groups_read
        );
        assert_eq!(decoded.rows.len(), 1, "edge and the call is still found");
        Ok(())
    }

    #[test]
    fn edge_a_call_id_no_row_has_reads_nearly_nothing() -> TestResult {
        let query = ask(&[("call_id", "absent@example.com")])?;
        let decoded = decode(encode_grouped(&rows(40), 10)?, &query)?;
        assert!(
            decoded.rows.is_empty(),
            "edge no row has the Call-ID: {:?}",
            decoded.rows
        );
        assert!(
            decoded.groups_read < decoded.groups,
            "edge the filter rules out row groups: read {} of {}",
            decoded.groups_read,
            decoded.groups
        );
        Ok(())
    }

    #[test]
    fn edge_a_window_reads_only_the_row_groups_it_overlaps() -> TestResult {
        // Rows at seconds 1 to 40, ten to a group: 1-10, 11-20, 21-30, 31-40.
        let query = ask(&[
            ("from", "2026-11-11T00:00:12Z"),
            ("to", "2026-11-11T00:00:14Z"),
        ])?;
        let decoded = decode(encode_grouped(&rows(40), 10)?, &query)?;
        assert_eq!(
            decoded.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![12, 13],
            "edge the rows in the window"
        );
        assert_eq!(
            (decoded.groups, decoded.groups_read),
            (4, 1),
            "edge only the row group whose times overlap the window is read"
        );
        Ok(())
    }

    #[test]
    fn edge_a_window_edge_on_a_row_group_edge_reads_the_right_groups() -> TestResult {
        // from is the last row of group 1; to is the first row of group 3.
        let query = ask(&[
            ("from", "2026-11-11T00:00:10Z"),
            ("to", "2026-11-11T00:00:21Z"),
        ])?;
        let decoded = decode(encode_grouped(&rows(40), 10)?, &query)?;
        assert_eq!(
            decoded.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            (10..=20).collect::<Vec<u64>>(),
            "edge from is included and to is not"
        );
        assert_eq!(
            decoded.groups_read, 2,
            "edge a group that ends at from is read, a group that starts at to is not"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_without_a_call_id_reads_back() -> TestResult {
        let mut bare = row("edge-a", 0, 1);
        bare.call = serde_json::json!({"state": "failed"});
        assert_eq!(call_id_of(&bare), "", "edge no call_id is the empty text");
        let decoded = decode(encode(std::slice::from_ref(&bare))?, &Query::all())?;
        assert_eq!(decoded.rows, vec![bare], "edge the row reads back equal");
        Ok(())
    }

    #[test]
    fn edge_the_greatest_position_and_a_nanosecond_time_read_back() -> TestResult {
        let mut odd = row("edge-a", 0, u64::MAX);
        odd.received_at += chrono::TimeDelta::nanoseconds(123_456_789);
        odd.sent_at += chrono::TimeDelta::nanoseconds(1);
        let decoded = decode(encode(std::slice::from_ref(&odd))?, &Query::all())?;
        assert_eq!(
            decoded.rows,
            vec![odd],
            "edge u64::MAX and nanoseconds survive"
        );
        Ok(())
    }

    #[test]
    fn edge_a_large_call_with_other_scripts_reads_back() -> TestResult {
        let mut big = row("edge-a", 0, 1);
        big.call = serde_json::json!({
            "call_id": "größe-δοκιμή-呼叫@example.com",
            "display": "Zoë \u{1F4DE} \"quoted\" \\ back",
            "body": "v".repeat(300_000),
            "nested": {"list": [1, 2.5, null, true, {"k": "v"}]},
        });
        let query = ask(&[("call_id", "größe-δοκιμή-呼叫@example.com")])?;
        let decoded = decode(encode(std::slice::from_ref(&big))?, &query)?;
        assert_eq!(
            decoded.rows,
            vec![big],
            "edge a 300 kB call with other scripts"
        );
        Ok(())
    }

    #[test]
    fn edge_parquet_bytes_hold_the_numbers_in_clear_and_the_sealed_file_does_not() -> TestResult {
        let parquet = encode(&rows(3))?;
        let needle = b"+12025550101";
        let holds = |bytes: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            holds(&parquet),
            "edge Parquet itself is not encrypted: the number is in its bytes"
        );
        let sealed = seal(REL, &parquet, 1, CHUNK_BYTES)?;
        assert!(
            !holds(&sealed),
            "edge the sealed file holds no byte run of the number"
        );
        Ok(())
    }

    // ----- sealed files -----

    #[test]
    fn success_a_sealed_file_opens_at_its_path() -> TestResult {
        let parquet = encode(&rows(3))?;
        let sealed = seal(REL, &parquet, 1, CHUNK_BYTES)?;
        assert_eq!(
            unseal(REL, &sealed, &keys(1), Kind::Calls)?,
            parquet,
            "success the Parquet bytes come back"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_in_many_pieces_opens_whole() -> TestResult {
        let parquet = encode(&rows(50))?;
        let sealed = seal(REL, &parquet, 1, 100)?;
        assert!(
            sealed_lines(REL, &parquet, 100).len() > 10,
            "success the file is in many pieces"
        );
        assert_eq!(
            unseal(REL, &sealed, &keys(1), Kind::Calls)?,
            parquet,
            "success and the pieces join to the same bytes"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_under_an_old_key_opens() -> TestResult {
        let parquet = encode(&rows(3))?;
        let sealed = seal(REL, &parquet, 1, CHUNK_BYTES)?;
        let both = Keys::new(
            MasterKey::from_bytes([2; 32]),
            vec![MasterKey::from_bytes([1; 32])],
        );
        assert_eq!(
            unseal(REL, &sealed, &both, Kind::Calls)?,
            parquet,
            "success a file written under the earlier key opens after a key change"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_under_a_key_that_is_not_loaded_is_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(3))?, 1, CHUNK_BYTES)?;
        let got = unseal(REL, &sealed, &keys(2), Kind::Calls);
        assert!(
            got.as_ref().is_err_and(|e| e.starts_with(REL)
                && e.contains("sealed layer")
                && e.contains("not loaded")),
            "failure another key: the file, the layer and the key id are named: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_moved_to_another_path_is_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(3))?, 1, CHUNK_BYTES)?;
        let other = "calls/date=2026-11-11/member=edge-b/x.sealed";
        let got = unseal(other, &sealed, &keys(1), Kind::Calls);
        assert!(
            got.as_ref()
                .is_err_and(|e| e.starts_with(other) && e.contains("was written as")),
            "failure a file at another member's path does not open: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_changed_byte_anywhere_is_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(20))?, 1, 200)?;
        for at in [
            0,
            20,
            crate::app::fleet_seal::HEADER_BYTES + 10,
            sealed.len() / 2,
            sealed.len() - 1,
        ] {
            let mut bad = sealed.clone();
            bad[at] ^= 0x01;
            let got = unseal(REL, &bad, &keys(1), Kind::Calls);
            assert!(
                got.as_ref().is_err_and(|e| e.contains("sealed layer")),
                "failure byte {at} of {} changed: {got:?}",
                sealed.len()
            );
        }
        Ok(())
    }

    #[test]
    fn failure_a_cut_file_is_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(20))?, 1, 200)?;
        for keep in [
            0,
            10,
            crate::app::fleet_seal::HEADER_BYTES,
            sealed.len() / 2,
            sealed.len() - 1,
        ] {
            let got = unseal(REL, &sealed[..keep], &keys(1), Kind::Calls);
            assert!(
                got.as_ref().is_err_and(|e| e.contains("sealed layer")),
                "failure the first {keep} of {} bytes: {got:?}",
                sealed.len()
            );
        }
        Ok(())
    }

    #[test]
    fn failure_bytes_added_after_a_sealed_file_are_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(3))?, 1, CHUNK_BYTES)?;
        for extra in [vec![1u8], vec![1, 0, 0], vec![0u8; 40]] {
            let mut longer = sealed.clone();
            longer.extend(&extra);
            let got = unseal(REL, &longer, &keys(1), Kind::Calls);
            assert!(
                got.as_ref().is_err_and(|e| e.contains("sealed layer")),
                "failure {} byte(s) after the file's end: a calls file is written once and \
                 nothing follows it: {got:?}",
                extra.len()
            );
        }
        Ok(())
    }

    #[test]
    fn failure_a_sealed_file_of_another_kind_is_refused() -> TestResult {
        let (mut sealer, header) =
            LogSealer::new(&MasterKey::from_bytes([1; 32]), Kind::Intake, &system_draw)?;
        let mut intake = header.to_vec();
        intake.extend(sealer.record(REL.as_bytes())?);
        intake.extend(sealer.record(b"PAR1")?);
        intake.extend(sealer.base_end()?);
        let got = unseal(REL, &intake, &keys(1), Kind::Calls);
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("intake") && e.contains("calls")),
            "failure an intake file in a calls file's place: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_clear_parquet_file_in_the_store_is_refused() -> TestResult {
        let got = unseal(REL, &encode(&rows(3))?, &keys(1), Kind::Calls);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("not a sealed file")),
            "failure a Parquet file in clear is not read: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_sealed_file_with_no_records_is_refused() -> TestResult {
        let (mut sealer, header) =
            LogSealer::new(&MasterKey::from_bytes([1; 32]), Kind::Calls, &system_draw)?;
        let mut empty = header.to_vec();
        empty.extend(sealer.base_end()?);
        let got = unseal(REL, &empty, &keys(1), Kind::Calls);
        assert!(
            got.as_ref().is_err_and(|e| e.contains("holds no path")),
            "failure a calls file with nothing in it: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_file_whose_size_is_a_whole_number_of_pieces_opens() -> TestResult {
        let parquet = vec![7u8; 400];
        let lines = sealed_lines(REL, &parquet, 100);
        assert_eq!(lines.len(), 5, "edge the path and four whole pieces");
        assert!(
            lines[1..].iter().all(|l| l.len() == 100),
            "edge no empty last piece"
        );
        let sealed = seal(REL, &parquet, 1, 100)?;
        assert_eq!(
            unseal(REL, &sealed, &keys(1), Kind::Calls)?,
            parquet,
            "edge the bytes come back"
        );
        Ok(())
    }

    #[test]
    fn edge_pieces_are_never_larger_than_asked() {
        let parquet = vec![7u8; 1001];
        let lines = sealed_lines(REL, &parquet, 100);
        assert_eq!(
            lines[0],
            REL.as_bytes(),
            "edge the first record is the path"
        );
        assert_eq!(
            lines[1..].iter().map(Vec::len).collect::<Vec<_>>(),
            [vec![100usize; 10], vec![1]].concat(),
            "edge ten whole pieces and the rest"
        );
    }

    #[test]
    fn edge_a_file_of_more_than_one_whole_piece_seals_and_opens() -> TestResult {
        // One piece of the size the store writes, and one byte more.
        let parquet = vec![9u8; CHUNK_BYTES + 1];
        let sealed = seal(REL, &parquet, 1, CHUNK_BYTES)?;
        assert_eq!(
            unseal(REL, &sealed, &keys(1), Kind::Calls)?.len(),
            CHUNK_BYTES + 1,
            "edge a piece of the size the store writes fits one sealed record"
        );
        Ok(())
    }

    // ----- rows already filed, retention, the newest rows -----

    #[test]
    fn success_rows_a_file_holds_are_left_out() {
        let stored = rows(3);
        let got = without_stored(rows(5), &stored);
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![4, 5],
            "success rows 1 to 3 are in a file already"
        );
    }

    #[test]
    fn success_days_past_the_retention_are_expired() {
        let day = |d: u32| NaiveDate::from_ymd_opt(2026, 11, d).unwrap_or_default();
        let got = expired(&[day(1), day(7), day(8), day(9), day(11)], day(11), 3);
        assert_eq!(
            got,
            vec![day(1), day(7)],
            "success a day more than 3 days before today goes; the day 3 days back stays"
        );
    }

    #[test]
    fn success_the_newest_rows_come_first() {
        let (got, more) = newest(rows(5), 3);
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![5, 4, 3],
            "success the three newest, newest first"
        );
        assert!(more, "success and there were more");
    }

    #[test]
    fn failure_a_row_is_not_left_out_for_a_like_row_of_another_stream_or_time() {
        let mut other_stream = row("edge-a", 1000, 1);
        other_stream.stream = "t".to_string();
        let mut other_time = row("edge-a", 1000, 1);
        other_time.sent_at += chrono::TimeDelta::seconds(9);
        let got = without_stored(vec![row("edge-a", 1000, 1)], &[other_stream, other_time]);
        assert_eq!(
            got.len(),
            1,
            "failure the same position in another stream, or sent at another time, is another row"
        );
    }

    #[test]
    fn edge_nothing_stored_leaves_every_row() {
        assert_eq!(
            without_stored(rows(4), &[]).len(),
            4,
            "edge no file: every row is new"
        );
        assert!(
            without_stored(Vec::new(), &rows(4)).is_empty(),
            "edge no rows: nothing to file"
        );
    }

    #[test]
    fn edge_retention_keeps_today_and_days_ahead_of_the_clock() {
        let day = |d: u32| NaiveDate::from_ymd_opt(2026, 11, d).unwrap_or_default();
        assert!(
            expired(&[day(11), day(12), day(30)], day(11), 1).is_empty(),
            "edge today and days after it are kept"
        );
        assert_eq!(
            expired(&[day(9), day(10)], day(11), 1),
            vec![day(9)],
            "edge with one day of retention yesterday stays and the day before goes"
        );
        assert!(
            expired(&[], day(11), 1).is_empty(),
            "edge no days: nothing expires"
        );
    }

    #[test]
    fn edge_a_row_held_twice_is_returned_once() {
        let mut twice = rows(3);
        twice.extend(rows(3));
        let (got, more) = newest(twice, 10);
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "edge a row the intake and a file both hold is one row"
        );
        assert!(!more, "edge and nothing was cut");
    }

    #[test]
    fn edge_exactly_the_limit_is_not_more() {
        let (got, more) = newest(rows(3), 3);
        assert_eq!(got.len(), 3, "edge three rows for a limit of three");
        assert!(!more, "edge and no more");
        let (none, more) = newest(Vec::<IntakeRecord>::new(), 3);
        assert!(none.is_empty() && !more, "edge no rows: none, and no more");
    }

    #[test]
    fn edge_rows_received_at_one_instant_have_a_fixed_order() {
        let same = vec![
            row("edge-b", 1000, 1),
            row("edge-a", 1000, 2),
            row("edge-a", 1000, 1),
        ];
        let (got, _) = newest(same, 10);
        assert_eq!(
            got.iter()
                .map(|r| (r.member.as_str(), r.seq))
                .collect::<Vec<_>>(),
            vec![("edge-a", 2), ("edge-a", 1), ("edge-b", 1)],
            "edge one instant: by member, then the later position first"
        );
    }
}

/// The class of heartbeats, the bound on the files of one question, and
/// what a start reads to rebuild the registry.
#[cfg(test)]
mod members_tests {
    use super::*;
    use crate::app::fleet_calls::CallCounts;
    use crate::app::fleet_center::Cursor;
    use crate::app::fleet_seal::MasterKey;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    /// One day in milliseconds.
    const DAY: i64 = 86_400_000;

    /// Heartbeat `count` of `member`, received `ms` milliseconds into
    /// 2026-11-11.
    fn beat(member: &str, ms: i64, count: u64) -> MemberRecord {
        MemberRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            peer: "192.0.2.10".to_string(),
            heartbeats: count,
            cursor: Cursor {
                stream: "s".to_string(),
                seq: count * 2,
                sent_at: at_ms(ms - 250),
            },
            heartbeat_secs: 30,
            inventory: serde_json::json!({"host": "edge.example.com", "count": count}),
            call_records: count + 5,
            calls: Some(CallCounts {
                selected: count,
                dropped_by_cap: 1,
                left_out: 2,
                spooled: 3,
            }),
        }
    }

    /// Heartbeats `from` to `to` of `member`, one a second.
    fn beats(member: &str, from: u64, to: u64) -> Vec<MemberRecord> {
        (from..=to)
            .map(|n| beat(member, i64::try_from(n).unwrap_or(0) * 1000, n))
            .collect()
    }

    /// The call record at `seq` of `member`, received `ms` milliseconds
    /// into 2026-11-11.
    fn call(member: &str, ms: i64, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            stream: "s".to_string(),
            seq,
            sent_at: at_ms(ms - 250),
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": format!("call-{seq}@example.com")}),
        }
    }

    /// A history store in a new directory, under key 1.
    fn store() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let history = History::open(&dir.path().join("center.store"), keys(1))?;
        Ok((dir, history))
    }

    /// The question for every heartbeat of `member`.
    fn of(member: &str) -> Query {
        Query {
            member: Some(member.to_string()),
            ..Query::all()
        }
    }

    /// The counts of the heartbeats the store answers `query` with.
    fn counts(history: &History, query: &Query) -> Result<Vec<u64>, String> {
        let files = history.list(CLASS_MEMBERS, query)?;
        let answer = history.answer(query, &files, Vec::<MemberRecord>::new());
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}"));
        }
        Ok(answer.rows.iter().map(|r| r.heartbeats).collect())
    }

    /// Change one byte in the middle of the file at `rel`.
    fn change(history: &History, rel: &str) -> std::io::Result<()> {
        let path = history.dir().join(rel);
        let mut bytes = std::fs::read(&path)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)
    }

    /// The pairs of a query string.
    fn pairs(text: &[(&str, &str)]) -> Vec<(String, String)> {
        text.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn success_heartbeat_rows_read_back_equal() -> TestResult {
        let written = beats("edge-a", 1, 25);
        let decoded = decode::<MemberRecord>(encode_grouped(&written, 10)?, &Query::all())?;
        assert_eq!(
            decoded.rows, written,
            "success every field of a heartbeat row reads back as it was written"
        );
        assert_eq!(decoded.groups, 3, "success in three row groups of ten");
        Ok(())
    }

    #[test]
    fn success_heartbeats_are_filed_under_class_day_and_member() -> TestResult {
        let (_dir, history) = store()?;
        let filed = history.file_per_member(&beats("edge-a", 1, 3))?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (1, 3, 0),
            "success three heartbeats of one day and member make one file"
        );
        let listed = history.list(CLASS_MEMBERS, &Query::all())?;
        assert_eq!(
            listed.iter().map(|f| f.rel.as_str()).collect::<Vec<&str>>(),
            ["members/date=2026-11-11/member=edge-a/1794355201000-1794355203000-s-1.sealed"],
            "success under class members, the day and the member, named by its times, the \
             stream and the count of its first heartbeat"
        );
        assert!(
            history.list(CLASS_CALLS, &Query::all())?.is_empty(),
            "success and the class of call records lists none of it"
        );
        Ok(())
    }

    #[test]
    fn success_an_answer_joins_waiting_and_filed_heartbeats_newest_first() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&beats("edge-a", 1, 2))?;
        history.file_per_member(&beats("edge-b", 1, 2))?;
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        let waiting = [beats("edge-a", 3, 4), beats("edge-b", 3, 3)].concat();
        let answer = history.answer(&query, &files, waiting);
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [4, 3, 2, 1],
            "success the member's waiting and filed heartbeats, newest first, and no other's"
        );
        assert_eq!(
            (answer.files_read, answer.files_not_read, answer.more),
            (1, 0, false),
            "success from the member's one file"
        );
        Ok(())
    }

    #[test]
    fn success_a_window_selects_heartbeats_by_receive_time() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 5))?;
        let query = Query {
            from: Some(at_ms(2000)),
            to: Some(at_ms(4000)),
            ..of("edge-a")
        };
        assert_eq!(
            counts(&history, &query)?,
            [3, 2],
            "success from is included and to is not"
        );
        Ok(())
    }

    #[test]
    fn success_the_newest_heartbeat_of_each_member_is_found() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 3))?;
        history.file(&beats("edge-a", 4, 6))?;
        history.file(&beats("edge-b", 1, 2))?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 4096)?;
        assert_eq!(
            found.members,
            vec![beat("edge-a", 6000, 6), beat("edge-b", 2000, 2)],
            "success the last heartbeat of each member, whole"
        );
        assert_eq!(
            (found.files_read, found.refused.len()),
            (3, 0),
            "success with no member named, from every file of the kept days"
        );
        Ok(())
    }

    #[test]
    fn success_heartbeat_days_before_the_oldest_kept_are_removed_and_no_other() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 0, 1), beat("edge-a", DAY, 2)])?;
        history.file(&[call("edge-a", 0, 1)])?;
        let expired = history.expire_before(CLASS_MEMBERS, at_ms(DAY).date_naive())?;
        assert_eq!(
            (expired.days, expired.files, expired.left.len()),
            (1, 1, 0),
            "success the one day of heartbeats before the oldest kept is removed"
        );
        assert_eq!(
            counts(&history, &of("edge-a"))?,
            [2],
            "success the heartbeat of the kept day stays"
        );
        assert_eq!(
            history.list(CLASS_CALLS, &Query::all())?.len(),
            1,
            "success and the call records of the removed day stay: they have their own retention"
        );
        Ok(())
    }

    #[test]
    fn success_the_oldest_kept_day_is_the_day_of_the_oldest_kept_instant() {
        let now = at_ms(3 * DAY + 3_600_000);
        assert_eq!(
            oldest_kept_at(now, chrono::Duration::hours(72)),
            at_ms(0).date_naive(),
            "success 72 hours before 01:00 on the 14th is on the 11th, so the 11th is kept"
        );
        assert_eq!(
            oldest_kept_at(now, chrono::Duration::hours(1)),
            at_ms(3 * DAY).date_naive(),
            "success one hour before 01:00 is the same day"
        );
    }

    #[test]
    fn success_the_question_of_the_history_route_is_read() -> TestResult {
        let query = Query::parse_heartbeats(
            "edge-a",
            &pairs(&[
                ("from", "2026-11-11T00:00:00Z"),
                ("to", "2026-11-12T00:00:00Z"),
                ("limit", "7"),
            ]),
        )?;
        assert_eq!(
            query,
            Query {
                member: Some("edge-a".to_string()),
                from: Some(at_ms(0)),
                to: Some(at_ms(DAY)),
                call_id: None,
                limit: 7,
            },
            "success the member of the path and every parameter"
        );
        assert_eq!(
            Query::parse_heartbeats("edge-a", &[])?.limit,
            DEFAULT_LIMIT,
            "success and no parameter asks for the newest rows"
        );
        Ok(())
    }

    #[test]
    fn success_call_records_since_an_instant_come_oldest_first() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[call("edge-a", 1000, 1), call("edge-a", 2000, 2)])?;
        history.file(&[call("edge-a", 3000, 3)])?;
        history.file(&[call("edge-b", 3000, 9)])?;
        let since = BTreeMap::from([("edge-a".to_string(), at_ms(2000))]);
        let found = history.calls_after(&since, 4096)?;
        assert_eq!(
            found.rows.iter().map(|r| r.seq).collect::<Vec<u64>>(),
            [2, 3],
            "success the member's call records received at the instant or later, oldest first"
        );
        assert!(found.refused.is_empty(), "success and every file opened");
        Ok(())
    }

    #[test]
    fn failure_a_heartbeat_file_moved_into_the_class_of_calls_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 2))?;
        let from = history.list(CLASS_MEMBERS, &Query::all())?[0].rel.clone();
        let to = from.replacen(CLASS_MEMBERS, CLASS_CALLS, 1);
        let target = history.dir().join(&to);
        std::fs::create_dir_all(target.parent().ok_or("a parent")?)?;
        std::fs::rename(history.dir().join(&from), &target)?;
        let got = history.read::<IntakeRecord>(&to, &Query::all());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("sealed layer") && e.contains("members")),
            "failure a heartbeat file under calls is refused by its kind: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_of_call_records_is_not_read_as_heartbeats() -> TestResult {
        let rel = "members/date=2026-11-11/member=edge-a/x.sealed";
        let got = decode::<MemberRecord>(encode(&[call("edge-a", 0, 1)])?, &Query::all());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("not the heartbeat schema")),
            "failure Parquet of another class is refused by its schema: {got:?}"
        );
        let got = decode::<IntakeRecord>(encode(&beats("edge-a", 1, 1))?, &Query::all());
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("not the call record schema")),
            "failure and so are heartbeats read as call records: {got:?} ({rel})"
        );
        Ok(())
    }

    #[test]
    fn failure_a_heartbeat_received_before_1970_is_refused_as_a_heartbeat() {
        let mut early = beat("edge-a", 0, 1);
        early.received_at = DateTime::<Utc>::UNIX_EPOCH - chrono::TimeDelta::seconds(1);
        let got = encode(&[early]);
        assert!(
            got.as_ref().is_err_and(
                |e| e.contains("a heartbeat of member 'edge-a'") && e.contains("before 1970")
            ),
            "failure the refusal says what the row is and whose: {got:?}"
        );
    }

    #[test]
    fn failure_the_reason_a_heartbeat_file_is_refused_for_does_not_repeat_its_path() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 2))?;
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        change(&history, &files[0].rel)?;
        let answer = history.answer(&query, &files, Vec::<MemberRecord>::new());
        assert_eq!(
            answer.refused.len(),
            1,
            "failure the changed file is refused"
        );
        let (file, reason) = &answer.refused[0];
        assert_eq!(*file, files[0].rel, "failure and named by its path");
        assert!(
            reason.starts_with("sealed layer: ") && !reason.contains(file.as_str()),
            "failure the reason starts at the layer and holds no second copy of the path: \
             {reason}"
        );
        assert_eq!(
            answer.json_as("heartbeats", |_| serde_json::Value::Null)["complete"],
            false,
            "failure and the answer is not whole"
        );
        Ok(())
    }

    #[test]
    fn failure_the_reason_a_calls_file_is_refused_for_does_not_repeat_its_path() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[call("edge-a", 0, 1)])?;
        let files = history.list(CLASS_CALLS, &Query::all())?;
        change(&history, &files[0].rel)?;
        let answer = history.answer(&Query::all(), &files, Vec::<IntakeRecord>::new());
        let json = answer.json();
        assert_eq!(
            json["refused"][0]["file"], files[0].rel,
            "failure the file field holds the path"
        );
        assert!(
            json["refused"][0]["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("sealed layer: ") && !r.contains("calls/date=")),
            "failure and the reason does not hold it again: {json}"
        );
        let read = history.read::<IntakeRecord>(&files[0].rel, &Query::all());
        assert!(
            read.as_ref().is_err_and(|e| e.starts_with(&files[0].rel)),
            "failure a read on its own still names the file, for a log line: {read:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_question_past_the_file_bound_is_answered_in_part_and_says_so() -> TestResult {
        let (_dir, history) = store()?;
        for n in 1..=5 {
            history.file(&beats("edge-a", n, n))?;
        }
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        assert_eq!(files.len(), 5, "failure five files answer the question");
        let answer = history.answer_within(&query, &files, Vec::<MemberRecord>::new(), 3);
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [5, 4, 3],
            "failure the rows of the three files with the latest rows are answered"
        );
        assert_eq!(
            (answer.files_read, answer.files_not_read),
            (3, 2),
            "failure three files were opened and two were not"
        );
        let json = answer.json_as("heartbeats", |r| serde_json::json!(r.heartbeats));
        assert_eq!(
            (&json["complete"], &json["files_not_read"]),
            (&serde_json::json!(false), &serde_json::json!(2)),
            "failure the answer says it is not whole and how many files it left: {json}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_newest_file_that_does_not_open_is_reported_and_restores_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 2))?;
        history.file(&beats("edge-b", 1, 2))?;
        let bad = history.list(CLASS_MEMBERS, &of("edge-a"))?[0].rel.clone();
        change(&history, &bad)?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 4096)?;
        assert_eq!(
            found.members,
            vec![beat("edge-b", 2000, 2)],
            "failure the member whose file opens is found, the other is not made up"
        );
        assert_eq!(
            found.refused.len(),
            1,
            "failure the changed file is reported"
        );
        assert!(
            found.refused[0].0 == bad && found.refused[0].1.starts_with("sealed layer"),
            "failure by its path, with the layer's reason: {:?}",
            found.refused
        );
        Ok(())
    }

    #[test]
    fn failure_the_history_route_takes_no_call_id_and_no_member_parameter() {
        for (name, value) in [
            ("call_id", "a@example.com"),
            ("member", "edge-b"),
            ("day", "1"),
        ] {
            let got = Query::parse_heartbeats("edge-a", &pairs(&[(name, value)]));
            assert!(
                got.as_ref()
                    .is_err_and(|e| e.contains(name) && e.contains("it takes from, to and limit")),
                "failure {name} is refused by name with what the route takes: {got:?}"
            );
        }
    }

    #[test]
    fn failure_the_history_route_refuses_an_id_no_member_has() {
        for id in ["", "edge a", "a/b", &"m".repeat(65)] {
            let got = Query::parse_heartbeats(id, &[]);
            assert!(
                got.as_ref()
                    .is_err_and(|e| e.starts_with("member must be 1 to 64")),
                "failure the id {id:?} is refused: {got:?}"
            );
        }
    }

    #[test]
    fn failure_the_history_route_refuses_values_outside_their_range() {
        for (name, value, says) in [
            ("limit", "0", "limit must be a number from 1 to 1000"),
            ("limit", "1001", "limit must be a number from 1 to 1000"),
            ("from", "noon", "from must be an RFC 3339 time"),
            ("to", "", "to must be an RFC 3339 time"),
        ] {
            let got = Query::parse_heartbeats("edge-a", &pairs(&[(name, value)]));
            assert_eq!(
                got.as_ref().err().map(|e| e.starts_with(says)),
                Some(true),
                "failure {name}={value} is refused as the calls route refuses it: {got:?}"
            );
        }
        let twice = Query::parse_heartbeats("edge-a", &pairs(&[("limit", "1"), ("limit", "2")]));
        assert!(
            twice.as_ref().is_err_and(|e| e.contains("given twice")),
            "failure a parameter given twice is refused: {twice:?}"
        );
    }

    #[test]
    fn failure_heartbeats_under_another_key_are_not_restored() -> TestResult {
        let (dir, history) = store()?;
        history.file(&beats("edge-a", 1, 1))?;
        let other = History::reader(&dir.path().join("center.store"), keys(2));
        let found = other.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 4096)?;
        assert!(
            found.members.is_empty() && found.refused.len() == 1,
            "failure a file whose key is not loaded restores no member and is reported: \
             {found:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_filing_the_same_heartbeats_again_writes_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 3))?;
        let again = history.file(&beats("edge-a", 1, 3))?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (0, 0, 3),
            "edge every row was in a file already"
        );
        let more = history.file(&beats("edge-a", 2, 5))?;
        assert_eq!(
            (more.files, more.rows, more.already),
            (1, 2, 2),
            "edge and only the rows no file holds are filed"
        );
        assert_eq!(
            counts(&history, &of("edge-a"))?,
            [5, 4, 3, 2, 1],
            "edge no heartbeat is answered twice"
        );
        Ok(())
    }

    #[test]
    fn edge_a_row_given_twice_in_one_filing_is_filed_once() -> TestResult {
        let (_dir, history) = store()?;
        let mut moved = beat("edge-a", 2000, 2);
        moved.cursor.seq = 40;
        let filed = history.file(&[beat("edge-a", 1000, 1), beat("edge-a", 2000, 2), moved])?;
        assert_eq!(
            (filed.rows, filed.already),
            (2, 1),
            "edge the second row of one identity is left out and counted"
        );
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        let answer = history.answer(&query, &files, Vec::<MemberRecord>::new());
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| (r.heartbeats, r.cursor.seq))
                .collect::<Vec<_>>(),
            vec![(2, 4), (1, 2)],
            "edge the file holds the first row given of each identity"
        );
        Ok(())
    }

    #[test]
    fn edge_a_record_moved_by_a_call_is_the_row_of_its_heartbeat() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 1))?;
        // What the registry holds once a call record followed the
        // heartbeat: the same count and receive time, a later position.
        let mut moved = beat("edge-a", 1000, 1);
        moved.cursor.seq = 40;
        moved.cursor.stream = "t".to_string();
        moved.call_records += 1;
        let again = history.file(&[moved])?;
        assert_eq!(
            (again.files, again.already),
            (0, 1),
            "edge a record of the same count and receive time is the heartbeat a file holds"
        );
        Ok(())
    }

    #[test]
    fn edge_heartbeats_of_one_request_are_rows_of_their_own() -> TestResult {
        let (_dir, history) = store()?;
        let batch: Vec<MemberRecord> = (1..=3).map(|n| beat("edge-a", 1000, n)).collect();
        let filed = history.file(&batch)?;
        assert_eq!(
            (filed.rows, filed.already),
            (3, 0),
            "edge three heartbeats received at one instant are three rows"
        );
        assert_eq!(
            counts(&history, &of("edge-a"))?,
            [3, 2, 1],
            "edge answered with the later count first"
        );
        Ok(())
    }

    #[test]
    fn edge_exactly_the_file_bound_is_a_whole_answer() -> TestResult {
        let (_dir, history) = store()?;
        for n in 1..=3 {
            history.file(&beats("edge-a", n, n))?;
        }
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        let answer = history.answer_within(&query, &files, Vec::<MemberRecord>::new(), 3);
        assert_eq!(
            (answer.rows.len(), answer.files_read, answer.files_not_read),
            (3, 3, 0),
            "edge a question that rules in as many files as the bound is read whole"
        );
        assert_eq!(
            answer.json_as("heartbeats", |_| serde_json::Value::Null)["complete"],
            true,
            "edge and says so"
        );
        Ok(())
    }

    #[test]
    fn edge_a_file_that_is_refused_counts_toward_the_bound() -> TestResult {
        let (_dir, history) = store()?;
        for n in 1..=3 {
            history.file(&beats("edge-a", n, n))?;
        }
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        change(&history, &files[0].rel)?;
        let answer = history.answer_within(&query, &files, Vec::<MemberRecord>::new(), 2);
        assert_eq!(
            (
                answer.refused.len(),
                answer.files_read,
                answer.files_not_read
            ),
            (1, 1, 1),
            "edge the bound is on the files opened, read or refused"
        );
        Ok(())
    }

    #[test]
    fn edge_a_limit_met_before_the_bound_leaves_no_file_unread() -> TestResult {
        let (_dir, history) = store()?;
        for n in 1..=6 {
            history.file(&beats("edge-a", n, n))?;
        }
        let query = Query {
            limit: 1,
            ..of("edge-a")
        };
        let files = history.list(CLASS_MEMBERS, &query)?;
        let answer = history.answer_within(&query, &files, Vec::<MemberRecord>::new(), 4);
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [6],
            "edge the newest row is answered"
        );
        assert_eq!(
            (answer.files_not_read, answer.more),
            (0, true),
            "edge files the limit made unneeded are not counted as left unread"
        );
        Ok(())
    }

    #[test]
    fn edge_a_bound_of_no_files_answers_from_the_waiting_rows_alone() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 1))?;
        let query = of("edge-a");
        let files = history.list(CLASS_MEMBERS, &query)?;
        let answer = history.answer_within(&query, &files, beats("edge-a", 2, 2), 0);
        assert_eq!(
            (answer.rows.len(), answer.files_read, answer.files_not_read),
            (1, 0, 1),
            "edge the waiting row is answered and the file is counted as not read"
        );
        Ok(())
    }

    #[test]
    fn edge_a_heartbeat_without_call_counts_reads_back_without_them() -> TestResult {
        let mut bare = beat("edge-a", 0, 1);
        bare.calls = None;
        bare.inventory = serde_json::json!({});
        bare.peer = String::new();
        bare.heartbeats = u64::MAX;
        bare.cursor.seq = u64::MAX;
        bare.call_records = u64::MAX;
        bare.heartbeat_secs = 3600;
        let decoded = decode::<MemberRecord>(encode(std::slice::from_ref(&bare))?, &Query::all())?;
        assert_eq!(
            decoded.rows,
            vec![bare],
            "edge no call counts, an empty inventory and the largest counts read back equal"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_the_caller_holds_newer_is_not_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&beats("edge-a", 1, 3))?;
        history.file(&beats("edge-b", 1, 3))?;
        let known: BTreeMap<String, DateTime<Utc>> = [
            ("edge-a".to_string(), at_ms(3000)),
            ("edge-b".to_string(), at_ms(2999)),
        ]
        .into();
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &known, 4096)?;
        assert_eq!(
            found.members,
            vec![beat("edge-b", 3000, 3)],
            "edge only the member of whom a file holds a later heartbeat than the caller has"
        );
        assert_eq!(
            found.files_read, 2,
            "edge both files end at the newest instant the caller holds and may hold a later row"
        );
        Ok(())
    }

    #[test]
    fn edge_heartbeats_in_days_before_the_oldest_are_not_restored() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 0, 1)])?;
        history.file(&[beat("edge-b", DAY, 1)])?;
        let found = history.newest_heartbeats(at_ms(DAY).date_naive(), &BTreeMap::new(), 4096)?;
        assert_eq!(
            found
                .members
                .iter()
                .map(|r| r.member.as_str())
                .collect::<Vec<&str>>(),
            ["edge-b"],
            "edge a member last heard in a day before the oldest is left out"
        );
        assert_eq!(found.files_read, 1, "edge and its file is not opened");
        Ok(())
    }

    #[test]
    fn edge_the_newest_heartbeat_is_taken_across_days_and_files() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", DAY + 5, 9)])?;
        history.file(&[beat("edge-a", 0, 1), beat("edge-a", 10, 2)])?;
        history.file(&[beat("edge-a", DAY, 7), beat("edge-a", DAY + 1, 8)])?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 4096)?;
        assert_eq!(
            found
                .members
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [9],
            "edge the heartbeat received last, whatever order the files were written in"
        );
        Ok(())
    }

    #[test]
    fn edge_the_last_instant_of_a_day_keeps_that_day() {
        let midnight = at_ms(DAY);
        assert_eq!(
            oldest_kept_at(midnight, chrono::Duration::nanoseconds(1)),
            at_ms(0).date_naive(),
            "edge one nanosecond before midnight is the day before"
        );
        assert_eq!(
            oldest_kept_at(midnight, chrono::Duration::zero()),
            at_ms(DAY).date_naive(),
            "edge and midnight is the new day"
        );
    }

    #[test]
    fn edge_a_retention_past_the_calendar_keeps_every_day() {
        assert_eq!(
            oldest_kept_at(at_ms(0), chrono::Duration::MAX),
            NaiveDate::MIN,
            "edge a span chrono cannot subtract keeps every day"
        );
    }

    #[test]
    fn edge_no_call_records_since_an_instant_is_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[call("edge-a", 1000, 1)])?;
        let after = |ms: i64| {
            history.calls_after(&BTreeMap::from([("edge-a".to_string(), at_ms(ms))]), 4096)
        };
        let found = after(1001)?;
        assert!(
            found.rows.is_empty() && found.refused.is_empty(),
            "edge a call record received before the instant is not returned"
        );
        assert_eq!(
            after(1000)?.rows.len(),
            1,
            "edge and one received at the instant is"
        );
        Ok(())
    }

    /// What one filing of a fleet's heartbeats and one rebuild of its
    /// registry cost, for 300 members with one heartbeat each: one file
    /// for all of them. A run with 2,000 is in the pull request that
    /// added the class.
    #[test]
    fn edge_filing_and_rebuilding_for_a_fleet_are_measured() -> TestResult {
        const MEMBERS: usize = 300;
        let (_dir, history) = store()?;
        let rows: Vec<MemberRecord> = (0..MEMBERS)
            .map(|n| beat(&format!("edge-{n:04}"), 1000, 1))
            .collect();
        let started = std::time::Instant::now();
        let filed = history.file(&rows)?;
        let wrote = started.elapsed();
        assert_eq!(
            (filed.files, filed.rows),
            (1, MEMBERS),
            "edge one file for the filing, whatever the members"
        );
        let mut bytes = 0;
        for file in history.list(CLASS_MEMBERS, &Query::all())? {
            bytes += std::fs::metadata(history.dir().join(&file.rel))?.len();
        }
        let started = std::time::Instant::now();
        let again = history.file(&rows)?;
        let checked = started.elapsed();
        assert_eq!(
            (again.files, again.already),
            (0, MEMBERS),
            "edge a second filing reads each file and writes none"
        );
        let started = std::time::Instant::now();
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 4096)?;
        let rebuilt = started.elapsed();
        assert_eq!(
            (found.members.len(), found.files_read),
            (MEMBERS, 1),
            "edge every member is found from the one file"
        );
        let known: BTreeMap<String, DateTime<Utc>> = rows
            .iter()
            .map(|r| (r.member.clone(), r.received_at))
            .collect();
        let started = std::time::Instant::now();
        let none = history.newest_heartbeats(at_ms(0).date_naive(), &known, 4096)?;
        let listed = started.elapsed();
        assert_eq!(
            (none.members.len(), none.files_read),
            (0, 1),
            "edge a registry that holds every member takes nothing; the file that ends in the \
             millisecond of its newest heartbeat is opened, since a name holds no finer time"
        );
        stderr_line!(
            "fleet heartbeat measurement: {MEMBERS} members, one row each, one file: {bytes} B, \
             write {wrote:?}, file again (the file read, none written) {checked:?}, rebuild \
             from history (the file read) {rebuilt:?}, rebuild check by path alone {listed:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_staged_heartbeat_file_from_a_stopped_write_is_removed_at_open() -> TestResult {
        let (dir, history) = store()?;
        history.file_per_member(&beats("edge-a", 1, 1))?;
        let member = history.dir().join("members/date=2026-11-11/member=edge-a");
        std::fs::write(member.join(".x.sealed.partial"), b"half")?;
        let again = History::open(&dir.path().join("center.store"), keys(1))?;
        assert!(
            !member.join(".x.sealed.partial").exists(),
            "edge the staged file is removed"
        );
        assert_eq!(
            counts(&again, &of("edge-a"))?,
            [1],
            "edge and the filed heartbeat stays"
        );
        Ok(())
    }
}

/// The codec of the history files: every file this build writes is
/// compressed with zstd, the files that releases 0.5.249 to 0.5.253 wrote
/// without a codec are read in place, and a file in any other codec is
/// refused with the codec named.
#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::app::fleet_calls::CallCounts;
    use crate::app::fleet_center::Cursor;
    use crate::app::fleet_seal::MasterKey;
    use parquet::basic::Compression;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    /// One day in milliseconds.
    const DAY: i64 = 86_400_000;

    /// The id of member `n` of a fleet.
    fn id(n: usize) -> String {
        format!("edge-{n:04}")
    }

    /// The call record at `seq` of `member`, received `ms` milliseconds into
    /// 2026-11-11, with the fields of a call a member pushes.
    fn call(member: &str, ms: i64, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            stream: "s".to_string(),
            seq,
            sent_at: at_ms(ms - 250),
            selected_by: "failed".to_string(),
            call: serde_json::json!({
                "schema_version": 1,
                "call_id": format!("call-{member}-{seq}@example.com"),
                "from": "sip:+12025550101@example.com",
                "to": "sip:+12025550102@example.com",
                "state": "Failed",
                "final_status_code": 486,
                "final_status_reason": "Busy Here",
                "method": "INVITE",
                "msg_count": 4 + seq % 9,
                "timing": {"pdd_ms": 800 + seq % 1000, "setup_ms": null, "retransmits": seq % 3},
                "sdp_timeline": [{
                    "timestamp": "2026-11-11T00:00:00Z",
                    "direction": "offer",
                    "codecs": ["PCMU", "PCMA", "telephone-event"],
                    "media_addr": "192.0.2.1",
                    "media_port": 10_000 + seq % 5000,
                    "mode": "sendrecv",
                }],
                "diagnosis": {
                    "one_way_audio": false,
                    "nat_mismatch": false,
                    "no_media": false,
                    "private_media_address": false,
                    "hints": [],
                },
                "streams": [],
                "capture_identity": {
                    "node": member,
                    "instance": "117b0818df1033d4fd2a28-2",
                    "dialog_generation": seq,
                    "stream_generation": 2,
                },
            }),
        }
    }

    /// `each` call records of each of `members` members, a second apart.
    fn calls(members: usize, each: u64) -> Vec<IntakeRecord> {
        let mut out = Vec::new();
        for n in 0..members {
            for seq in 1..=each {
                let ms =
                    i64::try_from(seq).unwrap_or(0) * 1000 + i64::try_from(n % 1000).unwrap_or(0);
                out.push(call(&id(n), ms, seq));
            }
        }
        out
    }

    /// Heartbeat `count` of `member`, received `ms` milliseconds into
    /// 2026-11-11, with an inventory of a few of the fields a member sends.
    fn beat(member: &str, ms: i64, count: u64) -> MemberRecord {
        MemberRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            peer: "192.0.2.10".to_string(),
            heartbeats: count,
            cursor: Cursor {
                stream: "s".to_string(),
                seq: count,
                sent_at: at_ms(ms - 250),
            },
            heartbeat_secs: 60,
            inventory: serde_json::json!({
                "schema_version": 1,
                "node_name": member,
                "build": {
                    "version": "0.5.253",
                    "target": "x86_64-unknown-linux-gnu",
                    "features": ["api", "archive", "audio", "hep", "metrics", "native", "tls"],
                },
                "config": {"recorded": true, "source": "/etc/sipnab/sipnab.toml"},
                "process": {"pid": 4000 + count, "uptime_seconds": count * 60},
                "counters": {"capture_packets_total": count * 7919, "capture_sources_refused_total": 0},
            }),
            call_records: count,
            calls: Some(CallCounts {
                selected: count,
                dropped_by_cap: 0,
                left_out: 0,
                spooled: 0,
            }),
        }
    }

    /// One heartbeat of each of `members` members, heartbeat `count`.
    fn beats(members: usize, ms: i64, count: u64) -> Vec<MemberRecord> {
        (0..members)
            .map(|n| beat(&id(n), ms + i64::try_from(n % 1000).unwrap_or(0), count))
            .collect()
    }

    /// `len` characters that no codec makes much smaller: 64 symbols drawn by
    /// a fixed generator from `seed`.
    fn noise(seed: u64, len: usize) -> String {
        const SYMBOLS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                char::from(SYMBOLS[usize::try_from(state >> 58).unwrap_or(0)])
            })
            .collect()
    }

    /// `count` call records of `edge-a` whose call holds `len` characters of
    /// noise.
    fn noisy(count: u64, len: usize) -> Vec<IntakeRecord> {
        (1..=count)
            .map(|seq| {
                let mut row = call("edge-a", i64::try_from(seq).unwrap_or(0), seq);
                row.call = serde_json::json!({
                    "call_id": format!("call-{seq}@example.com"),
                    "noise": noise(seq, len),
                });
                row
            })
            .collect()
    }

    /// A history store in a new directory, under key 1.
    fn store() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let history = History::open(&dir.path().join("center.store"), keys(1))?;
        Ok((dir, history))
    }

    /// The question for every row of `member`.
    fn of(member: &str) -> Query {
        Query {
            member: Some(member.to_string()),
            ..Query::all()
        }
    }

    /// The question for every row there is, up to the most one answer holds.
    fn every() -> Query {
        Query {
            limit: MAX_LIMIT,
            ..Query::all()
        }
    }

    /// The answer of the store to `query` with no row waiting; a file that
    /// was refused is an error.
    fn ask<R: Row>(history: &History, query: &Query) -> Result<Answer<R>, String> {
        let answer = history.answer(query, &history.list(R::CLASS, query)?, Vec::<R>::new());
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}"));
        }
        Ok(answer)
    }

    /// The codec of every column chunk of the Parquet file `bytes`, row group
    /// by row group.
    fn codecs_of(bytes: &[u8]) -> Result<Vec<Compression>, Box<dyn std::error::Error>> {
        use parquet::file::reader::FileReader as _;
        use parquet::file::serialized_reader::SerializedFileReader;
        let reader = SerializedFileReader::new(bytes::Bytes::from(bytes.to_vec()))?;
        Ok(reader
            .metadata()
            .row_groups()
            .iter()
            .flat_map(|group| group.columns().iter().map(|column| column.compression()))
            .collect())
    }

    /// The rows each row group of the Parquet file `bytes` holds.
    fn group_rows_of(bytes: &[u8]) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
        use parquet::file::reader::FileReader as _;
        use parquet::file::serialized_reader::SerializedFileReader;
        let reader = SerializedFileReader::new(bytes::Bytes::from(bytes.to_vec()))?;
        Ok(reader
            .metadata()
            .row_groups()
            .iter()
            .map(parquet::file::metadata::RowGroupMetaData::num_rows)
            .collect())
    }

    /// The Parquet file `file` with a footer that names `codec` for every
    /// column chunk: the pages stay as they are. A file another writer made in
    /// `codec` has such a footer; this build links one codec and cannot write
    /// the others.
    fn marked(file: &[u8], codec: Compression) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        marked_from(file, 0, codec)
    }

    /// [`marked`] for the row groups from `first` on; the footer names the
    /// file's own codec for the row groups before it.
    fn marked_from(
        file: &[u8],
        first: usize,
        codec: Compression,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use parquet::file::metadata::ParquetMetaDataWriter;
        use parquet::file::reader::FileReader as _;
        use parquet::file::serialized_reader::SerializedFileReader;
        let reader = SerializedFileReader::new(bytes::Bytes::from(file.to_vec()))?;
        let metadata = reader.metadata().clone();
        let tail = file
            .len()
            .checked_sub(8)
            .ok_or("a file shorter than its trailer")?;
        let footer = usize::try_from(u32::from_le_bytes(file[tail..tail + 4].try_into()?))?;
        let body = tail
            .checked_sub(footer)
            .ok_or("a footer longer than the file")?;
        let mut groups = Vec::new();
        for (index, group) in metadata.row_groups().iter().enumerate() {
            let mut columns = Vec::new();
            for column in group.columns() {
                let named = if index < first {
                    column.compression()
                } else {
                    codec
                };
                columns.push(
                    column
                        .clone()
                        .into_builder()
                        .set_compression(named)
                        .build()?,
                );
            }
            groups.push(
                group
                    .clone()
                    .into_builder()
                    .set_column_metadata(columns)
                    .build()?,
            );
        }
        let metadata = metadata.into_builder().set_row_groups(groups).build();
        let mut out = file[..body].to_vec();
        ParquetMetaDataWriter::new(&mut out, &metadata).finish()?;
        Ok(out)
    }

    /// The Parquet bytes of the one file of class `R` in `history`.
    fn only_file<R: Row>(history: &History) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let listed = history.list(R::CLASS, &Query::all())?;
        let [file] = listed.as_slice() else {
            return Err(format!("{} files, not one", listed.len()).into());
        };
        let sealed = std::fs::read(history.dir().join(&file.rel))?;
        Ok(unseal(&file.rel, &sealed, &history.keys, R::KIND)?)
    }

    /// The bytes of every file of `class` in `history`, as the disk holds them.
    fn disk_bytes(history: &History, class: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let mut bytes = 0;
        for file in history.list(class, &Query::all())? {
            bytes += std::fs::metadata(history.dir().join(&file.rel))?.len();
        }
        Ok(bytes)
    }

    /// `rows` in file order, for a comparison with what a file gave.
    fn in_order<R: Row>(rows: &[R]) -> Vec<R> {
        sorted(rows.to_vec())
    }

    /// The refusal of the file `bytes` of call records, or an error when it
    /// was read.
    fn refusal(bytes: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        match decode::<IntakeRecord>(bytes, &Query::all()) {
            Ok(read) => {
                Err(format!("read {} rows of a file that is refused", read.rows.len()).into())
            }
            Err(why) => Ok(why),
        }
    }

    /// A file of five call records without a codec, with a footer that names
    /// `codec`, and what the reader says of it.
    fn refusal_in(codec: Compression) -> Result<String, Box<dyn std::error::Error>> {
        refusal(marked(&encode_uncompressed(&calls(1, 5))?, codec)?)
    }

    // ----- success -----

    #[test]
    fn success_the_codec_is_zstd_at_level_1() -> TestResult {
        let level = parquet::basic::ZstdLevel::try_new(1)?;
        assert_eq!(
            (codec()?, ZSTD_LEVEL),
            (Compression::ZSTD(level), 1),
            "success a history file is written with zstd at level 1"
        );
        Ok(())
    }

    #[test]
    fn success_every_column_of_a_calls_file_is_zstd() -> TestResult {
        let codecs = codecs_of(&encode(&calls(1, 5))?)?;
        assert_eq!(
            codecs,
            vec![codec()?; 8],
            "success the eight columns of a call record file are zstd"
        );
        Ok(())
    }

    #[test]
    fn success_every_column_of_a_heartbeat_file_is_zstd() -> TestResult {
        let codecs = codecs_of(&encode(&beats(5, 0, 1))?)?;
        assert_eq!(
            codecs,
            vec![codec()?; 11],
            "success the eleven columns of a heartbeat file are zstd"
        );
        Ok(())
    }

    #[test]
    fn success_every_row_group_of_a_file_is_zstd() -> TestResult {
        let file = encode_grouped(&calls(1, 10), 3)?;
        assert_eq!(
            (group_rows_of(&file)?, codecs_of(&file)?),
            (vec![3, 3, 3, 1], vec![codec()?; 32]),
            "success each of four row groups has its eight columns in zstd"
        );
        Ok(())
    }

    #[test]
    fn success_call_records_read_back_from_a_compressed_file() -> TestResult {
        let rows = in_order(&calls(3, 40));
        let read = decode::<IntakeRecord>(encode(&rows)?, &every())?;
        assert_eq!(
            read.rows, rows,
            "success every call record reads back as it was filed"
        );
        Ok(())
    }

    #[test]
    fn success_heartbeats_read_back_from_a_compressed_file() -> TestResult {
        let rows = in_order(&beats(300, 0, 7));
        let read = decode::<MemberRecord>(encode(&rows)?, &every())?;
        assert_eq!(
            read.rows, rows,
            "success every heartbeat reads back as it was filed"
        );
        Ok(())
    }

    #[test]
    fn success_a_compressed_calls_file_is_under_a_third_of_a_plain_one() -> TestResult {
        let rows = in_order(&calls(200, 10));
        let (zstd, plain) = (encode(&rows)?.len(), encode_uncompressed(&rows)?.len());
        assert!(
            zstd * 3 < plain,
            "success 2,000 call records are {zstd} B with zstd, under a third of {plain} B"
        );
        Ok(())
    }

    #[test]
    fn success_a_compressed_heartbeat_file_is_under_a_third_of_a_plain_one() -> TestResult {
        let rows = in_order(&beats(2000, 0, 9));
        let (zstd, plain) = (encode(&rows)?.len(), encode_uncompressed(&rows)?.len());
        assert!(
            zstd * 3 < plain,
            "success 2,000 heartbeats are {zstd} B with zstd, under a third of {plain} B"
        );
        Ok(())
    }

    #[test]
    fn success_a_one_member_question_decodes_one_row_group_of_a_compressed_file() -> TestResult {
        let rows = in_order(&beats(600, 0, 1));
        let read = decode::<MemberRecord>(encode(&rows)?, &of(&id(300)))?;
        assert_eq!(
            (read.rows.len(), read.groups, read.groups_read),
            (1, 5, 1),
            "success the member's heartbeat comes from one of five row groups"
        );
        Ok(())
    }

    #[test]
    fn success_a_call_id_question_decodes_one_row_group_of_a_compressed_file() -> TestResult {
        let rows = in_order(&calls(1, 40));
        let query = Query {
            call_id: Some("call-edge-0000-17@example.com".to_string()),
            ..Query::all()
        };
        let read = decode::<IntakeRecord>(encode_grouped(&rows, 10)?, &query)?;
        assert_eq!(
            (read.rows.len(), read.groups, read.groups_read),
            (1, 4, 1),
            "success the Call-ID filters rule out three of four compressed row groups"
        );
        Ok(())
    }

    #[test]
    fn success_a_window_decodes_the_row_groups_it_overlaps_in_a_compressed_file() -> TestResult {
        let rows = in_order(&calls(1, 40));
        let query = Query {
            from: Some(at_ms(11_000)),
            to: Some(at_ms(21_000)),
            ..Query::all()
        };
        let read = decode::<IntakeRecord>(encode_grouped(&rows, 10)?, &query)?;
        assert_eq!(
            (read.rows.len(), read.groups, read.groups_read),
            (10, 4, 1),
            "success ten seconds of rows come from the one row group that holds them"
        );
        Ok(())
    }

    #[test]
    fn success_a_filing_of_call_records_writes_a_zstd_file() -> TestResult {
        let (_dir, history) = store()?;
        let rows = calls(20, 10);
        history.file(&rows)?;
        let codecs = codecs_of(&only_file::<IntakeRecord>(&history)?)?;
        assert_eq!(
            codecs,
            vec![codec()?; 16],
            "success the eight columns of both row groups of the file a filing wrote are zstd"
        );
        let answer = ask::<IntakeRecord>(&history, &every())?;
        assert_eq!(
            in_order(&answer.rows),
            in_order(&rows),
            "success the store answers with every record of the filing"
        );
        Ok(())
    }

    #[test]
    fn success_a_filing_of_heartbeats_writes_a_zstd_file() -> TestResult {
        let (_dir, history) = store()?;
        let rows = beats(300, 0, 1);
        history.file(&rows)?;
        let codecs = codecs_of(&only_file::<MemberRecord>(&history)?)?;
        assert_eq!(
            codecs,
            vec![codec()?; 33],
            "success the eleven columns of the three row groups of the heartbeat file are zstd"
        );
        let answer = ask::<MemberRecord>(&history, &every())?;
        assert_eq!(
            in_order(&answer.rows),
            in_order(&rows),
            "success the store answers with every heartbeat of the filing"
        );
        Ok(())
    }

    #[test]
    fn success_a_filing_takes_under_a_third_of_the_disk_of_an_earlier_release() -> TestResult {
        let rows = calls(200, 10);
        let (_old_dir, old) = store()?;
        old.file_plain(&rows)?;
        let (_new_dir, new) = store()?;
        new.file(&rows)?;
        let (plain, zstd) = (
            disk_bytes(&old, CLASS_CALLS)?,
            disk_bytes(&new, CLASS_CALLS)?,
        );
        assert!(
            zstd * 3 < plain,
            "success the sealed file of 2,000 call records is {zstd} B, under a third of the \
         {plain} B an earlier release wrote"
        );
        Ok(())
    }

    #[test]
    fn success_a_calls_file_of_an_earlier_release_reads_back() -> TestResult {
        let rows = in_order(&calls(3, 40));
        let file = encode_uncompressed(&rows)?;
        assert_eq!(
            codecs_of(&file)?,
            vec![Compression::UNCOMPRESSED; 8],
            "success the file of an earlier release has no codec"
        );
        let read = decode::<IntakeRecord>(file, &every())?;
        assert_eq!(read.rows, rows, "success its call records read back");
        Ok(())
    }

    #[test]
    fn success_a_heartbeat_file_of_an_earlier_release_reads_back() -> TestResult {
        let rows = in_order(&beats(300, 0, 3));
        let read = decode::<MemberRecord>(encode_uncompressed(&rows)?, &every())?;
        assert_eq!(
            read.rows, rows,
            "success the heartbeats of a file without a codec read back"
        );
        Ok(())
    }

    #[test]
    fn success_a_day_answers_from_an_earlier_releases_file_and_a_new_one() -> TestResult {
        let (_dir, history) = store()?;
        let early: Vec<IntakeRecord> = (1..=5)
            .map(|seq| call("edge-a", seq * 1000, seq.unsigned_abs()))
            .collect();
        let late: Vec<IntakeRecord> = (6..=9)
            .map(|seq| call("edge-a", seq * 1000, seq.unsigned_abs()))
            .collect();
        history.file_plain(&early)?;
        history.file(&late)?;
        let answer = ask::<IntakeRecord>(&history, &every())?;
        let mut all = early;
        all.extend(late);
        assert_eq!(
            (answer.files_read, in_order(&answer.rows)),
            (2, in_order(&all)),
            "success one answer holds the rows of the plain file and of the zstd file"
        );
        Ok(())
    }

    #[test]
    fn success_a_filing_leaves_out_rows_an_earlier_releases_file_holds() -> TestResult {
        let (_dir, history) = store()?;
        let rows = calls(4, 5);
        history.file_plain(&rows)?;
        let again = history.file(&rows)?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (0, 0, 20),
            "success rows a plain file holds are not filed a second time"
        );
        Ok(())
    }

    #[test]
    fn success_the_member_list_is_rebuilt_from_files_of_both_kinds() -> TestResult {
        let (_dir, history) = store()?;
        history.file_plain(&beats(50, 0, 1))?;
        let newest = beats(50, 60_000, 2);
        history.file(&newest)?;
        let rebuilt = history.newest_heartbeats(
            at_ms(0).date_naive(),
            &BTreeMap::new(),
            MAX_FILES_PER_QUESTION,
        )?;
        assert_eq!(
            (rebuilt.refused.len(), in_order(&rebuilt.members)),
            (0, in_order(&newest)),
            "success each member's newest heartbeat is found with a plain file in the day"
        );
        Ok(())
    }

    #[test]
    fn success_an_old_layout_file_is_as_release_0_5_249_wrote_it() -> TestResult {
        let (_dir, history) = store()?;
        let rows = vec![call("edge-a", 1000, 1), call("edge-a", 2000, 2)];
        history.file_per_member(&rows)?;
        let codecs = codecs_of(&only_file::<IntakeRecord>(&history)?)?;
        let answer = ask::<IntakeRecord>(&history, &of("edge-a"))?;
        assert_eq!(
            (codecs, in_order(&answer.rows)),
            (vec![Compression::UNCOMPRESSED; 8], rows),
            "success a file under member=<id> has no codec and answers"
        );
        Ok(())
    }

    #[test]
    fn success_the_same_rows_are_the_same_bytes() -> TestResult {
        let rows = in_order(&calls(5, 30));
        assert_eq!(
            encode(&rows)?,
            encode(&rows)?,
            "success two encodings of the same rows are byte-equal"
        );
        Ok(())
    }

    #[test]
    fn success_text_outside_ascii_reads_back_from_a_compressed_file() -> TestResult {
        let mut row = call("edge-a", 1000, 1);
        row.call = serde_json::json!({
            "call_id": "call-1@example.com",
            "from_display": "Zo\u{eb} \u{4e2d}\u{6587} \u{1f4de}",
            "reason": "line one\nline two\ttab \u{0} nul",
        });
        let read = decode::<IntakeRecord>(encode(std::slice::from_ref(&row))?, &every())?;
        assert_eq!(
            read.rows,
            vec![row],
            "success text of several scripts and control characters reads back"
        );
        Ok(())
    }

    // ----- failure -----

    #[test]
    fn failure_a_file_in_snappy_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::SNAPPY)?;
        assert_eq!(
            why,
            "parquet: column received_at is compressed with snappy; this build reads zstd and \
         uncompressed files",
            "failure a snappy file is refused before a page is read"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_gzip_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::GZIP(parquet::basic::GzipLevel::default()))?;
        assert!(
            why.contains("is compressed with gzip; this build reads zstd and uncompressed files"),
            "failure a gzip file is refused with the codec named, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_brotli_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::BROTLI(parquet::basic::BrotliLevel::default()))?;
        assert!(
            why.contains("is compressed with brotli; this build reads zstd and uncompressed files"),
            "failure a brotli file is refused with the codec named, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_lz4_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::LZ4)?;
        assert!(
            why.contains("is compressed with lz4; this build reads zstd and uncompressed files"),
            "failure an lz4 file is refused with the codec named, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_lz4_raw_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::LZ4_RAW)?;
        assert!(
            why.contains(
                "is compressed with lz4_raw; this build reads zstd and uncompressed files"
            ),
            "failure an lz4_raw file is refused with the codec named, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_lzo_is_refused_with_the_codec_named() -> TestResult {
        let why = refusal_in(Compression::LZO)?;
        assert!(
            why.contains("is compressed with lzo; this build reads zstd and uncompressed files"),
            "failure an lzo file is refused with the codec named, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_heartbeat_file_in_another_codec_is_refused() -> TestResult {
        let file = marked(&encode_uncompressed(&beats(5, 0, 1))?, Compression::SNAPPY)?;
        let why = decode::<MemberRecord>(file, &Query::all())
            .err()
            .ok_or("a snappy heartbeat file was read")?;
        assert_eq!(
            why,
            "parquet: column received_at is compressed with snappy; this build reads zstd and \
         uncompressed files",
            "failure a heartbeat file in another codec is refused as a call record file is"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_in_another_codec_is_refused_for_a_question_no_row_answers() -> TestResult {
        let file = marked(&encode_uncompressed(&calls(1, 5))?, Compression::SNAPPY)?;
        let why = decode::<IntakeRecord>(file, &of("edge-zzzz"))
            .err()
            .ok_or("a snappy file was read for a member it does not hold")?;
        assert!(
            why.contains("is compressed with snappy"),
            "failure the codec is refused whatever the question rules out, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_whose_last_row_group_is_in_another_codec_is_refused_whole() -> TestResult {
        let rows = in_order(&calls(1, 40));
        let file = marked_from(&encode_grouped(&rows, 10)?, 3, Compression::SNAPPY)?;
        // The question's window ends before the last row group begins.
        let query = Query {
            to: Some(at_ms(5000)),
            ..Query::all()
        };
        let why = decode::<IntakeRecord>(file, &query)
            .err()
            .ok_or("rows were read from a file with a row group in snappy")?;
        assert_eq!(
            why,
            "parquet: column received_at is compressed with snappy; this build reads zstd and \
         uncompressed files",
            "failure no row of the three zstd row groups is answered from a file with a fourth in \
         snappy"
        );
        Ok(())
    }

    #[test]
    fn failure_the_store_refuses_a_file_in_another_codec_and_names_it() -> TestResult {
        let (_dir, history) = store()?;
        history.file_as(&calls(1, 5), &|rows| {
            marked(&encode_uncompressed(rows)?, Compression::SNAPPY).map_err(|e| e.to_string())
        })?;
        let query = every();
        let listed = history.list(CLASS_CALLS, &query)?;
        let answer = history.answer(&query, &listed, Vec::<IntakeRecord>::new());
        let reasons: Vec<&str> = answer.refused.iter().map(|(_, why)| why.as_str()).collect();
        assert_eq!(
            (answer.rows.len(), reasons),
            (
                0,
                vec![
                    "parquet: column received_at is compressed with snappy; this build reads zstd \
                 and uncompressed files"
                ]
            ),
            "failure the answer holds no row of the file and the reason names the codec"
        );
        Ok(())
    }

    #[test]
    fn failure_the_store_answers_from_the_other_files_of_a_day_with_a_refused_one() -> TestResult {
        let (_dir, history) = store()?;
        history.file_as(&[call("edge-a", 1000, 1)], &|rows| {
            marked(&encode_uncompressed(rows)?, Compression::LZ4_RAW).map_err(|e| e.to_string())
        })?;
        let kept = [call("edge-b", 5000, 1), call("edge-b", 6000, 2)];
        history.file(&kept)?;
        let query = every();
        let listed = history.list(CLASS_CALLS, &query)?;
        let answer = history.answer(&query, &listed, Vec::<IntakeRecord>::new());
        assert_eq!(
            (answer.refused.len(), in_order(&answer.rows)),
            (1, kept.to_vec()),
            "failure one file in another codec is refused and the zstd file answers"
        );
        Ok(())
    }

    #[test]
    fn failure_half_of_a_compressed_file_is_refused() -> TestResult {
        let file = encode(&calls(3, 40))?;
        let why = refusal(file[..file.len() / 2].to_vec())?;
        assert!(
            why.starts_with("parquet: "),
            "failure half a file is refused by the Parquet reader, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_compressed_file_without_its_last_byte_is_refused() -> TestResult {
        let file = encode(&calls(3, 40))?;
        let why = refusal(file[..file.len() - 1].to_vec())?;
        assert!(
            why.starts_with("parquet: "),
            "failure a file one byte short is refused by the Parquet reader, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_damaged_zstd_frame_is_refused() -> TestResult {
        const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
        let mut file = encode(&calls(3, 40))?;
        let at = file
            .windows(4)
            .position(|window| window == MAGIC)
            .ok_or("the file holds no zstd frame")?;
        file[at] ^= 0xff;
        let why = refusal(file)?;
        assert!(
            why.starts_with("parquet: "),
            "failure a page whose zstd frame does not start as one is refused, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_plain_file_whose_footer_says_zstd_is_refused() -> TestResult {
        let why = refusal_in(codec()?)?;
        assert!(
            why.starts_with("parquet: "),
            "failure pages that are not zstd frames are refused, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_rows_are_not_filed_over_a_file_in_another_codec_that_may_hold_them() -> TestResult {
        let (_dir, history) = store()?;
        history.file_as(
            &[call("edge-a", 1000, 1), call("edge-a", 5000, 2)],
            &|rows| {
                marked(&encode_uncompressed(rows)?, Compression::SNAPPY).map_err(|e| e.to_string())
            },
        )?;
        let before = disk_bytes(&history, CLASS_CALLS)?;
        // A row of the same seconds: the file may hold it, so a filing reads
        // the file first.
        let refused = history
            .file(&[call("edge-a", 3000, 3)])
            .err()
            .ok_or("rows were filed over a file that could not be read")?;
        assert!(
            refused.starts_with("calls/date=2026-11-11/")
                && refused.ends_with(
                    ".sealed: parquet: column received_at is compressed with snappy; this build \
                 reads zstd and uncompressed files"
                ),
            "failure a filing that cannot read a file that may hold its rows names the file and \
         the codec, got: {refused}"
        );
        assert_eq!(
            (
                history.list(CLASS_CALLS, &Query::all())?.len(),
                disk_bytes(&history, CLASS_CALLS)?
            ),
            (1, before),
            "failure the directory holds the one file it held"
        );
        Ok(())
    }

    #[test]
    fn failure_a_level_past_the_codecs_greatest_is_refused() {
        let refused = zstd(23);
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.starts_with("parquet: ")),
            "failure zstd has no level 23, got: {refused:?}"
        );
    }

    // ----- edge -----

    #[test]
    fn edge_one_row_is_a_compressed_file_that_reads_back() -> TestResult {
        let row = call("edge-a", 1000, 1);
        let file = encode(std::slice::from_ref(&row))?;
        assert_eq!(
            codecs_of(&file)?,
            vec![codec()?; 8],
            "edge a file of one row is zstd"
        );
        let read = decode::<IntakeRecord>(file, &every())?;
        assert_eq!(read.rows, vec![row], "edge its one row reads back");
        Ok(())
    }

    #[test]
    fn edge_empty_texts_read_back_from_a_compressed_file() -> TestResult {
        let mut row = call("edge-a", 1000, 1);
        row.stream = String::new();
        row.selected_by = String::new();
        row.call = serde_json::json!({});
        let read = decode::<IntakeRecord>(encode(std::slice::from_ref(&row))?, &every())?;
        assert_eq!(
            read.rows,
            vec![row],
            "edge empty texts and an empty call read back"
        );
        Ok(())
    }

    #[test]
    fn edge_a_row_group_of_the_most_rows_and_one_more_read_back() -> TestResult {
        let rows: Vec<IntakeRecord> = (1..=u64::try_from(ROWS_PER_GROUP)? + 1)
            .map(|seq| {
                let mut row = call("edge-a", i64::try_from(seq).unwrap_or(0), seq);
                row.call = serde_json::json!({"call_id": format!("call-{seq}@example.com")});
                row
            })
            .collect();
        let file = encode(&rows)?;
        assert_eq!(
            (group_rows_of(&file)?, codecs_of(&file)?),
            (vec![10_000, 1], vec![codec()?; 16]),
            "edge 10,001 rows of one member are a full row group and a group of one, both zstd"
        );
        let read = decode::<IntakeRecord>(file, &Query::all())?;
        assert_eq!(
            (read.groups_read, read.rows.len()),
            (2, 10_001),
            "edge both row groups are decoded and every row is read"
        );
        Ok(())
    }

    #[test]
    fn edge_noise_is_no_larger_compressed_than_plain() -> TestResult {
        let rows = noisy(200, 1000);
        let (zstd, plain) = (encode(&rows)?.len(), encode_uncompressed(&rows)?.len());
        assert!(
            zstd <= plain,
            "edge 200 kB of noise is {zstd} B with zstd, no more than the {plain} B without"
        );
        let read = decode::<IntakeRecord>(encode(&rows)?, &every())?;
        assert_eq!(read.rows, rows, "edge the noise reads back");
        Ok(())
    }

    #[test]
    fn edge_a_value_of_one_mebibyte_reads_back() -> TestResult {
        let mut row = call("edge-a", 1000, 1);
        row.call = serde_json::json!({"call_id": "call-1@example.com", "noise": noise(7, 1 << 20)});
        let read = decode::<IntakeRecord>(encode(std::slice::from_ref(&row))?, &every())?;
        assert_eq!(read.rows, vec![row], "edge a call of 1 MiB reads back");
        Ok(())
    }

    #[test]
    fn edge_rows_past_one_sealed_piece_plain_are_one_piece_compressed() -> TestResult {
        let rows = in_order(&calls(100, 90));
        let (plain, zstd) = (encode_uncompressed(&rows)?, encode(&rows)?);
        let pieces =
            |parquet: &[u8]| sealed_lines("calls/x.sealed", parquet, CHUNK_BYTES).len() - 1;
        assert!(
            pieces(&plain) >= 2 && pieces(&zstd) == 1,
            "edge 9,000 call records are {} B in {} sealed pieces plain and {} B in {} compressed",
            plain.len(),
            pieces(&plain),
            zstd.len(),
            pieces(&zstd)
        );
        Ok(())
    }

    #[test]
    fn edge_a_compressed_file_of_several_sealed_pieces_reads_back_from_the_store() -> TestResult {
        let (_dir, history) = store()?;
        let rows = noisy(8000, 1000);
        history.file(&rows)?;
        let parquet = only_file::<IntakeRecord>(&history)?;
        assert!(
            parquet.len() > CHUNK_BYTES,
            "edge 8 MB of noise is {} B compressed, more than one sealed piece of {CHUNK_BYTES} B",
            parquet.len()
        );
        let query = Query {
            call_id: Some("call-7999@example.com".to_string()),
            ..Query::all()
        };
        let answer = ask::<IntakeRecord>(&history, &query)?;
        assert_eq!(
            answer.rows,
            vec![rows[7998].clone()],
            "edge a record near the end of a file of several pieces is found"
        );
        Ok(())
    }

    #[test]
    fn edge_a_compressed_file_has_the_row_groups_of_a_plain_one() -> TestResult {
        let rows = in_order(&calls(600, 2));
        let (zstd, plain) = (encode(&rows)?, encode_uncompressed(&rows)?);
        assert_eq!(
            group_rows_of(&zstd)?,
            group_rows_of(&plain)?,
            "edge the codec does not move a row group's end"
        );
        assert_eq!(
            group_rows_of(&zstd)?.len(),
            10,
            "edge 1,200 rows of 600 members are ten row groups"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_id_no_row_has_decodes_no_group_of_a_compressed_file() -> TestResult {
        let query = Query {
            call_id: Some("call-none@example.com".to_string()),
            ..Query::all()
        };
        let read = decode::<IntakeRecord>(encode_grouped(&in_order(&calls(1, 40)), 10)?, &query)?;
        assert_eq!(
            (read.rows.len(), read.groups, read.groups_read),
            (0, 4, 0),
            "edge the Call-ID filters of a compressed file rule every row group out"
        );
        Ok(())
    }

    #[test]
    fn edge_an_answer_of_a_few_rows_spans_a_plain_file_and_a_zstd_file() -> TestResult {
        let (_dir, history) = store()?;
        history.file_plain(&[call("edge-a", 1000, 1), call("edge-a", 2000, 2)])?;
        history.file(&[call("edge-a", 3000, 3), call("edge-a", 4000, 4)])?;
        let query = Query {
            limit: 3,
            ..of("edge-a")
        };
        let answer = ask::<IntakeRecord>(&history, &query)?;
        assert_eq!(
            (answer.rows.len(), answer.more, answer.files_read),
            (3, true, 2),
            "edge three of four rows come from both files, and the answer says there are more"
        );
        Ok(())
    }

    #[test]
    fn edge_a_footer_written_again_with_the_files_own_codec_reads_back() -> TestResult {
        let rows = in_order(&calls(3, 40));
        let read = decode::<IntakeRecord>(marked(&encode(&rows)?, codec()?)?, &every())?;
        assert_eq!(
            read.rows, rows,
            "edge a zstd file whose footer was written again reads back: the refusals above come \
         from the codec the footer names"
        );
        Ok(())
    }

    #[test]
    fn edge_a_zstd_file_of_another_level_reads_back() -> TestResult {
        let rows = in_order(&calls(3, 40));
        let file = encode_cut(&rows, GROUP_ROWS, ROWS_PER_GROUP, zstd(19)?)?;
        assert_ne!(
            file,
            encode(&rows)?,
            "edge level 19 gives other bytes than level 1"
        );
        let read = decode::<IntakeRecord>(file, &every())?;
        assert_eq!(read.rows, rows, "edge a file of level 19 reads back");
        Ok(())
    }

    #[test]
    fn edge_the_least_and_the_greatest_level_are_codecs() -> TestResult {
        let rows = in_order(&calls(1, 5));
        for level in [-131_072, 22] {
            let file = encode_cut(&rows, GROUP_ROWS, ROWS_PER_GROUP, zstd(level)?)?;
            let read = decode::<IntakeRecord>(file, &every())?;
            assert_eq!(read.rows, rows, "edge a file of level {level} reads back");
        }
        Ok(())
    }

    #[test]
    fn edge_the_two_codecs_this_build_reads_and_the_six_it_does_not() -> TestResult {
        let read = [Compression::UNCOMPRESSED, zstd(1)?, zstd(19)?];
        for codec in read {
            assert_eq!(
                codec_read("call", codec),
                Ok(()),
                "edge a column in {} is read",
                codec_name(codec)
            );
        }
        let refused = [
            (Compression::SNAPPY, "snappy"),
            (
                Compression::GZIP(parquet::basic::GzipLevel::default()),
                "gzip",
            ),
            (Compression::LZO, "lzo"),
            (
                Compression::BROTLI(parquet::basic::BrotliLevel::default()),
                "brotli",
            ),
            (Compression::LZ4, "lz4"),
            (Compression::LZ4_RAW, "lz4_raw"),
        ];
        for (codec, name) in refused {
            assert_eq!(
                codec_read("call", codec),
                Err(format!(
                    "parquet: column call is compressed with {name}; this build reads zstd and \
                 uncompressed files"
                )),
                "edge a column in {name} is refused with the column and the codec named"
            );
        }
        Ok(())
    }

    #[test]
    fn edge_a_one_member_question_decodes_one_group_of_each_kind_of_file() -> TestResult {
        let (_dir, history) = store()?;
        history.file_plain(&beats(600, 0, 1))?;
        history.file(&beats(600, 60_000, 2))?;
        let answer = ask::<MemberRecord>(&history, &of(&id(300)))?;
        assert_eq!(
            (
                answer.rows.len(),
                answer.files_read,
                answer.groups,
                answer.groups_read
            ),
            (2, 2, 10, 2),
            "edge the member's two heartbeats come from one row group of each file"
        );
        Ok(())
    }

    #[test]
    fn edge_rows_of_two_days_are_two_zstd_files() -> TestResult {
        let (_dir, history) = store()?;
        let rows = [call("edge-a", 1000, 1), call("edge-a", DAY + 1000, 2)];
        let filed = history.file(&rows)?;
        assert_eq!(
            (filed.files, filed.rows),
            (2, 2),
            "edge one file for each day"
        );
        for file in history.list(CLASS_CALLS, &Query::all())? {
            let sealed = std::fs::read(history.dir().join(&file.rel))?;
            let parquet = unseal(&file.rel, &sealed, &history.keys, Kind::Calls)?;
            assert_eq!(
                codecs_of(&parquet)?,
                vec![codec()?; 8],
                "edge {} is zstd",
                file.rel
            );
        }
        Ok(())
    }

    #[test]
    fn edge_filing_the_same_rows_again_writes_no_second_compressed_file() -> TestResult {
        let (_dir, history) = store()?;
        let rows = calls(4, 5);
        history.file(&rows)?;
        let before = disk_bytes(&history, CLASS_CALLS)?;
        let again = history.file(&rows)?;
        assert_eq!(
            (
                again.files,
                again.already,
                disk_bytes(&history, CLASS_CALLS)?
            ),
            (0, 20, before),
            "edge rows a zstd file holds are read back and not filed again"
        );
        Ok(())
    }

    /// What the codec saves on disk for one filing of a fleet's heartbeats and
    /// one of its call records, on rows of this module's shape: the sealed
    /// file this build writes against the one releases 0.5.249 to 0.5.253
    /// wrote. The sizes here are small. The numbers in docs/fleet.md came from
    /// this test with 2,000 members and 10 call records each in the line
    /// below.
    #[test]
    fn edge_a_filing_is_measured_with_and_without_the_codec() -> TestResult {
        let (members, each) = (200, 4);
        let (heartbeats, records) = (beats(members, 0, 720), calls(members, each));
        let (_old_dir, old) = store()?;
        old.file_plain(&heartbeats)?;
        old.file_plain(&records)?;
        let (_new_dir, new) = store()?;
        let started = std::time::Instant::now();
        new.file(&heartbeats)?;
        let beats_filed = started.elapsed();
        let started = std::time::Instant::now();
        new.file(&records)?;
        let calls_filed = started.elapsed();
        let started = std::time::Instant::now();
        let answer = ask::<IntakeRecord>(&new, &of(&id(members / 2)))?;
        let asked = started.elapsed();
        assert_eq!(
            (answer.rows.len(), answer.groups_read),
            (usize::try_from(each)?, 1),
            "edge one member's call records come from one row group"
        );
        let sizes = [
            disk_bytes(&old, CLASS_MEMBERS)?,
            disk_bytes(&new, CLASS_MEMBERS)?,
            disk_bytes(&old, CLASS_CALLS)?,
            disk_bytes(&new, CLASS_CALLS)?,
        ];
        stderr_line!(
            "fleet codec measurement: {members} heartbeats in one sealed file: {} B without a \
         codec, {} B with zstd, filed in {beats_filed:?}; {} call records in one sealed file: \
         {} B without a codec, {} B with zstd, filed in {calls_filed:?}; one member's records \
         read in {asked:?}",
            sizes[0],
            sizes[1],
            records.len(),
            sizes[2],
            sizes[3]
        );
        assert!(
            sizes[1] * 3 < sizes[0] && sizes[3] * 3 < sizes[2],
            "edge both classes are under a third of their size without a codec: {sizes:?}"
        );
        Ok(())
    }
}

/// The layout of one file for each filing and day, whatever the number of
/// members, and the files release 0.5.249 wrote under `member=<id>`.
#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::app::fleet_calls::CallCounts;
    use crate::app::fleet_center::Cursor;
    use crate::app::fleet_seal::MasterKey;

    /// What a test returns.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// One day in milliseconds.
    const DAY: i64 = 86_400_000;

    /// A key whose every byte is `b`, alone.
    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    /// The call record at `seq` of `member`, received `ms` milliseconds
    /// into 2026-11-11.
    fn call(member: &str, ms: i64, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            stream: "s".to_string(),
            seq,
            sent_at: at_ms(ms - 250),
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": format!("call-{seq}@example.com")}),
        }
    }

    /// Heartbeat `count` of `member`, received `ms` milliseconds into
    /// 2026-11-11.
    fn beat(member: &str, ms: i64, count: u64) -> MemberRecord {
        MemberRecord {
            member: member.to_string(),
            received_at: at_ms(ms),
            peer: "192.0.2.10".to_string(),
            heartbeats: count,
            cursor: Cursor {
                stream: "s".to_string(),
                seq: count,
                sent_at: at_ms(ms - 250),
            },
            heartbeat_secs: 30,
            inventory: serde_json::json!({"host": "edge.example.com"}),
            call_records: count,
            calls: Some(CallCounts {
                selected: count,
                dropped_by_cap: 0,
                left_out: 0,
                spooled: 0,
            }),
        }
    }

    /// The id of member `n` of a fleet.
    fn id(n: usize) -> String {
        format!("edge-{n:04}")
    }

    /// One call record of each of `members` members, all received within
    /// one second from `ms` on, at position `seq`.
    fn fleet_calls(members: usize, ms: i64, seq: u64) -> Vec<IntakeRecord> {
        (0..members)
            .map(|n| call(&id(n), ms + i64::try_from(n % 1000).unwrap_or(0), seq))
            .collect()
    }

    /// One heartbeat of each of `members` members, as [`fleet_calls`].
    fn fleet_beats(members: usize, ms: i64, count: u64) -> Vec<MemberRecord> {
        (0..members)
            .map(|n| beat(&id(n), ms + i64::try_from(n % 1000).unwrap_or(0), count))
            .collect()
    }

    /// A history store in a new directory, under key 1.
    fn store() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let history = History::open(&dir.path().join("center.store"), keys(1))?;
        Ok((dir, history))
    }

    /// Every file under `dir`, as paths relative to it, sorted.
    fn tree(dir: &Path) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(&at)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                } else if let Ok(rel) = entry.path().strip_prefix(dir) {
                    out.push(rel.to_string_lossy().into_owned());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// The question for every row of `member`.
    fn of(member: &str) -> Query {
        Query {
            member: Some(member.to_string()),
            ..Query::all()
        }
    }

    /// The answer of the store to `query` with no row waiting; a file that
    /// was refused is an error.
    fn ask<R: Row>(history: &History, query: &Query) -> Result<Answer<R>, String> {
        let answer = history.answer(query, &history.list(R::CLASS, query)?, Vec::<R>::new());
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}"));
        }
        Ok(answer)
    }

    /// Whether `rel` is a path of the layout this build writes in `class`
    /// on 2026-11-11: the class, the day and a name, with no member.
    fn is_interval_path(rel: &str, class: &str) -> bool {
        rel.strip_prefix(&format!("{class}/date=2026-11-11/"))
            .is_some_and(|name| IntervalName::parse(name).is_some())
    }

    #[test]
    fn success_an_interval_name_carries_first_and_last_time_and_the_mark() -> TestResult {
        let rows = [call("edge-a", 1000, 1), call("edge-b", 3000, 1)];
        let name = IntervalName::of(&rows)?;
        assert_eq!(
            (name.first_ms, name.last_ms, name.mark),
            (1_794_355_201_000, 1_794_355_203_000, rows_mark(&rows)?),
            "success a name holds the earliest and latest receive time and the rows' mark"
        );
        assert_eq!(
            name.text(),
            format!("1794355201000-1794355203000-h{:016x}.sealed", name.mark),
            "success a name is first ms, last ms and the mark in 16 hex digits"
        );
        Ok(())
    }

    #[test]
    fn success_an_interval_name_reads_back() -> TestResult {
        let name = IntervalName::of(&fleet_calls(5, 1000, 1))?;
        assert_eq!(
            IntervalName::parse(&name.text()),
            Some(name),
            "success a written name parses to itself"
        );
        let greatest = IntervalName {
            first_ms: 0,
            last_ms: 9_999_999_999_999,
            mark: u64::MAX,
        };
        assert_eq!(
            IntervalName::parse(&greatest.text()),
            Some(greatest),
            "success the least and greatest values read back"
        );
        Ok(())
    }

    #[test]
    fn success_the_same_rows_in_any_order_have_one_name() -> TestResult {
        let rows = fleet_calls(7, 1000, 1);
        let mut turned = rows.clone();
        turned.reverse();
        assert_eq!(
            IntervalName::of(&rows)?,
            IntervalName::of(&turned)?,
            "success a replay that gives the rows in another order spells the same name"
        );
        Ok(())
    }

    #[test]
    fn success_rows_are_sorted_by_member_then_receive_time() {
        let rows = vec![
            call("edge-b", 1000, 1),
            call("edge-a", 3000, 3),
            call("edge-a", 1000, 9),
            call("edge-a", 2000, 2),
        ];
        let order: Vec<(String, u64)> = sorted(rows)
            .into_iter()
            .map(|r| (r.member, r.seq))
            .collect();
        assert_eq!(
            order,
            [
                ("edge-a".to_string(), 9),
                ("edge-a".to_string(), 2),
                ("edge-a".to_string(), 3),
                ("edge-b".to_string(), 1)
            ],
            "success member first, then the receive time, whatever the position says"
        );
    }

    #[test]
    fn success_groups_end_where_the_member_changes() {
        let members: Vec<&str> = [["a"; 100], ["b"; 100], ["c"; 100]].concat();
        assert_eq!(
            group_cuts(&members, 128, 10_000),
            [200, 100],
            "success a group that reached 128 rows ends with the member it is in"
        );
    }

    #[test]
    fn success_a_fleet_of_one_row_each_is_cut_every_128_rows() {
        let ids: Vec<String> = (0..2000).map(id).collect();
        let members: Vec<&str> = ids.iter().map(String::as_str).collect();
        let cuts = group_cuts(&members, GROUP_ROWS, ROWS_PER_GROUP);
        assert_eq!(cuts.len(), 16, "success 2,000 rows are 16 row groups");
        assert!(
            cuts[..15].iter().all(|rows| *rows == 128) && cuts[15] == 80,
            "success 15 groups of 128 rows and one of 80, got {cuts:?}"
        );
    }

    #[test]
    fn success_a_question_wants_the_days_of_its_window() -> TestResult {
        let query = Query {
            from: Some(at_ms(1000)),
            to: Some(at_ms(DAY + 1000)),
            ..Query::all()
        };
        let day = |offset: i64| at_ms(offset * DAY).date_naive();
        assert!(
            query.wants_date(day(0)) && query.wants_date(day(1)),
            "success the days the window touches"
        );
        assert!(
            !query.wants_date(day(-1)) && !query.wants_date(day(2)),
            "success no day before or after the window"
        );
        Ok(())
    }

    #[test]
    fn success_rows_are_grouped_by_day_only() {
        let rows = [
            call("edge-a", 1000, 1),
            call("edge-b", 2000, 1),
            call("edge-a", DAY, 2),
        ];
        let got: Vec<(String, usize)> = by_date(&rows)
            .into_iter()
            .map(|(date, rows)| (date.to_string(), rows.len()))
            .collect();
        assert_eq!(
            got,
            [("2026-11-11".to_string(), 2), ("2026-11-12".to_string(), 1)],
            "success two members of one day are one group"
        );
    }

    #[test]
    fn failure_no_rows_have_no_interval_name() {
        assert!(
            IntervalName::of(&Vec::<IntakeRecord>::new())
                .is_err_and(|e| e.contains("no rows") && e.contains("at least one")),
            "failure a file of no rows has no name"
        );
    }

    #[test]
    fn failure_names_this_module_does_not_write_are_no_interval_name() {
        for name in [
            "",
            ".sealed",
            "1794355201000-1794355203000-s-1.sealed",
            "1794355201000-1794355203000-h0123456789abcdef",
            "1794355201000-1794355203000-h0123456789ABCDEF.sealed",
            "1794355201000-1794355203000-h123.sealed",
            "1794355201000-1794355203000-0123456789abcdef.sealed",
            "1794355201000-1794355203000-h0123456789abcdeg.sealed",
            "1794355201000-1794355203000-h0123456789abcdef0.sealed",
            "1794355203000-1794355201000-h0123456789abcdef.sealed",
            "794355201000-1794355203000-h0123456789abcdef.sealed",
            "+794355201000-1794355203000-h0123456789abcdef.sealed",
            "1794355201000-1794355203000-h0123456789abcdef.sealed.partial",
            "1794355201000-h0123456789abcdef.sealed",
            "1794355201000-1794355203000-m2-r2-h0123456789abcdef.sealed",
        ] {
            assert_eq!(
                IntervalName::parse(name),
                None,
                "failure {name:?} is not a name this module writes"
            );
        }
    }

    #[test]
    fn failure_the_names_of_the_two_layouts_are_not_each_others() -> TestResult {
        let old = FileName::of(&[call("edge-a", 1000, 1)])?.text();
        let new = IntervalName::of(&[call("edge-a", 1000, 1)])?.text();
        assert_eq!(
            IntervalName::parse(&old),
            None,
            "failure a name of release 0.5.249 is no name of this layout"
        );
        assert_eq!(
            FileName::parse(&new),
            None,
            "failure a name of this layout is no name of release 0.5.249"
        );
        let digits = IntervalName {
            first_ms: 1,
            last_ms: 2,
            mark: 0x1234_5678_9012_3456,
        };
        assert_eq!(
            FileName::parse(&digits.text()),
            None,
            "failure and neither is one whose mark has only decimal digits"
        );
        Ok(())
    }

    #[test]
    fn failure_a_row_received_before_1970_has_no_interval_name() {
        let mut row = call("edge-a", 0, 1);
        row.received_at = DateTime::<Utc>::UNIX_EPOCH - chrono::TimeDelta::seconds(1);
        assert!(
            IntervalName::of(&[row]).is_err_and(|e| e.contains("before 1970")),
            "failure a row the store keeps none of names no file"
        );
    }

    #[test]
    fn edge_different_rows_of_the_same_times_have_different_names() -> TestResult {
        let a = IntervalName::of(&[call("edge-a", 1000, 1)])?;
        let b = IntervalName::of(&[call("edge-b", 1000, 1)])?;
        let later = IntervalName::of(&[call("edge-a", 1000, 2)])?;
        assert_eq!(
            (a.first_ms, a.last_ms),
            (b.first_ms, b.last_ms),
            "edge the same times"
        );
        assert!(
            a.mark != b.mark && a.mark != later.mark,
            "edge another member or another position is another mark"
        );
        Ok(())
    }

    #[test]
    fn edge_the_mark_does_not_run_fields_together() -> TestResult {
        let mut left = call("ab", 1000, 1);
        left.stream = "c".to_string();
        let mut right = call("a", 1000, 1);
        right.stream = "bc".to_string();
        assert_ne!(
            rows_mark(&[left])?,
            rows_mark(&[right])?,
            "edge member 'ab' with stream 'c' is not member 'a' with stream 'bc'"
        );
        Ok(())
    }

    #[test]
    fn edge_the_name_states_no_member_and_no_count() -> TestResult {
        let text = IntervalName::of(&fleet_calls(37, 1000, 1))?.text();
        let stem = text.strip_suffix(".sealed").ok_or("no suffix")?;
        let parts: Vec<&str> = stem.split('-').collect();
        assert_eq!(parts.len(), 3, "edge two times and the mark, got {text}");
        assert!(
            !text.contains("edge") && parts.iter().all(|part| *part != "37"),
            "edge neither a member id nor the number of rows is in {text}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_with_more_rows_than_the_cap_is_cut_at_the_cap() {
        let members: Vec<&str> = [vec!["a"; 25], vec!["b"; 3]].concat();
        assert_eq!(
            group_cuts(&members, 4, 10),
            [10, 10, 5, 3],
            "edge the cap ends a group inside a member; the member's last rows end the next"
        );
    }

    #[test]
    fn edge_no_rows_are_cut_into_no_groups() {
        assert_eq!(
            group_cuts(&[], 128, 10_000),
            Vec::<usize>::new(),
            "edge nothing to cut"
        );
    }

    #[test]
    fn edge_one_member_under_the_cap_is_one_group() {
        assert_eq!(
            group_cuts(&["a"; 9000], 128, 10_000),
            [9000],
            "edge a file of one member, as release 0.5.249 wrote, keeps one group"
        );
    }

    #[test]
    fn edge_a_group_ends_inside_a_member_only_at_the_cap() {
        let members: Vec<&str> = [vec!["a"; 127], vec!["b"; 300], vec!["c"; 1]].concat();
        assert_eq!(
            group_cuts(&members, 128, 10_000),
            [427, 1],
            "edge 127 rows are under the least, so the group takes all of the next member"
        );
    }

    #[test]
    fn edge_the_cuts_add_up_to_the_rows_and_none_is_empty() {
        for (members, least, most) in [
            (vec!["a"; 1], 1, 1),
            (vec!["a"; 7], 3, 3),
            ([vec!["a"; 5], vec!["b"; 5]].concat(), 1, 100),
            ([vec!["a"; 5], vec!["b"; 5]].concat(), 0, 0),
            ([vec!["a"; 2], vec!["b"; 9], vec!["c"; 2]].concat(), 4, 6),
        ] {
            let cuts = group_cuts(&members, least, most);
            assert_eq!(
                cuts.iter().sum::<usize>(),
                members.len(),
                "edge every row is in one group for least {least}, most {most}"
            );
            assert!(
                cuts.iter().all(|rows| *rows > 0),
                "edge no group is empty for least {least}, most {most}: {cuts:?}"
            );
        }
    }

    #[test]
    fn success_the_members_of_one_filing_are_one_file() -> TestResult {
        let (_dir, history) = store()?;
        let filed = history.file(&fleet_calls(50, 1000, 1))?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (1, 50, 0),
            "success 50 members with one call record each are one file"
        );
        let files = tree(history.dir())?;
        assert_eq!(files.len(), 1, "success one file on disk, got {files:?}");
        assert!(
            is_interval_path(&files[0], CLASS_CALLS),
            "success at calls/date=/<name>, with no member in the path: {}",
            files[0]
        );
        Ok(())
    }

    #[test]
    fn success_the_files_of_a_day_do_not_grow_with_the_members() -> TestResult {
        let mut counts = Vec::new();
        for members in [1, 40] {
            let (_dir, history) = store()?;
            for interval in 0..3 {
                history.file(&fleet_calls(
                    members,
                    interval * 60_000,
                    1 + interval as u64,
                ))?;
            }
            counts.push(tree(history.dir())?.len());
        }
        assert_eq!(
            counts,
            [3, 3],
            "success three filings are three files for 1 member and for 40"
        );
        Ok(())
    }

    #[test]
    fn success_the_heartbeats_of_one_filing_are_one_file() -> TestResult {
        let (_dir, history) = store()?;
        let filed = history.file(&fleet_beats(300, 1000, 1))?;
        assert_eq!(
            (filed.files, filed.rows),
            (1, 300),
            "success 300 heartbeats are one file"
        );
        let files = tree(history.dir())?;
        assert!(
            files.len() == 1 && is_interval_path(&files[0], CLASS_MEMBERS),
            "success at members/date=/<name>: {files:?}"
        );
        Ok(())
    }

    #[test]
    fn success_a_one_member_question_decodes_one_row_group_of_calls() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(2000, 1000, 1))?;
        let answer = ask::<IntakeRecord>(&history, &of(&id(1234)))?;
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.member.clone())
                .collect::<Vec<String>>(),
            [id(1234)],
            "success the member's one call record"
        );
        assert_eq!(
            (answer.files_read, answer.groups, answer.groups_read),
            (1, 16, 1),
            "success of the file's 16 row groups, the reader decoded the one that holds the \
             member"
        );
        Ok(())
    }

    #[test]
    fn success_a_one_member_question_decodes_one_row_group_of_heartbeats() -> TestResult {
        let (_dir, history) = store()?;
        for interval in 0..3 {
            history.file(&fleet_beats(2000, interval * 60_000, 1 + interval as u64))?;
        }
        let answer = ask::<MemberRecord>(&history, &of(&id(7)))?;
        assert_eq!(
            answer
                .rows
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [3, 2, 1],
            "success the member's three heartbeats, newest first"
        );
        assert_eq!(
            (answer.files_read, answer.groups, answer.groups_read),
            (3, 48, 3),
            "success one row group of each file's 16 was decoded"
        );
        Ok(())
    }

    #[test]
    fn success_rows_of_two_days_are_two_files() -> TestResult {
        let (_dir, history) = store()?;
        let mut rows = fleet_calls(5, 1000, 1);
        rows.extend(fleet_calls(5, DAY + 1000, 2));
        let filed = history.file(&rows)?;
        assert_eq!((filed.files, filed.rows), (2, 10), "success one file a day");
        let files = tree(history.dir())?;
        assert!(
            files[0].starts_with("calls/date=2026-11-11/")
                && files[1].starts_with("calls/date=2026-11-12/"),
            "success each under its day: {files:?}"
        );
        Ok(())
    }

    #[test]
    fn success_filed_rows_of_many_members_read_back_equal() -> TestResult {
        let (_dir, history) = store()?;
        let mut rows = fleet_calls(300, 1000, 1);
        rows.extend(fleet_calls(300, 2000, 2));
        history.file(&rows)?;
        let rel = &history.list(CLASS_CALLS, &Query::all())?[0].rel;
        let read = history.read::<IntakeRecord>(rel, &Query::all())?;
        assert_eq!(
            read.rows,
            sorted(rows),
            "success every row, whole, in the file's order: member, then receive time"
        );
        assert!(
            read.groups > 1 && read.groups_read == read.groups,
            "success a question for every row reads every group"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_of_release_0_5_249_is_listed_and_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-a", 2000, 2)])?;
        let files = history.list(CLASS_CALLS, &Query::all())?;
        assert_eq!(files.len(), 1, "success the file is listed");
        assert_eq!(
            (files[0].rel.as_str(), files[0].member.as_deref()),
            (
                "calls/date=2026-11-11/member=edge-a/1794355201000-1794355203000-s-1.sealed"
                    .replace("3000-s", "2000-s")
                    .as_str(),
                Some("edge-a")
            ),
            "success at its path of release 0.5.249, with its member"
        );
        let answer = ask::<IntakeRecord>(&history, &Query::all())?;
        assert_eq!(
            answer.rows.iter().map(|r| r.seq).collect::<Vec<u64>>(),
            [2, 1],
            "success and its rows are answered"
        );
        Ok(())
    }

    #[test]
    fn success_both_layouts_answer_one_question_newest_first() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-b", 1500, 1)])?;
        history.file(&[call("edge-a", 2000, 2), call("edge-b", 2500, 2)])?;
        let all = ask::<IntakeRecord>(&history, &Query::all())?;
        assert_eq!(
            all.rows
                .iter()
                .map(|r| (r.member.as_str(), r.seq))
                .collect::<Vec<(&str, u64)>>(),
            [("edge-b", 2), ("edge-a", 2), ("edge-b", 1), ("edge-a", 1)],
            "success rows of both layouts, newest first"
        );
        assert_eq!(all.files_read, 3, "success two old files and one new");
        let one = ask::<IntakeRecord>(&history, &of("edge-b"))?;
        assert_eq!(
            (one.rows.len(), one.files_read),
            (2, 2),
            "success one member: its old file and the shared file, not the other member's"
        );
        Ok(())
    }

    #[test]
    fn success_a_one_member_question_rules_out_old_files_by_their_path() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&fleet_calls(20, 1000, 1))?;
        let files = history.list(CLASS_CALLS, &of(&id(3)))?;
        assert_eq!(files.len(), 1, "success one of the 20 old files is listed");
        assert_eq!(
            files[0].member,
            Some(id(3)),
            "success the one under the member's directory"
        );
        Ok(())
    }

    #[test]
    fn success_days_of_both_layouts_expire_and_are_counted() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)])?;
        history.file(&fleet_calls(10, 2000, 2))?;
        history.file(&fleet_calls(10, 5 * DAY, 3))?;
        let expired = history.expire_before(CLASS_CALLS, at_ms(3 * DAY).date_naive())?;
        assert_eq!(
            (expired.days, expired.files, expired.left.len()),
            (1, 3, 0),
            "success the day went with its two old files and its one new file"
        );
        let files = tree(history.dir())?;
        assert!(
            files.len() == 1 && files[0].starts_with("calls/date=2026-11-16/"),
            "success the kept day stays: {files:?}"
        );
        assert!(
            !history.dir().join("calls/date=2026-11-11").exists(),
            "success and the old day's directories are gone"
        );
        Ok(())
    }

    #[test]
    fn success_the_rebuild_finds_each_members_newest_heartbeat_in_shared_files() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1), beat("edge-b", 1000, 1)])?;
        history.file(&[beat("edge-a", 2000, 2)])?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 100)?;
        let mut got: Vec<(String, u64)> = found
            .members
            .iter()
            .map(|r| (r.member.clone(), r.heartbeats))
            .collect();
        got.sort();
        assert_eq!(
            got,
            [("edge-a".to_string(), 2), ("edge-b".to_string(), 1)],
            "success each member once, with its newest heartbeat"
        );
        assert_eq!(
            (found.files_read, found.files_not_read, found.refused.len()),
            (2, 0, 0),
            "success with no member named, every file to the retention edge is read"
        );
        Ok(())
    }

    #[test]
    fn success_call_records_after_each_members_instant_come_in_one_pass() -> TestResult {
        let (_dir, history) = store()?;
        for (ms, seq) in [(1000, 1), (2000, 2), (3000, 3)] {
            history.file(&[
                call("edge-a", ms, seq),
                call("edge-b", ms, seq),
                call("edge-c", ms, seq),
            ])?;
        }
        let since = BTreeMap::from([
            ("edge-a".to_string(), at_ms(2000)),
            ("edge-b".to_string(), at_ms(3000)),
        ]);
        let found = history.calls_after(&since, 100)?;
        assert_eq!(
            found
                .rows
                .iter()
                .map(|r| (r.member.as_str(), r.seq))
                .collect::<Vec<(&str, u64)>>(),
            [("edge-a", 2), ("edge-a", 3), ("edge-b", 3)],
            "success each member's records from its own instant on, oldest first, and no \
             record of a member that was not asked for"
        );
        assert_eq!(
            (found.files_read, found.files_not_read),
            (2, 0),
            "success two files for two members: the file before every instant is not opened"
        );
        Ok(())
    }

    #[test]
    fn success_call_records_after_an_instant_include_old_layout_files() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-b", 1000, 9)])?;
        history.file(&[call("edge-a", 2000, 2)])?;
        let since = BTreeMap::from([("edge-a".to_string(), at_ms(0))]);
        let found = history.calls_after(&since, 100)?;
        assert_eq!(
            found.rows.iter().map(|r| r.seq).collect::<Vec<u64>>(),
            [1, 2],
            "success the member's record of release 0.5.249 and the new one"
        );
        assert_eq!(
            found.files_read, 2,
            "success the other member's old file is ruled out by its path"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_moved_to_another_day_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let from = tree(history.dir())?.remove(0);
        let to = from.replace("date=2026-11-11", "date=2026-11-12");
        std::fs::create_dir_all(history.dir().join("calls/date=2026-11-12"))?;
        std::fs::rename(history.dir().join(&from), history.dir().join(&to))?;
        assert!(
            history
                .read::<IntakeRecord>(&to, &Query::all())
                .is_err_and(|e| e.contains("was written as") && e.contains("date=2026-11-11")),
            "failure a file does not open at another day's path"
        );
        Ok(())
    }

    #[test]
    fn failure_an_old_file_moved_out_of_its_member_directory_is_not_listed() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1)])?;
        let from = tree(history.dir())?.remove(0);
        let name = from.rsplit('/').next().ok_or("no name")?;
        let day = history.dir().join("calls/date=2026-11-11");
        std::fs::rename(history.dir().join(&from), day.join(name))?;
        assert_eq!(
            history.list(CLASS_CALLS, &Query::all())?,
            Vec::new(),
            "failure a name of release 0.5.249 beside the shared files is no file of the store"
        );
        let expired = history.expire_before(CLASS_CALLS, at_ms(DAY).date_naive())?;
        assert!(
            expired.files == 0
                && expired
                    .left
                    .iter()
                    .any(|left| left.contains(name) && left.contains("not a file of the store")),
            "failure and a retention pass leaves it and says so: {expired:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_shared_file_under_a_member_directory_is_not_listed() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let from = tree(history.dir())?.remove(0);
        let name = from.rsplit('/').next().ok_or("no name")?;
        let member = history.dir().join("calls/date=2026-11-11/member=edge-a");
        std::fs::create_dir_all(&member)?;
        std::fs::rename(history.dir().join(&from), member.join(name))?;
        assert_eq!(
            history.list(CLASS_CALLS, &Query::all())?,
            Vec::new(),
            "failure a name of this layout under member= is no file of the store"
        );
        Ok(())
    }

    #[test]
    fn failure_a_changed_shared_file_is_refused_and_the_rest_is_answered() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        history.file(&fleet_calls(3, 60_000, 2))?;
        let files = history.list(CLASS_CALLS, &Query::all())?;
        let broken = history.dir().join(&files[0].rel);
        let mut bytes = std::fs::read(&broken)?;
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&broken, bytes)?;
        let answer = history.answer(&Query::all(), &files, Vec::<IntakeRecord>::new());
        assert_eq!(
            answer
                .refused
                .iter()
                .map(|(file, _)| file.as_str())
                .collect::<Vec<&str>>(),
            [files[0].rel.as_str()],
            "failure the changed file is named"
        );
        assert!(
            answer.refused[0].1.contains("sealed layer") && !answer.refused[0].1.contains("date="),
            "failure with the sealed layer's reason and no path in it: {}",
            answer.refused[0].1
        );
        assert_eq!(
            answer.rows.iter().map(|r| r.seq).collect::<Vec<u64>>(),
            [1, 1, 1],
            "failure and the other file's rows are answered"
        );
        Ok(())
    }

    #[test]
    fn failure_filing_stops_when_an_old_file_that_may_hold_the_rows_cannot_be_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1)])?;
        let old = tree(history.dir())?.remove(0);
        std::fs::write(history.dir().join(&old), b"not sealed")?;
        let again = history.file(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)]);
        assert!(
            again.as_ref().is_err_and(|e| e.contains("member=edge-a")),
            "failure the rows are not filed beside a file that may hold them: {again:?}"
        );
        assert_eq!(
            tree(history.dir())?,
            [old],
            "failure and no file was written"
        );
        Ok(())
    }

    #[test]
    fn failure_filing_stops_when_a_shared_file_that_may_hold_the_rows_cannot_be_read() -> TestResult
    {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let held = tree(history.dir())?.remove(0);
        std::fs::write(history.dir().join(&held), b"not sealed")?;
        let again = history.file(&fleet_calls(3, 1000, 1));
        assert!(
            again.as_ref().is_err_and(|e| e.contains("sealed layer")),
            "failure the rows are not filed twice when the file cannot say: {again:?}"
        );
        assert_eq!(
            tree(history.dir())?.len(),
            1,
            "failure and no file was written"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_that_is_not_the_stores_in_a_day_is_left_when_it_expires() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let notes = history.dir().join("calls/date=2026-11-11/notes.txt");
        std::fs::write(&notes, b"kept")?;
        let expired = history.expire_before(CLASS_CALLS, at_ms(DAY).date_naive())?;
        assert_eq!(
            (expired.days, expired.files),
            (0, 1),
            "failure the store's file went and the day stays"
        );
        assert_eq!(
            expired.left,
            ["calls/date=2026-11-11/notes.txt: not a file of the store"],
            "failure the other file is named"
        );
        assert!(notes.exists(), "failure and is still there");
        Ok(())
    }

    #[test]
    fn failure_a_shared_file_under_another_key_is_not_read() -> TestResult {
        let (dir, history) = store()?;
        history.file(&fleet_beats(3, 1000, 1))?;
        let other = History::reader(&dir.path().join("center.store"), keys(2));
        let files = other.list(CLASS_MEMBERS, &Query::all())?;
        let answer = other.answer(&Query::all(), &files, Vec::<MemberRecord>::new());
        assert_eq!(
            (answer.rows.len(), answer.refused.len(), answer.files_read),
            (0, 1, 0),
            "failure no row without the key, and the file is reported"
        );
        Ok(())
    }

    #[test]
    fn failure_the_rebuild_reports_a_file_it_cannot_read_and_goes_on() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1)])?;
        history.file(&[beat("edge-a", 2000, 2)])?;
        let newest = &history.list(CLASS_MEMBERS, &Query::all())?[0].rel;
        std::fs::write(history.dir().join(newest), b"not sealed")?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 100)?;
        assert_eq!(
            found
                .refused
                .iter()
                .map(|(file, _)| file)
                .collect::<Vec<&String>>(),
            [newest],
            "failure the file is named"
        );
        assert_eq!(
            found
                .members
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [1],
            "failure and the member is taken from the file before it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_day_that_is_a_file_fails_the_filing() -> TestResult {
        let (_dir, history) = store()?;
        std::fs::create_dir_all(history.dir().join("calls"))?;
        std::fs::write(history.dir().join("calls/date=2026-11-11"), b"")?;
        let filed = history.file(&fleet_calls(3, 1000, 1));
        assert!(
            filed
                .as_ref()
                .is_err_and(|e| e.contains("the history store: calls/date=2026-11-11")),
            "failure the day is named: {filed:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_rebuild_bound_of_no_files_reads_none_and_says_how_many() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1)])?;
        history.file(&[beat("edge-a", 2000, 2)])?;
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 0)?;
        assert_eq!(
            (found.members.len(), found.files_read, found.files_not_read),
            (0, 0, 2),
            "failure nothing is restored and both files are counted as not read"
        );
        Ok(())
    }

    #[test]
    fn edge_filing_the_same_rows_of_many_members_again_writes_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(200, 1000, 1))?;
        let again = history.file(&fleet_calls(200, 1000, 1))?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (0, 0, 200),
            "edge a replay of a filed intake files nothing"
        );
        assert_eq!(tree(history.dir())?.len(), 1, "edge one file stays one");
        Ok(())
    }

    #[test]
    fn edge_rows_release_0_5_249_filed_are_not_filed_again() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)])?;
        let again = history.file(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)])?;
        assert_eq!(
            (again.files, again.rows, again.already),
            (0, 0, 2),
            "edge an intake that the old release filed and did not empty is not filed twice"
        );
        Ok(())
    }

    #[test]
    fn edge_a_replay_with_some_rows_in_an_old_file_files_only_the_rest() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-a", 2000, 2)])?;
        let filed = history.file(&[
            call("edge-a", 1000, 1),
            call("edge-a", 2000, 2),
            call("edge-a", 3000, 3),
            call("edge-b", 1000, 1),
        ])?;
        assert_eq!(
            (filed.files, filed.rows, filed.already),
            (1, 2, 2),
            "edge the two rows no file holds go into one shared file"
        );
        let answer = ask::<IntakeRecord>(&history, &Query::all())?;
        assert_eq!(answer.rows.len(), 4, "edge and every row is answered once");
        Ok(())
    }

    #[test]
    fn edge_two_members_with_the_same_stream_and_position_are_two_rows() -> TestResult {
        let (_dir, history) = store()?;
        let filed = history.file(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)])?;
        assert_eq!(
            (filed.rows, filed.already),
            (2, 0),
            "edge neither is the other's duplicate within a filing"
        );
        let later = history.file(&[call("edge-c", 1000, 1), call("edge-b", 1000, 1)])?;
        assert_eq!(
            (later.rows, later.already),
            (1, 1),
            "edge and against a file, only the same member's row is held already"
        );
        Ok(())
    }

    #[test]
    fn edge_heartbeats_of_two_members_at_one_count_and_time_are_both_kept() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1)])?;
        let filed = history.file(&[beat("edge-b", 1000, 1), beat("edge-a", 1000, 1)])?;
        assert_eq!(
            (filed.rows, filed.already),
            (1, 1),
            "edge the other member's heartbeat of the same count and instant is a new row"
        );
        let answer = ask::<MemberRecord>(&history, &Query::all())?;
        assert_eq!(answer.rows.len(), 2, "edge one row for each member");
        Ok(())
    }

    #[test]
    fn edge_two_filings_of_the_same_millisecond_are_two_files() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[call("edge-a", 1000, 1)])?;
        let second = history.file(&[call("edge-b", 1000, 1)])?;
        assert_eq!(second.files, 1, "edge the second filing is not refused");
        let files = tree(history.dir())?;
        assert_eq!(
            files.len(),
            2,
            "edge two files of the same times: {files:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_staged_file_in_a_day_is_removed_at_open() -> TestResult {
        let (dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let staged = history.dir().join(
            "calls/date=2026-11-11/.1794355209000-1794355209000-h0123456789abcdef.sealed.partial",
        );
        std::fs::write(&staged, b"half")?;
        let again = History::open(&dir.path().join("center.store"), keys(1))?;
        assert!(
            !staged.exists(),
            "edge a stopped write's staged file is gone"
        );
        assert_eq!(tree(again.dir())?.len(), 1, "edge and the filed file stays");
        Ok(())
    }

    #[test]
    fn edge_the_rebuild_stops_at_its_file_bound() -> TestResult {
        let (_dir, history) = store()?;
        for n in 0..10 {
            history.file(&[beat(&id(n), i64::try_from(n)? * 60_000, 1)])?;
        }
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &BTreeMap::new(), 3)?;
        assert_eq!(
            (found.files_read, found.files_not_read),
            (3, 7),
            "edge three files are opened and seven are counted as not read"
        );
        let mut got: Vec<String> = found.members.iter().map(|r| r.member.clone()).collect();
        got.sort();
        assert_eq!(
            got,
            [id(7), id(8), id(9)],
            "edge the members of the three newest files"
        );
        Ok(())
    }

    #[test]
    fn edge_the_rebuild_reads_nothing_when_the_store_file_is_newer() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1), beat("edge-b", 1000, 1)])?;
        history.file(&[beat("edge-a", 2000, 2), beat("edge-c", 2000, 1)])?;
        let known = BTreeMap::from([
            ("edge-a".to_string(), at_ms(5000)),
            ("edge-b".to_string(), at_ms(1000)),
        ]);
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &known, 100)?;
        assert_eq!(
            (found.members.len(), found.files_read, found.files_not_read),
            (0, 0, 0),
            "edge every file ends before the newest heartbeat the store file names: none is \
             opened, also for a member that has been silent"
        );
        Ok(())
    }

    #[test]
    fn edge_the_rebuild_stops_when_every_named_member_has_a_row() -> TestResult {
        let (_dir, history) = store()?;
        for (ms, count) in [(1000, 1), (2000, 2), (3000, 3)] {
            history.file(&[beat("edge-a", ms, count), beat("edge-b", ms, count)])?;
        }
        let known = BTreeMap::from([
            ("edge-a".to_string(), at_ms(500)),
            ("edge-b".to_string(), at_ms(500)),
        ]);
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &known, 100)?;
        assert_eq!(
            found.files_read, 1,
            "edge the newest file holds both named members: the two before it stay closed"
        );
        assert_eq!(
            found
                .members
                .iter()
                .map(|r| r.heartbeats)
                .collect::<Vec<u64>>(),
            [3, 3],
            "edge with the newest heartbeat of each"
        );
        Ok(())
    }

    #[test]
    fn edge_the_rebuild_reads_back_to_a_named_member_that_an_older_file_holds() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1), beat("edge-b", 1000, 1)])?;
        history.file(&[beat("edge-a", 2000, 2), beat("edge-b", 2000, 2)])?;
        history.file(&[beat("edge-a", 3000, 3)])?;
        let known = BTreeMap::from([
            ("edge-a".to_string(), at_ms(500)),
            ("edge-b".to_string(), at_ms(500)),
        ]);
        let found = history.newest_heartbeats(at_ms(0).date_naive(), &known, 100)?;
        let mut got: Vec<(String, u64)> = found
            .members
            .iter()
            .map(|r| (r.member.clone(), r.heartbeats))
            .collect();
        got.sort();
        assert_eq!(
            (got, found.files_read),
            (
                vec![("edge-a".to_string(), 3), ("edge-b".to_string(), 2)],
                2
            ),
            "edge the second file is opened for the member the newest does not hold, and \
             the third is not"
        );
        Ok(())
    }

    #[test]
    fn edge_the_rebuild_does_not_pass_the_retention_edge() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[beat("edge-a", 1000, 1)])?;
        history.file(&[beat("edge-b", 2 * DAY, 1)])?;
        let found = history.newest_heartbeats(at_ms(DAY).date_naive(), &BTreeMap::new(), 100)?;
        assert_eq!(
            found
                .members
                .iter()
                .map(|r| r.member.as_str())
                .collect::<Vec<&str>>(),
            ["edge-b"],
            "edge a day before the oldest kept day is not read"
        );
        assert_eq!(
            (found.files_read, found.files_not_read),
            (1, 0),
            "edge and its file is not counted as left unread"
        );
        Ok(())
    }

    #[test]
    fn edge_call_records_after_an_instant_stop_at_the_file_bound() -> TestResult {
        let (_dir, history) = store()?;
        for (ms, seq) in [(1000, 1), (2000, 2), (3000, 3)] {
            history.file(&[call("edge-a", ms, seq)])?;
        }
        let since = BTreeMap::from([("edge-a".to_string(), at_ms(0))]);
        let found = history.calls_after(&since, 2)?;
        assert_eq!(
            (found.files_read, found.files_not_read),
            (2, 1),
            "edge two files are opened and one is counted"
        );
        assert_eq!(
            found.rows.iter().map(|r| r.seq).collect::<Vec<u64>>(),
            [2, 3],
            "edge the records of the two newest files, oldest first"
        );
        Ok(())
    }

    #[test]
    fn edge_no_member_asked_for_reads_no_call_record_file() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        let found = history.calls_after(&BTreeMap::new(), 100)?;
        assert_eq!(
            (found.rows.len(), found.files_read, found.files_not_read),
            (0, 0, 0),
            "edge nothing to look for opens nothing"
        );
        Ok(())
    }

    #[test]
    fn edge_the_bound_of_a_question_counts_files_of_both_layouts() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-b", 1000, 1)])?;
        history.file(&[call("edge-a", 2000, 2)])?;
        history.file(&[call("edge-a", 3000, 3)])?;
        let files = history.list(CLASS_CALLS, &Query::all())?;
        let answer = history.answer_within(&Query::all(), &files, Vec::<IntakeRecord>::new(), 3);
        assert_eq!(
            (files.len(), answer.files_read, answer.files_not_read),
            (4, 3, 1),
            "edge four files, three opened, one counted as not read"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_question_with_a_window_lists_only_the_days_of_the_window() -> TestResult {
        let (_dir, history) = store()?;
        for day in 0..3 {
            history.file(&fleet_calls(4, day * DAY + 1000, 1 + day as u64))?;
        }
        let query = Query {
            from: Some(at_ms(DAY)),
            to: Some(at_ms(DAY + 60_000)),
            ..of(&id(2))
        };
        let files = history.list(CLASS_CALLS, &query)?;
        assert_eq!(files.len(), 1, "edge one day's file of three");
        assert!(
            files[0].rel.starts_with("calls/date=2026-11-12/") && files[0].member.is_none(),
            "edge the day of the window, a shared file: {files:?}"
        );
        Ok(())
    }

    /// A day the window rules out is not read at all: its directory is
    /// closed to the test's user, and the listing still answers. A user
    /// that reads any directory (root) cannot see the difference, and the
    /// test then asserts nothing.
    #[cfg(unix)]
    #[test]
    fn edge_a_day_outside_the_window_is_not_opened() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, history) = store()?;
        history.file(&fleet_calls(3, 1000, 1))?;
        history.file(&fleet_calls(3, DAY + 1000, 2))?;
        let closed = history.dir().join("calls/date=2026-11-11");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))?;
        let can_read_anyway = std::fs::read_dir(&closed).is_ok();
        let query = Query {
            from: Some(at_ms(DAY)),
            ..Query::all()
        };
        let listed = history.list(CLASS_CALLS, &query);
        let all = history.list(CLASS_CALLS, &Query::all());
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))?;
        if can_read_anyway {
            return Ok(());
        }
        assert!(
            listed.as_ref().is_ok_and(|files| files.len() == 1),
            "edge the window's day is listed without a look into the day before it: {listed:?}"
        );
        assert!(
            all.is_err(),
            "edge and a question with no window does need that day"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_no_row_group_can_hold_decodes_none() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(500, 1000, 1))?;
        let answer = ask::<IntakeRecord>(&history, &of("zulu"))?;
        assert_eq!(
            (
                answer.rows.len(),
                answer.files_read,
                answer.groups,
                answer.groups_read
            ),
            (0, 1, 4, 0),
            "edge the file is opened and none of its four row groups is decoded"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_inside_a_groups_range_that_has_no_row_answers_nothing() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&[call("edge-a", 1000, 1), call("edge-c", 1000, 1)])?;
        let answer = ask::<IntakeRecord>(&history, &of("edge-b"))?;
        assert_eq!(
            (answer.rows.len(), answer.groups_read),
            (0, 1),
            "edge the statistics cannot rule the group out; its rows are read and none answers"
        );
        Ok(())
    }

    #[test]
    fn edge_the_first_and_the_last_member_of_a_file_are_each_in_one_group() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&fleet_calls(1000, 1000, 1))?;
        for member in [id(0), id(127), id(128), id(999)] {
            let answer = ask::<IntakeRecord>(&history, &of(&member))?;
            assert_eq!(
                (answer.rows.len(), answer.groups, answer.groups_read),
                (1, 8, 1),
                "edge member {member} at a group's edge is found in one group of eight"
            );
        }
        Ok(())
    }

    /// What the layout costs for a fleet: one filing of heartbeats, one
    /// member's history over many filings, the rebuild at a start, and one
    /// filing of call records with a one-member question. The sizes here
    /// are small. The numbers in the pull request that made the layout
    /// came from this test with 2,000 members, 1,440 filings (24 hours at
    /// 60 seconds) and 20,000 call records in the line below.
    #[test]
    fn edge_the_layout_is_measured_for_a_fleet() -> TestResult {
        let (members, filings, calls) = (200, 12, 2000);
        let (_dir, history) = store()?;
        // A heartbeat whose inventory differs from member to member and
        // from filing to filing, about 300 bytes of JSON, so the size of a
        // file is not that of one value repeated.
        let fleet_beats = |members: usize, ms: i64, count: u64| -> Vec<MemberRecord> {
            fleet_beats(members, ms, count)
                .into_iter()
                .enumerate()
                .map(|(n, mut row)| {
                    row.inventory = serde_json::json!({
                        "host": format!("edge-{n:04}.example.com"),
                        "version": "0.5.249",
                        "uptime_secs": count * 60 + n as u64,
                        "interfaces": [
                            {"name": "eth0", "addr": format!("192.0.2.{}", n % 250), "packets": count * 7919 + n as u64},
                            {"name": "eth1", "addr": format!("2001:db8::{n:x}"), "packets": count * 104_729 + n as u64},
                        ],
                        "dialogs": n * 3 + count as usize,
                        "streams": n * 5 + count as usize,
                    });
                    row
                })
                .collect()
        };
        let bytes_of = |class: &str| -> Result<u64, Box<dyn std::error::Error>> {
            let mut bytes = 0;
            for file in history.list(class, &Query::all())? {
                bytes += std::fs::metadata(history.dir().join(&file.rel))?.len();
            }
            Ok(bytes)
        };

        let started = std::time::Instant::now();
        let filed = history.file(&fleet_beats(members, 0, 1))?;
        let wrote = started.elapsed();
        assert_eq!(
            (filed.files, filed.rows),
            (1, members),
            "edge one filing of every member's heartbeat is one file"
        );
        let one_file = bytes_of(CLASS_MEMBERS)?;
        let started = std::time::Instant::now();
        for filing in 1..filings {
            let ms = i64::try_from(filing)? * 60_000;
            history.file(&fleet_beats(members, ms, 1 + filing as u64))?;
        }
        let wrote_rest = started.elapsed();
        let files = history.list(CLASS_MEMBERS, &Query::all())?;
        assert_eq!(files.len(), filings, "edge one file for each filing");

        let query = Query {
            limit: MAX_LIMIT,
            ..of(&id(members / 2))
        };
        let started = std::time::Instant::now();
        let listed = history.list(CLASS_MEMBERS, &query)?;
        let answer = history.answer(&query, &listed, Vec::<MemberRecord>::new());
        let asked = started.elapsed();
        // One answer holds at most `MAX_LIMIT` rows, and the reading stops
        // one file after the file that gave the last of them.
        let opened = filings.min(MAX_LIMIT + 1);
        assert_eq!(
            (answer.rows.len(), answer.files_read, answer.groups_read),
            (filings.min(MAX_LIMIT), opened, opened),
            "edge the member's heartbeats, from one row group of each file opened"
        );

        let started = std::time::Instant::now();
        let lost = history.newest_heartbeats(
            at_ms(0).date_naive(),
            &BTreeMap::new(),
            MAX_FILES_PER_QUESTION,
        )?;
        let rebuilt_lost = started.elapsed();
        assert_eq!(
            (lost.members.len(), lost.files_read),
            (members, filings),
            "edge with no store file, every file is read and every member found"
        );
        // The store file holds each member's newest heartbeat, and the
        // newest of them is the last row of the newest file.
        let last_ms = i64::try_from(filings - 1)? * 60_000 + i64::try_from((members - 1) % 1000)?;
        let known: BTreeMap<String, DateTime<Utc>> =
            (0..members).map(|n| (id(n), at_ms(last_ms))).collect();
        let started = std::time::Instant::now();
        let kept =
            history.newest_heartbeats(at_ms(0).date_naive(), &known, MAX_FILES_PER_QUESTION)?;
        let rebuilt_kept = started.elapsed();
        assert_eq!(
            (kept.members.len(), kept.files_read),
            (0, 1),
            "edge with the store file, the newest file is read and nothing is taken"
        );
        stderr_line!(
            "fleet layout measurement, heartbeats: {members} members x 1 heartbeat = 1 file, \
             {one_file} B, write {wrote:?}; {filings} filings = {} files, {} B, write \
             {wrote_rest:?} for the other {}; one member's history over them: {} files opened, \
             {} of {} row groups decoded, {asked:?}; rebuild without a store file: {} files \
             read, {rebuilt_lost:?}; rebuild with the store file: {} file read, {rebuilt_kept:?}",
            files.len(),
            bytes_of(CLASS_MEMBERS)?,
            filings - 1,
            answer.files_read,
            answer.groups_read,
            answer.groups,
            lost.files_read,
            kept.files_read
        );

        let per_member = calls / members;
        let rows: Vec<IntakeRecord> = (0..calls)
            .map(|n| {
                let mut row = call(
                    &id(n % members),
                    i64::try_from(n % 60_000).unwrap_or(0),
                    n as u64,
                );
                row.call = serde_json::json!({
                    "call_id": format!("call-{n}@example.com"),
                    "from": "sip:+12025550101@example.com",
                    "to": "sip:+12025550102@example.com",
                    "detail": "x".repeat(1100),
                });
                row
            })
            .collect();
        let started = std::time::Instant::now();
        let filed = history.file(&rows)?;
        let wrote = started.elapsed();
        assert_eq!(
            (filed.files, filed.rows),
            (1, calls),
            "edge one filing of call records is one file"
        );
        let query = Query {
            limit: MAX_LIMIT,
            ..of(&id(members / 2))
        };
        let started = std::time::Instant::now();
        let listed = history.list(CLASS_CALLS, &query)?;
        let answer = history.answer(&query, &listed, Vec::<IntakeRecord>::new());
        let asked = started.elapsed();
        assert_eq!(
            (answer.rows.len(), answer.files_read, answer.groups_read),
            (per_member, 1, 1),
            "edge the member's call records, from one row group"
        );
        stderr_line!(
            "fleet layout measurement, call records: {calls} records of about 1.3 kB over \
             {members} members = 1 file, {} B, write {wrote:?}; one member's records: 1 file \
             opened, {} of {} row groups decoded, {asked:?}",
            bytes_of(CLASS_CALLS)?,
            answer.groups_read,
            answer.groups
        );
        Ok(())
    }

    #[test]
    fn edge_an_old_layout_file_of_one_member_keeps_its_row_group_pruning() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&[call("edge-a", 1000, 1), call("edge-a", 2000, 2)])?;
        let query = Query {
            from: Some(at_ms(5000)),
            ..of("edge-a")
        };
        let rel = history.list(CLASS_CALLS, &of("edge-a"))?[0].rel.clone();
        let read = history.read::<IntakeRecord>(&rel, &query)?;
        assert_eq!(
            (read.rows.len(), read.groups, read.groups_read),
            (0, 1, 0),
            "edge a window after the file's rows rules its group out by the receive times"
        );
        Ok(())
    }
}
