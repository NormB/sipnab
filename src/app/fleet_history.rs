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
//! `calls/date=YYYY-MM-DD/member=<id>/<first>-<last>-<stream>-<seq>.sealed`.
//! The date is the UTC day the center received the rows on, `<first>` and
//! `<last>` are the earliest and the latest receive time in the file in
//! milliseconds, and `<stream>-<seq>` is the file's first row. A question
//! for one member, one day or one hour opens only the files whose path
//! says they can hold an answer ([`Query::wants_partition`],
//! [`Query::wants_file`]).
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
//! # Files are written once
//!
//! [`History::file`] writes a new file for each day and member that has
//! rows; it never changes a file. The center calls it with every row of
//! its intake and then empties the intake. When the center stops between
//! the two, the next start files the same rows again: rows a file of the
//! same day and member already holds are left out ([`without_stored`]),
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

use super::fleet_center::is_valid_id;
use super::fleet_intake::IntakeRecord;
use super::fleet_seal::{Keys, Kind};

/// The directory of the data class this module files: call records.
pub const CLASS_CALLS: &str = "calls";

/// The rows of one Parquet row group. A question reads only the row groups
/// whose statistics and Call-ID filter say they can hold an answer.
pub const ROWS_PER_GROUP: usize = 10_000;

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
const SCHEMA: &str = "message call {
    required int64 received_at (TIMESTAMP(NANOS,true));
    required binary member (STRING);
    required binary stream (STRING);
    required int64 seq (INTEGER(64,false));
    required binary sent_at (STRING);
    required binary selected_by (STRING);
    required binary call_id (STRING);
    required binary call (JSON);
}";

/// The column of the receive time in [`SCHEMA`].
const COL_RECEIVED_AT: usize = 0;

/// The column of the Call-ID in [`SCHEMA`].
const COL_CALL_ID: usize = 6;

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
pub fn received_ns(record: &IntakeRecord) -> Result<i64, String> {
    let at = record.received_at;
    if at < DateTime::<Utc>::UNIX_EPOCH {
        return Err(format!(
            "a call record of member '{}' was received at {at}, before 1970; the history store \
             keeps no such row",
            record.member
        ));
    }
    at.timestamp_nanos_opt().ok_or_else(|| {
        format!(
            "a call record of member '{}' was received at {at}, past the year 2262; the \
             history store keeps no such row",
            record.member
        )
    })
}

/// When the center received `record`, in milliseconds since 1970.
fn received_ms(record: &IntakeRecord) -> Result<u64, String> {
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
    pub fn of(record: &IntakeRecord) -> Self {
        Self {
            date: record.received_at.date_naive(),
            member: record.member.clone(),
        }
    }

    /// The partition's directory under the history directory, with `/`
    /// between its parts.
    #[must_use]
    pub fn rel_dir(&self) -> String {
        format!(
            "{CLASS_CALLS}/{DATE_PREFIX}{}/{MEMBER_PREFIX}{}",
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
    pub fn of(rows: &[IntakeRecord]) -> Result<Self, String> {
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
            stream: first.stream.clone(),
            seq: first.seq,
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

/// The rows of `records` by partition, each partition's rows in the order
/// they came in.
#[must_use]
pub fn groups(records: &[IntakeRecord]) -> BTreeMap<Partition, Vec<IntakeRecord>> {
    let mut out: BTreeMap<Partition, Vec<IntakeRecord>> = BTreeMap::new();
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

    /// Whether a file named `name` can hold an answer.
    #[must_use]
    pub fn wants_file(&self, name: &FileName) -> bool {
        // A name's times are whole milliseconds, rounded down, so a file is
        // ruled out only when every time it can hold is outside the window.
        self.from
            .is_none_or(|from| i128::from(name.last_ms) >= i128::from(from.timestamp_millis()))
            && self
                .to
                .is_none_or(|to| i128::from(name.first_ms) <= i128::from(to.timestamp_millis()))
    }

    /// Whether `record` is an answer.
    #[must_use]
    pub fn wants_row(&self, record: &IntakeRecord) -> bool {
        self.member
            .as_ref()
            .is_none_or(|member| *member == record.member)
            && self.from.is_none_or(|from| record.received_at >= from)
            && self.to.is_none_or(|to| record.received_at < to)
            && self
                .call_id
                .as_ref()
                .is_none_or(|call_id| call_id == call_id_of(record))
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
pub fn encode(rows: &[IntakeRecord]) -> Result<Vec<u8>, String> {
    encode_grouped(rows, ROWS_PER_GROUP)
}

/// [`encode`] with `per_group` rows to a row group.
fn encode_grouped(rows: &[IntakeRecord], per_group: usize) -> Result<Vec<u8>, String> {
    use parquet::file::properties::{EnabledStatistics, WriterProperties};
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::types::ColumnPath;
    if rows.is_empty() {
        return Err("no rows: a file holds at least one".to_string());
    }
    let schema = parquet::schema::parser::parse_message_type(SCHEMA).map_err(parquet_error)?;
    let properties = WriterProperties::builder()
        .set_created_by("sipnab".to_string())
        .set_statistics_enabled(EnabledStatistics::Chunk)
        .set_column_bloom_filter_enabled(ColumnPath::from("call_id"), true)
        .build();
    let mut writer = SerializedFileWriter::new(Vec::new(), Arc::new(schema), Arc::new(properties))
        .map_err(parquet_error)?;
    for chunk in rows.chunks(per_group.max(1)) {
        let received = chunk
            .iter()
            .map(received_ns)
            .collect::<Result<Vec<i64>, String>>()?;
        let calls = chunk
            .iter()
            .map(|row| serde_json::to_vec(&row.call).map_err(|e| e.to_string()))
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        let mut group = writer.next_row_group().map_err(parquet_error)?;
        write_longs(&mut group, &received)?;
        write_texts(&mut group, chunk.iter().map(|row| row.member.as_bytes()))?;
        write_texts(&mut group, chunk.iter().map(|row| row.stream.as_bytes()))?;
        let positions: Vec<i64> = chunk
            .iter()
            .map(|row| i64::from_ne_bytes(row.seq.to_ne_bytes()))
            .collect();
        write_longs(&mut group, &positions)?;
        let sent: Vec<String> = chunk.iter().map(|row| sent_text(row.sent_at)).collect();
        write_texts(&mut group, sent.iter().map(String::as_bytes))?;
        write_texts(
            &mut group,
            chunk.iter().map(|row| row.selected_by.as_bytes()),
        )?;
        write_texts(
            &mut group,
            chunk.iter().map(|row| call_id_of(row).as_bytes()),
        )?;
        write_texts(&mut group, calls.iter().map(Vec::as_slice))?;
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

/// The row group being written.
type GroupWriter<'a> = parquet::file::writer::SerializedRowGroupWriter<'a, Vec<u8>>;

/// Write `values` as the next column of `group`, a column of 64-bit
/// numbers.
fn write_longs(group: &mut GroupWriter<'_>, values: &[i64]) -> Result<(), String> {
    let mut column = group
        .next_column()
        .map_err(parquet_error)?
        .ok_or("parquet: the schema has fewer columns than a call record")?;
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
        .ok_or("parquet: the schema has fewer columns than a call record")?;
    column
        .typed::<parquet::data_type::ByteArrayType>()
        .write_batch(&values, None, None)
        .map_err(parquet_error)?;
    column.close().map_err(parquet_error)
}

/// What [`decode`] read.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// The rows that answer the question, in the file's order.
    pub rows: Vec<IntakeRecord>,
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
pub fn decode(bytes: Vec<u8>, query: &Query) -> Result<Decoded, String> {
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
    let expected = parquet::schema::parser::parse_message_type(SCHEMA).map_err(parquet_error)?;
    let found = reader.metadata().file_metadata().schema();
    if *found != expected {
        return Err(
            "parquet: the file's schema is not the call record schema this build reads".to_string(),
        );
    }
    let mut decoded = Decoded {
        rows: Vec::new(),
        groups: reader.num_row_groups(),
        groups_read: 0,
    };
    for index in 0..reader.num_row_groups() {
        let group = reader.get_row_group(index).map_err(parquet_error)?;
        if !may_answer(&*group, query) {
            continue;
        }
        decoded.groups_read += 1;
        let rows = usize::try_from(group.metadata().num_rows())
            .map_err(|_| "parquet: a row group has a negative row count".to_string())?;
        for row in group_rows(&*group, rows)? {
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
fn may_answer(group: &dyn parquet::file::reader::RowGroupReader, query: &Query) -> bool {
    use parquet::file::statistics::Statistics;
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
        group.get_column_bloom_filter(COL_CALL_ID),
    ) && !filter.check(&parquet::data_type::ByteArray::from(call_id.as_str()))
    {
        return false;
    }
    true
}

/// The `rows` rows of the row group `group`.
fn group_rows(
    group: &dyn parquet::file::reader::RowGroupReader,
    rows: usize,
) -> Result<Vec<IntakeRecord>, String> {
    let received = read_longs(group, 0, rows)?;
    let members = read_texts(group, 1, rows)?;
    let streams = read_texts(group, 2, rows)?;
    let positions = read_longs(group, 3, rows)?;
    let sent = read_texts(group, 4, rows)?;
    let selected = read_texts(group, 5, rows)?;
    let calls = read_texts(group, 7, rows)?;
    let text = |column: &[parquet::data_type::ByteArray], row: usize| {
        column[row]
            .as_utf8()
            .map(str::to_string)
            .map_err(|_| format!("parquet: row {} holds text that is not UTF-8", row + 1))
    };
    (0..rows)
        .map(|row| {
            let sent_at = DateTime::parse_from_rfc3339(&text(&sent, row)?)
                .map_err(|_| format!("parquet: row {} has a send time that is no time", row + 1))?
                .with_timezone(&Utc);
            let call = serde_json::from_slice(calls[row].data()).map_err(|e| {
                format!("parquet: row {} has a call that is not JSON: {e}", row + 1)
            })?;
            Ok(IntakeRecord {
                member: text(&members, row)?,
                received_at: DateTime::from_timestamp_nanos(received[row]),
                stream: text(&streams, row)?,
                seq: u64::from_ne_bytes(positions[row].to_ne_bytes()),
                sent_at,
                selected_by: text(&selected, row)?,
                call,
            })
        })
        .collect()
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
/// The sealed layer refuses the file (not a sealed calls file, key not
/// loaded, modified, truncated), or the file was written for another path
/// than `rel`. The message starts with `rel` and names the layer.
pub fn unseal(rel: &str, bytes: &[u8], keys: &Keys) -> Result<Vec<u8>, String> {
    let log = super::fleet_seal::open_log(bytes, keys, Kind::Calls)
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

/// The rows of `rows` that `stored` does not hold, in order. Both are rows
/// of one partition; a row is the same row when its stream, its position
/// and its send time are the same.
#[must_use]
pub fn without_stored(rows: Vec<IntakeRecord>, stored: &[IntakeRecord]) -> Vec<IntakeRecord> {
    let held: BTreeSet<(&str, u64, DateTime<Utc>)> = stored
        .iter()
        .map(|row| (row.stream.as_str(), row.seq, row.sent_at))
        .collect();
    rows.into_iter()
        .filter(|row| !held.contains(&(row.stream.as_str(), row.seq, row.sent_at)))
        .collect()
}

/// The days of `dates` that are past a retention of `days` days on the
/// day `today`: a day is kept while it is at most `days` days old.
#[must_use]
pub fn expired(dates: &[NaiveDate], today: NaiveDate, days: u32) -> Vec<NaiveDate> {
    let oldest_kept = today
        .checked_sub_days(chrono::Days::new(u64::from(days)))
        .unwrap_or(NaiveDate::MIN);
    dates
        .iter()
        .copied()
        .filter(|date| *date < oldest_kept)
        .collect()
}

/// The newest `limit` rows of `rows`, newest first, each row once, and
/// whether there were more.
#[must_use]
pub fn newest(rows: Vec<IntakeRecord>, limit: usize) -> (Vec<IntakeRecord>, bool) {
    let mut rows = rows;
    rows.sort_by(|a, b| {
        b.received_at
            .cmp(&a.received_at)
            .then_with(|| a.member.cmp(&b.member))
            .then_with(|| a.stream.cmp(&b.stream))
            .then_with(|| b.seq.cmp(&a.seq))
            .then_with(|| b.sent_at.cmp(&a.sent_at))
    });
    rows.dedup_by(|a, b| {
        a.member == b.member && a.stream == b.stream && a.seq == b.seq && a.sent_at == b.sent_at
    });
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
    /// What its name says.
    pub name: FileName,
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
pub struct Answer {
    /// The rows, newest first, at most the question's limit.
    pub rows: Vec<IntakeRecord>,
    /// Whether more rows answer the question than were returned.
    pub more: bool,
    /// The files that could not be read, each with the reason.
    pub refused: Vec<(String, String)>,
    /// The files that were opened.
    pub files_read: usize,
}

impl Answer {
    /// The answer as `GET /v1/fleet/calls` returns it.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let refused: Vec<serde_json::Value> = self
            .refused
            .iter()
            .map(|(file, reason)| serde_json::json!({"file": file, "reason": reason}))
            .collect();
        serde_json::json!({
            "calls": self.rows,
            "count": self.rows.len(),
            "more": self.more,
            "complete": self.refused.is_empty(),
            "refused": refused,
            "files_read": self.files_read,
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
        for (_, _, member_dir) in history.member_dirs().map_err(refused)? {
            for (name, is_dir) in names(&member_dir).map_err(refused)? {
                if !is_dir && is_staged(&name) {
                    std::fs::remove_file(member_dir.join(&name)).map_err(refused)?;
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

    /// Every member directory of the store: the day's directory name, the
    /// member's, and the path. Directories under names this module does
    /// not write are included, for the caller to rule out.
    fn member_dirs(&self) -> std::io::Result<Vec<(String, String, PathBuf)>> {
        let class = self.dir.join(CLASS_CALLS);
        let mut out = Vec::new();
        for (date_dir, is_dir) in names(&class)? {
            if !is_dir {
                continue;
            }
            for (member_dir, is_dir) in names(&class.join(&date_dir))? {
                if is_dir {
                    let path = class.join(&date_dir).join(&member_dir);
                    out.push((date_dir.clone(), member_dir, path));
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

    /// File `records`: one new file for each day and member with rows that
    /// no file of that day and member already holds. Every file is on disk
    /// before this returns.
    ///
    /// # Errors
    ///
    /// A row's receive time is refused, a directory or file cannot be
    /// written, or a file that may already hold some of the rows cannot be
    /// read. Files written before the error stay; filing the same records
    /// again leaves their rows out.
    pub fn file(&self, records: &[IntakeRecord]) -> Result<Filed, String> {
        let mut filed = Filed::default();
        for (partition, rows) in groups(records) {
            let rel_dir = partition.rel_dir();
            let dir = self.dir.join(&rel_dir);
            let refused = |e: std::io::Error| format!("the history store: {rel_dir}: {e}");
            let asked = rows.len();
            let earliest = FileName::of(&rows)?.first_ms;
            create_private_dir(&dir).map_err(refused)?;
            // A file whose latest row is not before this group's earliest
            // may hold some of the group: after a stop between filing and
            // emptying the intake, it holds all of it.
            let mut rows = rows;
            for (name, is_dir) in names(&dir).map_err(refused)? {
                let may_hold = !is_dir
                    && FileName::parse(&name).is_some_and(|stored| stored.last_ms >= earliest);
                if may_hold {
                    let stored = self.read(&format!("{rel_dir}/{name}"), &Query::all())?;
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
            let lines = sealed_lines(&rel, &encode(&rows)?, CHUNK_BYTES);
            super::fleet_center::write_sealed_reading(
                &path,
                &self.keys,
                Kind::Calls,
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

    /// The files that can hold an answer to `query`, by their paths alone,
    /// the file with the latest rows first.
    ///
    /// # Errors
    ///
    /// A directory of the store cannot be read.
    pub fn list(&self, query: &Query) -> Result<Vec<Listed>, String> {
        let refused = |e: std::io::Error| format!("the history store: {e}");
        let mut out = Vec::new();
        for (date_dir, member_dir, path) in self.member_dirs().map_err(refused)? {
            let Some(partition) = Partition::parse(&date_dir, &member_dir) else {
                continue;
            };
            if !query.wants_partition(&partition) {
                continue;
            }
            for (file, is_dir) in names(&path).map_err(refused)? {
                if let Some(name) = FileName::parse(&file).filter(|_| !is_dir)
                    && query.wants_file(&name)
                {
                    out.push(Listed {
                        rel: format!("{}/{file}", partition.rel_dir()),
                        name,
                    });
                }
            }
        }
        out.sort_by(|a, b| {
            b.name
                .last_ms
                .cmp(&a.name.last_ms)
                .then_with(|| a.rel.cmp(&b.rel))
        });
        Ok(out)
    }

    /// The rows of the file at `rel` that answer `query`.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the sealed layer refuses it, or its
    /// Parquet does not parse. The message starts with `rel`.
    pub fn read(&self, rel: &str, query: &Query) -> Result<Decoded, String> {
        self.read_io(rel, query).map_err(|e| e.to_string())
    }

    /// [`History::read`], with a file that is absent told apart.
    fn read_io(&self, rel: &str, query: &Query) -> std::io::Result<Decoded> {
        let bytes = match std::fs::read(self.dir.join(rel)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
            Err(e) => return Err(std::io::Error::other(format!("{rel}: {e}"))),
        };
        let parquet = unseal(rel, &bytes, &self.keys).map_err(std::io::Error::other)?;
        decode(parquet, query).map_err(|e| std::io::Error::other(format!("{rel}: {e}")))
    }

    /// Remove the days past a retention of `days` days on the day `today`
    /// ([`expired`]): the files this module wrote in them, and then their
    /// directories.
    ///
    /// # Errors
    ///
    /// The store's directory cannot be read.
    pub fn expire(&self, today: NaiveDate, days: u32) -> Result<Expired, String> {
        let refused = |e: std::io::Error| format!("the history store: {e}");
        let class = self.dir.join(CLASS_CALLS);
        let dated: Vec<(NaiveDate, String)> = names(&class)
            .map_err(refused)?
            .into_iter()
            .filter(|(_, is_dir)| *is_dir)
            .filter_map(|(name, _)| parse_date_dir(&name).map(|date| (date, name)))
            .collect();
        let dates: Vec<NaiveDate> = dated.iter().map(|(date, _)| *date).collect();
        let gone = expired(&dates, today, days);
        let mut out = Expired::default();
        for (_, date_dir) in dated.iter().filter(|(date, _)| gone.contains(date)) {
            let day = class.join(date_dir);
            for (member_dir, is_dir) in names(&day).map_err(refused)? {
                let rel = format!("{CLASS_CALLS}/{date_dir}/{member_dir}");
                if !is_dir {
                    out.left.push(format!("{rel}: not a file of the store"));
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
    pub fn answer(&self, query: &Query, files: &[Listed], waiting: Vec<IntakeRecord>) -> Answer {
        let mut answer = Answer {
            rows: waiting
                .into_iter()
                .filter(|row| query.wants_row(row))
                .collect(),
            more: false,
            refused: Vec::new(),
            files_read: 0,
        };
        let keep = query.limit.saturating_add(1);
        for file in files {
            if answer.rows.len() >= keep {
                // The rows held are the newest `keep` so far. A file whose
                // latest row is older than the oldest of them adds none to
                // the answer, and neither does any file after it.
                let (rows, _) = newest(std::mem::take(&mut answer.rows), keep);
                answer.rows = rows;
                let oldest = answer.rows.last().map(|row| row.received_at);
                if answer.rows.len() >= keep
                    && oldest.is_some_and(|at| {
                        i128::from(file.name.last_ms) < i128::from(at.timestamp_millis())
                    })
                {
                    break;
                }
            }
            match self.read_io(&file.rel, query) {
                Ok(decoded) => {
                    answer.files_read += 1;
                    answer.rows.extend(decoded.rows);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => answer.refused.push((file.rel.clone(), e.to_string())),
            }
        }
        let (rows, more) = newest(answer.rows, query.limit);
        answer.rows = rows;
        answer.more = more;
        answer
    }
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
        let answer = history.answer(query, &history.list(query)?, Vec::new());
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
        let filed = history.file(&rows("edge-a", 1, 3))?;
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
        let listed = history.list(&Query::all())?;
        assert_eq!(listed.len(), 1, "success one file is listed");
        let decoded = history.read(&listed[0].rel, &Query::all())?;
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
        let filed = history.file(&all)?;
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
        let answer = history.answer(&query, &history.list(&query)?, rows("edge-a", 4, 5));
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
        let expired = history.expire(today, 1)?;
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
        history.file(&rows("edge-a", 1, 2))?;
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
        history.file(&rows("edge-a", 1, 3))?;
        history.file(&rows("edge-b", 1, 3))?;
        let bad = tree(history.dir())?.remove(0);
        let path = history.dir().join(&bad);
        let mut bytes = std::fs::read(&path)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let read = history.read(&bad, &Query::all());
        assert!(
            read.as_ref()
                .is_err_and(|e| e.starts_with(&bad) && e.contains("sealed layer")),
            "failure the changed file is refused with its path and the layer: {read:?}"
        );
        let query = limit(100);
        let answer = history.answer(&query, &history.list(&query)?, Vec::new());
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
        history.file(&rows("edge-a", 1, 3))?;
        let from = tree(history.dir())?.remove(0);
        let to = from.replace("member=edge-a", "member=edge-b");
        let target = history.dir().join(&to);
        std::fs::create_dir_all(target.parent().ok_or("a parent")?)?;
        std::fs::rename(history.dir().join(&from), &target)?;
        let got = history.read(&to, &Query::all());
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
        let answer = other.answer(&query, &other.list(&query)?, Vec::new());
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
        history.file(&rows("edge-a", 1, 2))?;
        let notes = history
            .dir()
            .join("calls/date=2026-11-11/member=edge-a/notes.txt");
        std::fs::write(&notes, b"an operator's file")?;
        let expired = history.expire(at_ms(30 * DAY).date_naive(), 1)?;
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
        history.file(&rows("edge-a", 1, 2))?;
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
        history.file(&all)?;
        let by_member = Query {
            member: Some("edge-b".to_string()),
            ..limit(10)
        };
        assert_eq!(
            history.list(&by_member)?.len(),
            1,
            "edge one member: one of three files"
        );
        let by_day = Query {
            from: Some(at_ms(DAY)),
            ..limit(10)
        };
        let listed = history.list(&by_day)?;
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
            history.list(&by_time)?.is_empty(),
            "edge a window before every file's first row: no file"
        );
        Ok(())
    }

    #[test]
    fn edge_names_the_store_did_not_write_are_not_listed() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&rows("edge-a", 1, 2))?;
        let member = history.dir().join("calls/date=2026-11-11/member=edge-a");
        std::fs::write(member.join("notes.txt"), b"x")?;
        std::fs::write(member.join("copy.sealed"), b"x")?;
        std::fs::create_dir_all(history.dir().join("calls/tmp/member=edge-a"))?;
        std::fs::create_dir_all(history.dir().join("calls/date=2026-11-11/other"))?;
        std::fs::write(history.dir().join("calls/readme"), b"x")?;
        assert_eq!(
            history.list(&Query::all())?.len(),
            1,
            "edge only the file the store wrote is listed"
        );
        Ok(())
    }

    #[test]
    fn edge_no_rows_file_nothing_and_an_empty_store_answers_nothing() -> TestResult {
        let (_dir, history) = store()?;
        assert_eq!(
            history.file(&[])?,
            Filed::default(),
            "edge no rows: no file"
        );
        assert!(
            history.list(&Query::all())?.is_empty(),
            "edge an empty store lists nothing"
        );
        assert_eq!(
            history.expire(at_ms(0).date_naive(), 1)?,
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
        let listed = history.list(&query)?;
        std::fs::remove_file(history.dir().join(&listed[0].rel))?;
        let answer = history.answer(&query, &listed, Vec::new());
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
        let listed = history.list(&query)?;
        assert_eq!(listed.len(), 4, "edge four files can hold an answer");
        let answer = history.answer(&query, &listed, Vec::new());
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
        history.file(&rows("edge-a", 1, 2))?;
        let member = history.dir().join("calls/date=2026-11-11/member=edge-a");
        std::fs::write(member.join(".x.sealed.partial"), b"half")?;
        std::fs::create_dir_all(history.dir().join("calls/date=2026-11-11/member=edge-z"))?;
        let expired = history.expire(at_ms(30 * DAY).date_naive(), 1)?;
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
        let listed = history.list(&Query::all())?;
        let bytes = std::fs::metadata(history.dir().join(&listed[0].rel))?.len();
        let started = std::time::Instant::now();
        let all = history.read(&listed[0].rel, &Query::all())?;
        let read_all = started.elapsed();
        assert_eq!(all.rows.len(), 20_000, "edge every row reads back");
        let one = Query {
            call_id: Some("call-15000@example.com".to_string()),
            ..limit(1)
        };
        let started = std::time::Instant::now();
        let found = history.read(&listed[0].rel, &one)?;
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
            partition.rel_dir(),
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
            .map(|(p, rows)| (p.rel_dir(), rows.iter().map(|r| r.seq).collect()))
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
        let got = FileName::of(&[]);
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
            Partition::of(&row("edge-a", day - 1, 1)).rel_dir(),
            "calls/date=2026-11-11/member=edge-a",
            "edge 23:59:59.999 is the day it is in"
        );
        assert_eq!(
            Partition::of(&row("edge-a", day, 1)).rel_dir(),
            "calls/date=2026-11-12/member=edge-a",
            "edge 00:00:00.000 is the next day"
        );
    }

    #[test]
    fn edge_a_member_named_with_dots_stays_one_directory() {
        let partition = Partition::of(&row("..", 0, 1));
        assert_eq!(
            partition.rel_dir(),
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
            .filter(|r| query.wants_row(r))
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
            .filter(|r| query.wants_row(r))
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
        let got = encode(&[]);
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
            unseal(REL, &sealed, &keys(1))?,
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
            unseal(REL, &sealed, &keys(1))?,
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
            unseal(REL, &sealed, &both)?,
            parquet,
            "success a file written under the earlier key opens after a key change"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_under_a_key_that_is_not_loaded_is_refused() -> TestResult {
        let sealed = seal(REL, &encode(&rows(3))?, 1, CHUNK_BYTES)?;
        let got = unseal(REL, &sealed, &keys(2));
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
        let got = unseal(other, &sealed, &keys(1));
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
            let got = unseal(REL, &bad, &keys(1));
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
            let got = unseal(REL, &sealed[..keep], &keys(1));
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
            let got = unseal(REL, &longer, &keys(1));
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
        let got = unseal(REL, &intake, &keys(1));
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("intake") && e.contains("calls")),
            "failure an intake file in a calls file's place: {got:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_clear_parquet_file_in_the_store_is_refused() -> TestResult {
        let got = unseal(REL, &encode(&rows(3))?, &keys(1));
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
        let got = unseal(REL, &empty, &keys(1));
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
            unseal(REL, &sealed, &keys(1))?,
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
            unseal(REL, &sealed, &keys(1))?.len(),
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
        let (none, more) = newest(Vec::new(), 3);
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
