// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet verify`: read every row of every file of a fleet center's
//! history store and report each file that is refused (docs/fleet.md,
//! "Verify the history store").
//!
//! A question to the center builds only the rows it selects, so a file
//! with a row that does not parse is refused only when a question selects
//! that row. This pass selects every row of every file: it reads each
//! file, opens its sealed layer, reads its Parquet footer and codecs,
//! builds every row, and compares the rows with what the file's path
//! says of them (the day, the earliest and latest receive time, and the
//! mark of this layout or the member, stream and position of the layout
//! release 0.5.249 wrote).
//!
//! The pass creates and changes nothing ([`History::reader`]), so it runs
//! beside a running center and on a copy of the store. A file that
//! retention removes between the listing and the read counts as `gone`.
//!
//! Not checked here: a row held by two files, the store file and the
//! intake of call records.
//!
//! [`check_path`], [`Scope`] and [`Report`] work on values. [`check_file`]
//! and [`verify`] read the file system; [`run`] is the command.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};

use super::fleet_center::MemberRecord;
use super::fleet_history::{
    CLASS_CALLS, CLASS_MEMBERS, FileName, History, IntervalName, Listed, Partition, Query, Row,
    parse_date_dir, reason,
};
use super::fleet_intake::IntakeRecord;
use super::fleet_seal::Keys;

/// What a pass reads: the classes, and the days of their directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The classes, in the order they are read and reported.
    pub classes: Vec<&'static str>,
    /// The first day read, when one was given.
    pub from: Option<NaiveDate>,
    /// The last day read, when one was given.
    pub to: Option<NaiveDate>,
}

impl Scope {
    /// The scope of `--class`, `--from` and `--to`: both classes when no
    /// class is named, every day when no day is.
    ///
    /// # Errors
    ///
    /// `class` is not a class of the history store, or `from` is after
    /// `to`.
    pub fn new(
        class: Option<&str>,
        from: Option<NaiveDate>,
        to: Option<NaiveDate>,
    ) -> Result<Self, String> {
        let classes = match class {
            None => vec![CLASS_CALLS, CLASS_MEMBERS],
            Some(CLASS_CALLS) => vec![CLASS_CALLS],
            Some(CLASS_MEMBERS) => vec![CLASS_MEMBERS],
            Some(other) => {
                return Err(format!(
                    "--class {other}: the classes are {CLASS_CALLS} and {CLASS_MEMBERS}"
                ));
            }
        };
        if let (Some(from), Some(to)) = (from, to)
            && from > to
        {
            return Err(format!("--from {from} is after --to {to}"));
        }
        Ok(Self { classes, from, to })
    }

    /// Whether the directory of the day `date` is read.
    #[must_use]
    pub fn wants(&self, date: NaiveDate) -> bool {
        self.from.is_none_or(|from| date >= from) && self.to.is_none_or(|to| date <= to)
    }
}

/// What the check of one file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// Every row was built and agrees with the path: the rows it holds.
    Clean(usize),
    /// The file was not there when it was read: retention removed it
    /// after the listing.
    Gone,
    /// Why the file is refused, without its path: the first reason found.
    Refused(String),
}

/// Compare the rows of the file at `rel` with what its path says of them:
/// the day of its directory, the earliest and the latest receive time in
/// its name and, for a file of this layout, the mark of its rows; for a
/// file release 0.5.249 wrote under `member=<id>`, the member of every row
/// and the stream and position of the first.
///
/// # Errors
///
/// The first disagreement, without the path; or `rel` is not a path the
/// history store writes.
pub fn check_path<R: Row>(rel: &str, rows: &[R]) -> Result<(), String> {
    let parts: Vec<&str> = rel.split('/').collect();
    let (date_dir, under_day) = match parts.as_slice() {
        [_class, date_dir, under_day @ ..] if matches!(under_day.len(), 1 | 2) => {
            (*date_dir, under_day)
        }
        _ => return Err("path: not a path the history store writes".to_string()),
    };
    let day = parse_date_dir(date_dir).ok_or_else(|| format!("path: '{date_dir}' names no day"))?;
    if rows.is_empty() {
        return Err("rows: the file holds no row".to_string());
    }
    for (index, row) in rows.iter().enumerate() {
        let received = row.received_at().date_naive();
        if received != day {
            return Err(format!(
                "rows: row {} was received on {received}, and the file is in the directory of \
                 {day}",
                index + 1
            ));
        }
    }
    let unnamed = |name: &str| format!("path: '{name}' is not a name the history store writes");
    match under_day {
        [name] => {
            let named = IntervalName::parse(name).ok_or_else(|| unnamed(name))?;
            let found = IntervalName::of(rows).map_err(|e| format!("rows: {e}"))?;
            check_span(
                (found.first_ms, found.last_ms),
                (named.first_ms, named.last_ms),
            )?;
            if found.mark != named.mark {
                return Err(format!(
                    "rows: the mark of the rows is h{:016x}, and the name says h{:016x}",
                    found.mark, named.mark
                ));
            }
        }
        [member_dir, name] => {
            let partition = Partition::parse(date_dir, member_dir)
                .ok_or_else(|| format!("path: '{member_dir}' names no member"))?;
            let named = FileName::parse(name).ok_or_else(|| unnamed(name))?;
            if let Some(index) = rows.iter().position(|row| row.member() != partition.member)
                && let Some(row) = rows.get(index)
            {
                return Err(format!(
                    "rows: row {} is of the member '{}', and the file is in the directory of \
                     '{}'",
                    index + 1,
                    row.member(),
                    partition.member
                ));
            }
            let found = FileName::of(rows).map_err(|e| format!("rows: {e}"))?;
            check_span(
                (found.first_ms, found.last_ms),
                (named.first_ms, named.last_ms),
            )?;
            if (found.stream.as_str(), found.seq) != (named.stream.as_str(), named.seq) {
                return Err(format!(
                    "rows: the first row is {}-{}, and the name says {}-{}",
                    found.stream, found.seq, named.stream, named.seq
                ));
            }
        }
        _ => return Err("path: not a path the history store writes".to_string()),
    }
    Ok(())
}

/// Compare the earliest and the latest receive time of a file's rows,
/// `found`, with the two its name states, `named`, in milliseconds.
fn check_span(found: (u64, u64), named: (u64, u64)) -> Result<(), String> {
    if found.0 != named.0 {
        return Err(format!(
            "rows: the earliest row was received at {} ms, and the name says {}",
            found.0, named.0
        ));
    }
    if found.1 != named.1 {
        return Err(format!(
            "rows: the latest row was received at {} ms, and the name says {}",
            found.1, named.1
        ));
    }
    Ok(())
}

/// Read every row of the file at `rel` and compare the rows with the path
/// ([`check_path`]).
#[must_use]
pub fn check_file<R: Row>(history: &History, rel: &str) -> Checked {
    match history.read_io::<R>(rel, &Query::all()) {
        Ok(decoded) => match check_path(rel, &decoded.rows) {
            Ok(()) => Checked::Clean(decoded.rows.len()),
            Err(why) => Checked::Refused(why),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Checked::Gone,
        Err(e) => Checked::Refused(reason(rel, &e)),
    }
}

/// What a pass found in one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassReport {
    /// The class.
    pub class: &'static str,
    /// The files listed.
    pub files: usize,
    /// The files whose every row was built and agrees with the path.
    pub clean: usize,
    /// The files refused.
    pub refused: usize,
    /// The files that were gone when they were read.
    pub gone: usize,
    /// The rows of the clean files.
    pub rows: u64,
}

impl ClassReport {
    /// The report of a class no file of which was read yet.
    #[must_use]
    pub const fn new(class: &'static str) -> Self {
        Self {
            class,
            files: 0,
            clean: 0,
            refused: 0,
            gone: 0,
            rows: 0,
        }
    }
}

/// A file that was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The file's class.
    pub class: &'static str,
    /// The file's path under the history directory.
    pub file: String,
    /// The first reason it was refused for, without the path.
    pub reason: String,
}

impl Refusal {
    /// The line the command prints for this file.
    #[must_use]
    pub fn line(&self) -> String {
        format!("refused: {}: {}", self.file, self.reason)
    }
}

/// What a pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// When the pass started.
    pub started_at: DateTime<Utc>,
    /// The version of the program that ran it.
    pub version: String,
    /// Each class read, in the scope's order.
    pub classes: Vec<ClassReport>,
    /// The files refused, in the order they were read.
    pub refused: Vec<Refusal>,
}

impl Report {
    /// The command's exit status: 0 when no file was refused, 1 when one
    /// was. A file that was gone does not change it.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.refused.is_empty())
    }

    /// One line for each class: its files and what became of them.
    #[must_use]
    pub fn summary_lines(&self) -> Vec<String> {
        self.classes
            .iter()
            .map(|class| {
                format!(
                    "{}: {} files, {} clean, {} refused, {} gone, {} rows",
                    class.class, class.files, class.clean, class.refused, class.gone, class.rows
                )
            })
            .collect()
    }

    /// The report as the JSON `--json` prints.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let classes: Vec<serde_json::Value> = self
            .classes
            .iter()
            .map(|class| {
                serde_json::json!({
                    "class": class.class,
                    "files": class.files,
                    "clean": class.clean,
                    "refused": class.refused,
                    "gone": class.gone,
                    "rows": class.rows,
                })
            })
            .collect();
        let refused: Vec<serde_json::Value> = self
            .refused
            .iter()
            .map(|refusal| {
                serde_json::json!({
                    "class": refusal.class,
                    "file": refusal.file,
                    "reason": refusal.reason,
                })
            })
            .collect();
        serde_json::json!({
            "started_at": self.started_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "version": self.version,
            "result": if self.refused.is_empty() { "clean" } else { "refused" },
            "classes": classes,
            "refused": refused,
        })
    }
}

/// Check the files `listed` of the class `class`, adding to `report` and
/// calling `on_refusal` for each file as it is refused.
pub fn check_listed(
    history: &History,
    class: &'static str,
    listed: &[Listed],
    report: &mut Report,
    on_refusal: &mut dyn FnMut(&Refusal),
) {
    let mut found = ClassReport::new(class);
    for file in listed {
        found.files += 1;
        let checked = if class == CLASS_CALLS {
            check_file::<IntakeRecord>(history, &file.rel)
        } else {
            check_file::<MemberRecord>(history, &file.rel)
        };
        match checked {
            Checked::Clean(rows) => {
                found.clean += 1;
                found.rows = found.rows.saturating_add(rows as u64);
            }
            Checked::Gone => found.gone += 1,
            Checked::Refused(reason) => {
                found.refused += 1;
                let refusal = Refusal {
                    class,
                    file: file.rel.clone(),
                    reason,
                };
                on_refusal(&refusal);
                report.refused.push(refusal);
            }
        }
    }
    report.classes.push(found);
}

/// Read every row of every file of `scope` in `history`.
///
/// # Errors
///
/// The pass cannot run: there is no history directory, or a directory of
/// the store cannot be read.
pub fn verify(
    history: &History,
    scope: &Scope,
    started_at: DateTime<Utc>,
    on_refusal: &mut dyn FnMut(&Refusal),
) -> Result<Report, String> {
    let mut report = Report {
        started_at,
        version: env!("CARGO_PKG_VERSION").to_string(),
        classes: Vec::new(),
        refused: Vec::new(),
    };
    if !history.dir().is_dir() {
        return Err(format!(
            "no history directory '{}': nothing to verify",
            history.dir().display()
        ));
    }
    for class in &scope.classes {
        let listed = history
            .list_days(class, &|date| scope.wants(date))
            .map_err(|e| format!("the history store: {class}: {e}"))?;
        check_listed(history, class, &listed, &mut report, on_refusal);
    }
    Ok(report)
}

/// The arguments of `sipnab fleet verify`.
#[derive(Debug, Clone)]
pub struct VerifyArgs {
    /// `--store`: the center's store file; the history directory is
    /// beside it.
    pub store: PathBuf,
    /// `--store-key-file`.
    pub store_key_file: PathBuf,
    /// `--store-old-key-file`, each one given.
    pub store_old_key_files: Vec<PathBuf>,
    /// `--class`, when given.
    pub class: Option<&'static str>,
    /// `--from`, when given.
    pub from: Option<NaiveDate>,
    /// `--to`, when given.
    pub to: Option<NaiveDate>,
    /// `--json`.
    pub json: bool,
}

/// `sipnab fleet verify`: run the pass `args` asks for, write what it
/// finds to `out` and why it could not run to `err`. Returns the exit
/// status: 0 no file refused, 1 a file refused, 2 the pass could not run.
///
/// `confine` is the step between the key files and the history files: it
/// is called once, with the history directory, after every key file was
/// read and before the directory is listed or a history file is opened.
/// The command drops root there ([`crate::early_exit::confine`]); what it
/// refuses ends the run with exit status 2.
pub fn run(
    args: &VerifyArgs,
    started_at: DateTime<Utc>,
    confine: &mut dyn FnMut(&std::path::Path) -> Result<(), String>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> i32 {
    let pass = Scope::new(args.class, args.from, args.to).and_then(|scope| {
        // The key files, then the step, then the history directory: a run
        // started as root reads a key file only root can read, and lists
        // and opens history files as the user the step dropped to.
        let history = History::reader(&args.store, keys_of(args)?);
        confine(history.dir()).map_err(|refusal| {
            refusal
                .strip_prefix("fleet verify: ")
                .unwrap_or(&refusal)
                .to_string()
        })?;
        let mut print = |refusal: &Refusal| {
            if !args.json {
                let _ = writeln!(out, "{}", refusal.line());
            }
        };
        verify(&history, &scope, started_at, &mut print)
    });
    let report = match pass {
        Ok(report) => report,
        Err(why) => {
            let _ = writeln!(err, "sipnab fleet verify: {why}");
            return 2;
        }
    };
    let written = if args.json {
        writeln!(out, "{}", report.json())
    } else {
        report
            .summary_lines()
            .iter()
            .try_for_each(|line| writeln!(out, "{line}"))
    };
    // A report that could not be written is not a verdict.
    if written.and_then(|()| out.flush()).is_err() {
        return 2;
    }
    report.exit_code()
}

/// The keys of `args`: the current key and every old one.
fn keys_of(args: &VerifyArgs) -> Result<Arc<Keys>, String> {
    use super::fleet_seal::read_key_file;
    let current = read_key_file(&args.store_key_file, "--store-key-file")?;
    let old = args
        .store_old_key_files
        .iter()
        .map(|file| read_key_file(file, "--store-old-key-file"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Arc::new(Keys::new(current, old)))
}

#[cfg(test)]
mod tests {
    //! Tests of `sipnab fleet verify` (`fleet_verify.rs`): the comparison of
    //! a file's rows with its path, the pass over a store, its report and the
    //! command's exit status. Every row is synthetic.

    use super::*;
    use crate::app::fleet_calls::CallCounts;
    use crate::app::fleet_center::{Cursor, write_sealed_reading};
    use crate::app::fleet_history::{
        CHUNK_BYTES, Column, GROUP_ROWS, ROWS_PER_GROUP, codec, encode_with, sealed_lines,
    };
    use crate::app::fleet_seal::{MasterKey, read_key_file, system_draw, write_new_key_file};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// One day in milliseconds.
    const DAY_MS: i64 = 86_400_000;
    /// The directory of the day the rows of these tests are received on.
    const DAY: &str = "date=2026-11-11";
    /// The column of a call record's JSON, and of a heartbeat's inventory.
    const CALL_JSON: usize = 7;
    const BEAT_INVENTORY: usize = 10;

    fn keys(b: u8) -> Arc<Keys> {
        Arc::new(Keys::new(MasterKey::from_bytes([b; 32]), Vec::new()))
    }

    /// 2026-11-11T00:00:00Z plus `ms` milliseconds.
    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_794_355_200_000 + ms)
    }

    fn call(member: &str, ms: i64, seq: u64) -> IntakeRecord {
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

    /// `n` call records of one member, one a second from 00:00:01.
    fn calls(n: u64) -> Vec<IntakeRecord> {
        (1..=n)
            .map(|seq| call("edge-a", i64::try_from(seq).unwrap_or(0) * 1000, seq))
            .collect()
    }

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
            inventory: serde_json::json!({"schema_version": 1, "node_name": member}),
            call_records: count,
            calls: Some(CallCounts {
                selected: count,
                dropped_by_cap: 0,
                left_out: 0,
                spooled: 0,
            }),
        }
    }

    /// One heartbeat of each of `n` members.
    fn beats(n: u64) -> Vec<MemberRecord> {
        (0..n)
            .map(|m| beat(&format!("edge-{m:04}"), i64::try_from(m).unwrap_or(0), 7))
            .collect()
    }

    /// An empty history store under key 1.
    fn store() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let history = History::open(&dir.path().join("center.store"), keys(1))?;
        Ok((dir, history))
    }

    /// The change that changes nothing.
    fn whole(_: usize, _: &mut Vec<Column>) {}

    /// The change that writes `value` as the text of row `row` of column
    /// `column` of the first row group.
    fn spoil(column: usize, row: usize, value: &'static [u8]) -> impl Fn(usize, &mut Vec<Column>) {
        move |group, columns| {
            if group == 0
                && let Some(Column::Texts(values)) = columns.get_mut(column)
                && let Some(slot) = values.get_mut(row)
            {
                *slot = value.to_vec();
            }
        }
    }

    /// The path of the file of this layout that holds `rows` on [`DAY`].
    fn rel_of<R: Row>(rows: &[R]) -> Result<String, String> {
        Ok(format!(
            "{}/{DAY}/{}",
            R::CLASS,
            IntervalName::of(rows)?.text()
        ))
    }

    /// Seal `rows` as the file at `rel`, whatever `rel` says of them.
    fn plant<R: Row>(
        history: &History,
        rel: &str,
        rows: &[R],
        edit: &dyn Fn(usize, &mut Vec<Column>),
    ) -> TestResult {
        let parquet = encode_with(rows, GROUP_ROWS, ROWS_PER_GROUP, codec()?, edit)?;
        let path = history.dir().join(rel);
        std::fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        write_sealed_reading(
            &path,
            &keys(1),
            R::KIND,
            sealed_lines(rel, &parquet, CHUNK_BYTES).into_iter().map(Ok),
            &|staged| std::fs::read(staged),
        )?;
        Ok(())
    }

    fn everything() -> Result<Scope, String> {
        Scope::new(None, None, None)
    }

    fn day(text: &str) -> Result<NaiveDate, chrono::ParseError> {
        NaiveDate::parse_from_str(text, "%Y-%m-%d")
    }

    /// A pass over `history`, with the refused lines as they were called.
    fn pass(history: &History, scope: &Scope) -> Result<(Report, Vec<String>), String> {
        let mut lines = Vec::new();
        let report = verify(history, scope, at_ms(0), &mut |refusal| {
            lines.push(refusal.line());
        })?;
        Ok((report, lines))
    }

    /// The one file of `class`.
    fn one(history: &History, class: &str) -> Result<String, Box<dyn std::error::Error>> {
        let listed = history.list_days(class, &|_| true)?;
        match listed.as_slice() {
            [file] => Ok(file.rel.clone()),
            other => Err(format!("{} files, not one", other.len()).into()),
        }
    }

    /// The report of the class `class`.
    fn of<'a>(report: &'a Report, class: &str) -> Result<&'a ClassReport, String> {
        report
            .classes
            .iter()
            .find(|found| found.class == class)
            .ok_or_else(|| format!("no report of {class}"))
    }

    /// Why `rows` at `rel` are refused.
    fn refused<R: Row>(rel: &str, rows: &[R]) -> Result<String, String> {
        match check_path(rel, rows) {
            Ok(()) => Err(format!("{rel} was not refused")),
            Err(why) => Ok(why),
        }
    }

    /// A store with twenty call records and thirty heartbeats filed.
    fn filed() -> Result<(tempfile::TempDir, History), Box<dyn std::error::Error>> {
        let (dir, history) = store()?;
        history.file(&calls(20))?;
        history.file(&beats(30))?;
        Ok((dir, history))
    }

    /// Every file under `dir`, with its length.
    fn tree(dir: &std::path::Path) -> std::io::Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(&at)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                }
                out.push((
                    entry.path().to_string_lossy().into_owned(),
                    entry.metadata()?.len(),
                ));
            }
        }
        out.sort();
        Ok(out)
    }

    // ---- the rows against the path -------------------------------------

    #[test]
    fn success_call_records_under_their_own_name_are_clean() -> TestResult {
        let rows = calls(20);
        assert_eq!(
            check_path(&rel_of(&rows)?, &rows),
            Ok(()),
            "success twenty call records agree with the name made from them"
        );
        Ok(())
    }

    #[test]
    fn success_heartbeats_under_their_own_name_are_clean() -> TestResult {
        let rows = beats(300);
        assert_eq!(
            check_path(&rel_of(&rows)?, &rows),
            Ok(()),
            "success 300 heartbeats agree with the name made from them"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_of_the_0_5_249_layout_is_clean() -> TestResult {
        let rows = calls(5);
        let rel = format!("calls/{DAY}/member=edge-a/{}", FileName::of(&rows)?.text());
        assert_eq!(
            check_path(&rel, &rows),
            Ok(()),
            "success one member's rows agree with a name of the 0.5.249 layout"
        );
        Ok(())
    }

    #[test]
    fn success_one_row_is_clean() -> TestResult {
        let rows = calls(1);
        assert_eq!(
            check_path(&rel_of(&rows)?, &rows),
            Ok(()),
            "success a file of one row is clean"
        );
        Ok(())
    }

    #[test]
    fn success_rows_at_both_ends_of_the_day_are_clean() -> TestResult {
        let rows = vec![call("edge-a", 0, 1), call("edge-a", DAY_MS - 1, 2)];
        assert_eq!(
            check_path(&rel_of(&rows)?, &rows),
            Ok(()),
            "success the first and the last millisecond of the day belong to it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_row_of_the_next_day_is_refused() -> TestResult {
        let rows = vec![call("edge-a", 1000, 1), call("edge-a", DAY_MS, 2)];
        assert_eq!(
            refused(&rel_of(&rows)?, &rows)?,
            "rows: row 2 was received on 2026-11-12, and the file is in the directory of 2026-11-11",
            "failure the row of the next day is named"
        );
        Ok(())
    }

    #[test]
    fn failure_a_name_with_an_earlier_first_time_is_refused() -> TestResult {
        let rows = calls(3);
        let mut name = IntervalName::of(&rows)?;
        name.first_ms -= 1;
        let why = refused(&format!("calls/{DAY}/{}", name.text()), &rows)?;
        assert_eq!(
            why,
            format!(
                "rows: the earliest row was received at {} ms, and the name says {}",
                name.first_ms + 1,
                name.first_ms
            ),
            "failure the earliest time is compared with the name"
        );
        Ok(())
    }

    #[test]
    fn failure_a_name_with_a_later_last_time_is_refused() -> TestResult {
        let rows = calls(3);
        let mut name = IntervalName::of(&rows)?;
        name.last_ms += 1;
        let why = refused(&format!("calls/{DAY}/{}", name.text()), &rows)?;
        assert_eq!(
            why,
            format!(
                "rows: the latest row was received at {} ms, and the name says {}",
                name.last_ms - 1,
                name.last_ms
            ),
            "failure the latest time is compared with the name"
        );
        Ok(())
    }

    #[test]
    fn failure_a_name_with_another_mark_is_refused() -> TestResult {
        let rows = calls(3);
        let mut name = IntervalName::of(&rows)?;
        let found = name.mark;
        name.mark ^= 1;
        let why = refused(&format!("calls/{DAY}/{}", name.text()), &rows)?;
        assert_eq!(
            why,
            format!(
                "rows: the mark of the rows is h{found:016x}, and the name says h{:016x}",
                name.mark
            ),
            "failure the mark of the rows is compared with the name"
        );
        Ok(())
    }

    #[test]
    fn failure_a_missing_row_changes_the_mark() -> TestResult {
        let rows = calls(4);
        let rel = rel_of(&rows)?;
        // Without a middle row the times of the name still hold.
        let fewer: Vec<IntakeRecord> = rows.iter().filter(|row| row.seq != 2).cloned().collect();
        let why = refused(&rel, &fewer)?;
        assert!(
            why.starts_with("rows: the mark of the rows is h"),
            "failure a file that lost a row is refused by its mark, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_row_of_another_member_in_a_member_directory_is_refused() -> TestResult {
        let mut rows = calls(3);
        let name = FileName::of(&rows)?.text();
        if let Some(row) = rows.get_mut(1) {
            row.member = "edge-b".to_string();
        }
        assert_eq!(
            refused(&format!("calls/{DAY}/member=edge-a/{name}"), &rows)?,
            "rows: row 2 is of the member 'edge-b', and the file is in the directory of 'edge-a'",
            "failure the row of another member is named"
        );
        Ok(())
    }

    #[test]
    fn failure_a_0_5_249_name_with_another_position_is_refused() -> TestResult {
        let rows = calls(3);
        let mut name = FileName::of(&rows)?;
        name.seq = 9;
        assert_eq!(
            refused(&format!("calls/{DAY}/member=edge-a/{}", name.text()), &rows)?,
            "rows: the first row is s-1, and the name says s-9",
            "failure the first row's position is compared with the name"
        );
        Ok(())
    }

    #[test]
    fn failure_a_0_5_249_name_with_another_stream_is_refused() -> TestResult {
        let rows = calls(3);
        let mut name = FileName::of(&rows)?;
        name.stream = "t".to_string();
        assert_eq!(
            refused(&format!("calls/{DAY}/member=edge-a/{}", name.text()), &rows)?,
            "rows: the first row is s-1, and the name says t-1",
            "failure the first row's stream is compared with the name"
        );
        Ok(())
    }

    #[test]
    fn failure_no_row_is_refused() -> TestResult {
        let rel = rel_of(&calls(2))?;
        assert_eq!(
            refused::<IntakeRecord>(&rel, &[])?,
            "rows: the file holds no row",
            "failure a file holds at least one row"
        );
        Ok(())
    }

    #[test]
    fn edge_a_directory_that_names_no_day_is_refused() -> TestResult {
        let rows = calls(2);
        let name = IntervalName::of(&rows)?.text();
        assert_eq!(
            refused(&format!("calls/date=2026-11-1/{name}"), &rows)?,
            "path: 'date=2026-11-1' names no day",
            "edge only the one spelling of a day is a day"
        );
        Ok(())
    }

    #[test]
    fn edge_a_name_the_store_does_not_write_is_refused() -> TestResult {
        let rows = calls(2);
        assert_eq!(
            refused(&format!("calls/{DAY}/notes.sealed"), &rows)?,
            "path: 'notes.sealed' is not a name the history store writes",
            "edge a name that states no times is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_a_path_that_is_too_deep_is_refused() -> TestResult {
        let rows = calls(2);
        let name = FileName::of(&rows)?.text();
        assert_eq!(
            refused(&format!("calls/{DAY}/member=edge-a/more/{name}"), &rows)?,
            "path: not a path the history store writes",
            "edge a file two directories under the day is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_a_member_directory_that_names_no_member_is_refused() -> TestResult {
        let rows = calls(2);
        let name = FileName::of(&rows)?.text();
        assert_eq!(
            refused(&format!("calls/{DAY}/who=edge-a/{name}"), &rows)?,
            "path: 'who=edge-a' names no member",
            "edge only `member=<id>` is a member directory"
        );
        Ok(())
    }

    #[test]
    fn edge_the_day_is_compared_before_the_name() -> TestResult {
        let rows = vec![call("edge-a", DAY_MS + 5, 1)];
        let mut name = IntervalName::of(&rows)?;
        name.mark ^= 1;
        let why = refused(&format!("calls/{DAY}/{}", name.text()), &rows)?;
        assert!(
            why.starts_with("rows: row 1 was received on 2026-11-12"),
            "edge the first disagreement is the one reported, got: {why}"
        );
        Ok(())
    }

    #[test]
    fn edge_the_order_of_the_rows_does_not_change_the_verdict() -> TestResult {
        let rows = calls(6);
        let rel = rel_of(&rows)?;
        let turned: Vec<IntakeRecord> = rows.into_iter().rev().collect();
        assert_eq!(
            check_path(&rel, &turned),
            Ok(()),
            "edge the mark and the times do not depend on the order of the rows"
        );
        Ok(())
    }

    // ---- the scope ------------------------------------------------------

    #[test]
    fn success_no_class_means_both_in_order() -> TestResult {
        assert_eq!(
            everything()?.classes,
            vec!["calls", "members"],
            "success both classes are read, call records first"
        );
        Ok(())
    }

    #[test]
    fn success_from_and_to_include_their_days() -> TestResult {
        let scope = Scope::new(None, Some(day("2026-11-10")?), Some(day("2026-11-12")?))?;
        let wanted: Vec<bool> = [
            "2026-11-09",
            "2026-11-10",
            "2026-11-11",
            "2026-11-12",
            "2026-11-13",
        ]
        .iter()
        .map(|text| day(text).map(|date| scope.wants(date)))
        .collect::<Result<_, _>>()?;
        assert_eq!(
            wanted,
            vec![false, true, true, true, false],
            "success the first and the last day are read, the days outside are not"
        );
        Ok(())
    }

    #[test]
    fn failure_from_after_to_is_refused() -> TestResult {
        let why = Scope::new(None, Some(day("2026-11-12")?), Some(day("2026-11-11")?))
            .err()
            .ok_or("the scope was accepted")?;
        assert_eq!(
            why, "--from 2026-11-12 is after --to 2026-11-11",
            "failure a window that ends before it starts is refused"
        );
        Ok(())
    }

    #[test]
    fn failure_a_class_that_is_not_one_is_refused() -> TestResult {
        let why = Scope::new(Some("store"), None, None)
            .err()
            .ok_or("the scope was accepted")?;
        assert_eq!(
            why, "--class store: the classes are calls and members",
            "failure the refusal names the classes"
        );
        Ok(())
    }

    #[test]
    fn edge_from_alone_and_to_alone_are_open_at_the_other_end() -> TestResult {
        let from = Scope::new(None, Some(day("2026-11-11")?), None)?;
        let to = Scope::new(None, None, Some(day("2026-11-11")?))?;
        assert_eq!(
            (
                from.wants(day("2026-11-10")?),
                from.wants(day("2030-01-01")?),
                to.wants(day("2026-11-12")?),
                to.wants(day("2020-01-01")?),
            ),
            (false, true, false, true),
            "edge one bound leaves the other end open"
        );
        Ok(())
    }

    #[test]
    fn edge_from_equal_to_is_one_day() -> TestResult {
        let scope = Scope::new(None, Some(day("2026-11-11")?), Some(day("2026-11-11")?))?;
        assert_eq!(
            (
                scope.wants(day("2026-11-10")?),
                scope.wants(day("2026-11-11")?),
                scope.wants(day("2026-11-12")?),
            ),
            (false, true, false),
            "edge the same day twice reads that day"
        );
        Ok(())
    }

    // ---- the pass over a store ------------------------------------------

    #[test]
    fn success_a_filed_store_is_clean() -> TestResult {
        let (_dir, history) = filed()?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (
                of(&report, "calls")?.clone(),
                of(&report, "members")?.clone()
            ),
            (
                ClassReport {
                    class: "calls",
                    files: 1,
                    clean: 1,
                    refused: 0,
                    gone: 0,
                    rows: 20
                },
                ClassReport {
                    class: "members",
                    files: 1,
                    clean: 1,
                    refused: 0,
                    gone: 0,
                    rows: 30
                }
            ),
            "success each class has one clean file with every row counted"
        );
        assert_eq!(
            (report.exit_code(), lines.len()),
            (0, 0),
            "success a clean store exits 0 with no refused line"
        );
        Ok(())
    }

    #[test]
    fn success_every_row_is_counted_past_the_limit_of_a_question() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&calls(1500))?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            of(&report, "calls")?.rows,
            1500,
            "success the pass builds all 1,500 rows, not the 1,000 a question may have"
        );
        Ok(())
    }

    #[test]
    fn success_class_calls_does_not_read_heartbeats() -> TestResult {
        let (_dir, history) = filed()?;
        let members = one(&history, "members")?;
        std::fs::write(history.dir().join(&members), b"not a sealed file")?;
        let (report, _) = pass(&history, &Scope::new(Some("calls"), None, None)?)?;
        assert_eq!(
            (
                report.classes.len(),
                of(&report, "calls")?.clean,
                report.exit_code()
            ),
            (1, 1, 0),
            "success --class calls reports call records only and exits 0"
        );
        Ok(())
    }

    #[test]
    fn success_class_members_does_not_read_call_records() -> TestResult {
        let (_dir, history) = filed()?;
        let calls_file = one(&history, "calls")?;
        std::fs::write(history.dir().join(&calls_file), b"not a sealed file")?;
        let (report, _) = pass(&history, &Scope::new(Some("members"), None, None)?)?;
        assert_eq!(
            (
                report.classes.len(),
                of(&report, "members")?.clean,
                report.exit_code()
            ),
            (1, 1, 0),
            "success --class members reports heartbeats only and exits 0"
        );
        Ok(())
    }

    #[test]
    fn success_from_and_to_leave_other_days_unread() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&calls(5))?;
        history.file(&[call("edge-a", DAY_MS + 1000, 9)])?;
        let next = history.list_days("calls", &|date| date.to_string() == "2026-11-12")?;
        let next = next.first().ok_or("no file of the next day")?;
        std::fs::write(history.dir().join(&next.rel), b"not a sealed file")?;
        let scope = Scope::new(None, Some(day("2026-11-11")?), Some(day("2026-11-11")?))?;
        let (report, _) = pass(&history, &scope)?;
        assert_eq!(
            (of(&report, "calls")?.files, report.exit_code()),
            (1, 0),
            "success only the file of the day asked for is read"
        );
        assert_eq!(
            pass(&history, &everything()?)?.0.exit_code(),
            1,
            "success without the window the file of the next day is refused"
        );
        Ok(())
    }

    #[test]
    fn success_a_file_under_an_old_key_is_read() -> TestResult {
        let (dir, history) = filed()?;
        drop(history);
        let rotated = Arc::new(Keys::new(
            MasterKey::from_bytes([2; 32]),
            vec![MasterKey::from_bytes([1; 32])],
        ));
        let reader = History::reader(&dir.path().join("center.store"), rotated);
        let (report, _) = pass(&reader, &everything()?)?;
        assert_eq!(
            (of(&report, "calls")?.clean, of(&report, "members")?.clean),
            (1, 1),
            "success a file sealed under an old key is read when that key is given"
        );
        Ok(())
    }

    #[test]
    fn success_files_of_both_layouts_are_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file_per_member(&calls(4))?;
        history.file(&[call("edge-b", 9000, 1)])?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (
                of(&report, "calls")?.files,
                of(&report, "calls")?.clean,
                of(&report, "calls")?.rows
            ),
            (2, 2, 5),
            "success the file under member=<id> and the file of the day are both clean: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn success_the_summary_has_one_line_for_each_class() -> TestResult {
        let (_dir, history) = filed()?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            report.summary_lines(),
            vec![
                "calls: 1 files, 1 clean, 0 refused, 0 gone, 20 rows",
                "members: 1 files, 1 clean, 0 refused, 0 gone, 30 rows"
            ],
            "success one line for each class in the scope's order"
        );
        Ok(())
    }

    #[test]
    fn success_the_json_names_the_start_and_the_version() -> TestResult {
        let (_dir, history) = filed()?;
        let (report, _) = pass(&history, &everything()?)?;
        let json = report.json();
        assert_eq!(
            (
                json["started_at"].as_str(),
                json["version"].as_str(),
                json["result"].as_str()
            ),
            (
                Some("2026-11-11T00:00:00Z"),
                Some(env!("CARGO_PKG_VERSION")),
                Some("clean")
            ),
            "success the JSON carries when the pass started and the program's version"
        );
        assert_eq!(
            json["classes"][0],
            serde_json::json!({
                "class": "calls", "files": 1, "clean": 1, "refused": 0, "gone": 0, "rows": 20
            }),
            "success the JSON has the counts of each class"
        );
        Ok(())
    }

    #[test]
    fn success_an_empty_history_directory_is_clean() -> TestResult {
        let (_dir, history) = store()?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            (
                of(&report, "calls")?.files,
                of(&report, "members")?.files,
                report.exit_code()
            ),
            (0, 0, 0),
            "success a store that filed nothing yet has no file and exits 0"
        );
        Ok(())
    }

    #[test]
    fn failure_a_truncated_file_is_refused() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        let path = history.dir().join(&rel);
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, bytes.get(..bytes.len() - 10).ok_or("short file")?)?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(report.exit_code(), 1, "failure a refused file exits 1");
        assert!(
            lines
                .first()
                .is_some_and(|line| line.starts_with(&format!("refused: {rel}: sealed layer: "))),
            "failure the sealed layer refuses a truncated file: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_under_another_key_is_refused() -> TestResult {
        let (dir, history) = filed()?;
        drop(history);
        let reader = History::reader(&dir.path().join("center.store"), keys(9));
        let (report, lines) = pass(&reader, &everything()?)?;
        assert_eq!(
            (report.refused.len(), report.exit_code()),
            (2, 1),
            "failure both files are refused without their key: {lines:?}"
        );
        assert!(
            report
                .refused
                .iter()
                .all(|refusal| refusal.reason.starts_with("sealed layer: ")),
            "failure the sealed layer is the reason: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_moved_to_another_name_is_refused() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        let mut name = IntervalName::of(&calls(20))?;
        name.mark ^= 1;
        let moved = format!("calls/{DAY}/{}", name.text());
        std::fs::rename(history.dir().join(&rel), history.dir().join(&moved))?;
        let (report, lines) = pass(&history, &Scope::new(Some("calls"), None, None)?)?;
        assert_eq!(report.exit_code(), 1, "failure a moved file exits 1");
        assert!(
            lines.first().is_some_and(|line| line.starts_with(&format!(
                "refused: {moved}: sealed layer: the file was written as '{rel}'"
            ))),
            "failure the sealed layer names the path the file was written at: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_call_that_is_not_json_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        let rows = calls(1500);
        plant(
            &history,
            &rel_of(&rows)?,
            &rows,
            &spoil(CALL_JSON, 1400, b"not json"),
        )?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            report.exit_code(),
            1,
            "failure one row that does not parse exits 1"
        );
        assert!(
            report.refused.first().is_some_and(|refusal| refusal
                .reason
                .starts_with("parquet: row 1401 has a call that is not JSON: ")),
            "failure the row past a question's limit is found and named: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_an_inventory_that_is_not_json_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        let rows = beats(300);
        plant(
            &history,
            &rel_of(&rows)?,
            &rows,
            &spoil(BEAT_INVENTORY, 17, b"{"),
        )?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, "members")?.refused, report.exit_code()),
            (1, 1),
            "failure a heartbeat whose inventory does not parse refuses its file: {lines:?}"
        );
        assert!(
            report
                .refused
                .first()
                .is_some_and(|refusal| refusal.reason.starts_with("parquet: row 18 ")),
            "failure the row is named: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_file_that_is_not_sealed_is_refused() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "members")?;
        std::fs::write(history.dir().join(&rel), b"PAR1 and nothing sealed")?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, "members")?.refused, of(&report, "calls")?.clean),
            (1, 1),
            "failure the file is refused and the other class is still read: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_an_empty_file_is_refused() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, "calls")?.refused, report.exit_code()),
            (1, 1),
            "failure a file of no bytes is refused: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_rows_of_another_day_sealed_at_this_path_are_refused() -> TestResult {
        let (_dir, history) = store()?;
        let rows = vec![call("edge-a", DAY_MS + 1000, 1)];
        let rel = rel_of(&rows)?;
        plant(&history, &rel, &rows, &whole)?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            lines,
            vec![format!(
                "refused: {rel}: rows: row 1 was received on 2026-11-12, and the file is in the \
             directory of 2026-11-11"
            )],
            "failure a sealed file whose rows are of another day is refused"
        );
        assert_eq!(report.exit_code(), 1, "failure and the pass exits 1");
        Ok(())
    }

    #[test]
    fn failure_a_wrong_mark_sealed_at_this_path_is_refused() -> TestResult {
        let (_dir, history) = store()?;
        let rows = calls(3);
        let mut name = IntervalName::of(&rows)?;
        name.mark ^= 0xff;
        plant(
            &history,
            &format!("calls/{DAY}/{}", name.text()),
            &rows,
            &whole,
        )?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert!(
            report.refused.first().is_some_and(|refusal| refusal
                .reason
                .starts_with("rows: the mark of the rows is h")),
            "failure a writer that named a file for other rows is found: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_each_refused_file_has_one_line_and_the_rest_are_read() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&calls(5))?;
        for seq in [11_u64, 12] {
            let rows = vec![call("edge-b", i64::try_from(seq)? * 60_000, seq)];
            plant(&history, &rel_of(&rows)?, &rows, &spoil(CALL_JSON, 0, b"x"))?;
        }
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (
                of(&report, "calls")?.files,
                of(&report, "calls")?.clean,
                of(&report, "calls")?.refused,
                lines.len(),
                report.refused.len()
            ),
            (3, 1, 2, 2, 2),
            "failure two refused files give two lines, and the clean file is counted: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_no_history_directory_cannot_run() -> TestResult {
        let dir = tempfile::tempdir()?;
        let reader = History::reader(&dir.path().join("center.store"), keys(1));
        let why = pass(&reader, &everything()?)
            .err()
            .ok_or("the pass ran without a history directory")?;
        assert_eq!(
            why,
            format!(
                "no history directory '{}': nothing to verify",
                reader.dir().display()
            ),
            "failure the pass says which directory is missing"
        );
        assert!(
            !reader.dir().exists(),
            "failure the pass did not create the directory"
        );
        Ok(())
    }

    #[test]
    fn failure_the_reason_does_not_repeat_the_path() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (report, _) = pass(&history, &everything()?)?;
        let refusal = report.refused.first().ok_or("nothing was refused")?;
        assert_eq!(refusal.file, rel, "failure the file field holds the path");
        assert!(
            !refusal.reason.contains(&rel),
            "failure the reason does not hold the path again: {}",
            refusal.reason
        );
        Ok(())
    }

    #[test]
    fn failure_the_json_lists_each_refused_file() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (report, _) = pass(&history, &everything()?)?;
        let json = report.json();
        assert_eq!(
            (
                json["result"].as_str(),
                json["refused"][0]["class"].as_str(),
                json["refused"][0]["file"].as_str(),
                json["refused"][0]["reason"].as_str(),
                json["refused"].as_array().map(Vec::len)
            ),
            (
                Some("refused"),
                Some("calls"),
                Some(rel.as_str()),
                report
                    .refused
                    .first()
                    .map(|refusal| refusal.reason.as_str()),
                Some(1)
            ),
            "failure the JSON names the class, the file and the reason"
        );
        Ok(())
    }

    #[test]
    fn edge_a_file_gone_after_the_listing_counts_as_gone() -> TestResult {
        let (_dir, history) = filed()?;
        let listed = history.list_days("calls", &|_| true)?;
        std::fs::remove_file(history.dir().join(&one(&history, "calls")?))?;
        let mut report = Report {
            started_at: at_ms(0),
            version: String::new(),
            classes: Vec::new(),
            refused: Vec::new(),
        };
        check_listed(&history, "calls", &listed, &mut report, &mut |_| {});
        assert_eq!(
            (
                of(&report, "calls")?.files,
                of(&report, "calls")?.gone,
                of(&report, "calls")?.refused,
                report.exit_code()
            ),
            (1, 1, 0, 0),
            "edge a file that retention removed is gone, not refused, and the pass exits 0"
        );
        Ok(())
    }

    #[test]
    fn edge_a_file_that_is_absent_is_gone() -> TestResult {
        let (_dir, history) = store()?;
        assert_eq!(
            check_file::<IntakeRecord>(&history, &rel_of(&calls(2))?),
            Checked::Gone,
            "edge an absent file is told apart from a refused one"
        );
        Ok(())
    }

    #[test]
    fn edge_a_clean_file_says_how_many_rows_it_holds() -> TestResult {
        let (_dir, history) = filed()?;
        assert_eq!(
            check_file::<MemberRecord>(&history, &one(&history, "members")?),
            Checked::Clean(30),
            "edge the check of one file counts its rows"
        );
        Ok(())
    }

    #[test]
    fn edge_a_name_the_store_does_not_write_is_not_read() -> TestResult {
        let (_dir, history) = filed()?;
        std::fs::write(history.dir().join(format!("calls/{DAY}/notes.txt")), b"x")?;
        std::fs::write(history.dir().join(format!("calls/{DAY}/x.sealed")), b"x")?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, "calls")?.files, report.exit_code()),
            (1, 0),
            "edge only files under names the store writes are files of the store"
        );
        Ok(())
    }

    #[test]
    fn edge_a_directory_that_names_no_day_is_not_read() -> TestResult {
        let (_dir, history) = filed()?;
        let other = history.dir().join("calls/lost+found");
        std::fs::create_dir_all(&other)?;
        std::fs::write(other.join(IntervalName::of(&calls(2))?.text()), b"x")?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, "calls")?.files, report.exit_code()),
            (1, 0),
            "edge a directory under a name that is no day holds no file of the store"
        );
        Ok(())
    }

    #[test]
    fn edge_a_class_with_no_directory_has_no_file() -> TestResult {
        let (_dir, history) = store()?;
        history.file(&calls(3))?;
        let (report, _) = pass(&history, &everything()?)?;
        assert_eq!(
            (
                of(&report, "calls")?.files,
                of(&report, "members")?.files,
                report.exit_code()
            ),
            (1, 0, 0),
            "edge a center that filed no heartbeat yet has no members directory"
        );
        Ok(())
    }

    #[test]
    fn edge_the_pass_changes_nothing() -> TestResult {
        let (dir, history) = filed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"spoiled")?;
        let before = tree(dir.path())?;
        let _ = pass(&history, &everything()?)?;
        assert_eq!(
            tree(dir.path())?,
            before,
            "edge no file is created, removed or changed, a refused one included"
        );
        Ok(())
    }

    #[test]
    fn edge_refused_files_are_reported_in_path_order() -> TestResult {
        let (_dir, history) = store()?;
        for seq in [3_u64, 1, 2] {
            let rows = vec![call("edge-a", i64::try_from(seq)? * 60_000, seq)];
            plant(&history, &rel_of(&rows)?, &rows, &spoil(CALL_JSON, 0, b"x"))?;
        }
        let (report, _) = pass(&history, &everything()?)?;
        let files: Vec<&str> = report
            .refused
            .iter()
            .map(|refusal| refusal.file.as_str())
            .collect();
        let mut ordered = files.clone();
        ordered.sort_unstable();
        assert_eq!(
            (files.len(), files == ordered),
            (3, true),
            "edge the refused files come in the order of their paths: {files:?}"
        );
        Ok(())
    }

    #[test]
    fn edge_gone_files_alone_leave_the_exit_status_at_0() {
        let report = Report {
            started_at: at_ms(0),
            version: String::new(),
            classes: vec![ClassReport {
                class: "calls",
                files: 3,
                clean: 0,
                refused: 0,
                gone: 3,
                rows: 0,
            }],
            refused: Vec::new(),
        };
        assert_eq!(report.exit_code(), 0, "edge gone files are not refusals");
        assert_eq!(
            report.summary_lines(),
            vec!["calls: 3 files, 0 clean, 0 refused, 3 gone, 0 rows"],
            "edge and the summary counts them"
        );
    }

    #[test]
    fn edge_one_refusal_is_enough_for_exit_1() {
        let report = Report {
            started_at: at_ms(0),
            version: String::new(),
            classes: Vec::new(),
            refused: vec![Refusal {
                class: "members",
                file: "members/x".to_string(),
                reason: "why".to_string(),
            }],
        };
        assert_eq!(report.exit_code(), 1, "edge one refused file gives exit 1");
        assert_eq!(
            report.refused.first().map(Refusal::line).as_deref(),
            Some("refused: members/x: why"),
            "edge the line is the file and the reason"
        );
    }

    // ---- the command line -------------------------------------------------

    use crate::cli::fleet_args::{FleetCli, FleetCommand, HistoryClass, VerifyFlags, parse_day};

    /// The flags of `sipnab fleet verify` with `more` after the two required
    /// ones, or clap's refusal.
    fn flags(more: &[&str]) -> Result<VerifyFlags, String> {
        use clap::Parser as _;
        let line = [
            "sipnab fleet",
            "verify",
            "--store",
            "c.store",
            "--store-key-file",
            "k",
        ]
        .iter()
        .chain(more);
        match FleetCli::try_parse_from(line) {
            Ok(FleetCli {
                command: FleetCommand::Verify(flags),
            }) => Ok(flags),
            Ok(_) => Err("another command was parsed".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn success_every_flag_of_the_command_line_is_parsed() -> TestResult {
        let parsed = flags(&[
            "--store-old-key-file",
            "a",
            "--store-old-key-file",
            "b",
            "--class",
            "members",
            "--from",
            "2026-11-10",
            "--to",
            "2026-11-12",
            "--json",
        ])?;
        assert_eq!(
            (
                parsed.store_old_key_file.len(),
                parsed.class,
                parsed.from,
                parsed.to,
                parsed.json
            ),
            (
                2,
                Some(HistoryClass::Members),
                Some(day("2026-11-10")?),
                Some(day("2026-11-12")?),
                true
            ),
            "success each flag reaches its field"
        );
        Ok(())
    }

    #[test]
    fn failure_a_day_in_another_spelling_is_refused() {
        for text in [
            "2026-11-1",
            "20261111",
            "2026-13-01",
            "2026-11-11T00:00:00Z",
            "",
        ] {
            assert_eq!(
                parse_day(text),
                Err(format!("'{text}' is not a day as YYYY-MM-DD")),
                "failure '{text}' is not a day of the one spelling"
            );
        }
    }

    #[test]
    fn failure_the_command_line_refuses_a_class_that_is_not_one() -> TestResult {
        let why = flags(&["--class", "store"])
            .err()
            .ok_or("the class was accepted")?;
        assert!(
            why.contains("calls") && why.contains("members"),
            "failure the refusal names the two classes: {why}"
        );
        Ok(())
    }

    #[test]
    fn failure_the_command_line_needs_the_key_file() {
        use clap::Parser as _;
        let parsed = FleetCli::try_parse_from(["sipnab fleet", "verify", "--store", "c.store"]);
        assert!(
            parsed.is_err_and(|e| e.to_string().contains("--store-key-file")),
            "failure a pass without --store-key-file is refused by name"
        );
    }

    #[test]
    fn edge_the_two_required_flags_read_both_classes_and_every_day() -> TestResult {
        let parsed = flags(&[])?;
        assert_eq!(
            (parsed.class, parsed.from, parsed.to, parsed.json),
            (None, None, None, false),
            "edge no class, no day and no --json by default"
        );
        Ok(())
    }

    #[test]
    fn edge_the_class_names_are_the_directories() {
        assert_eq!(
            (HistoryClass::Calls.as_str(), HistoryClass::Members.as_str()),
            (CLASS_CALLS, CLASS_MEMBERS),
            "edge --class takes the names of the store's directories"
        );
    }

    #[test]
    fn success_the_command_line_takes_the_user_to_run_as() -> TestResult {
        let parsed = flags(&["--user", "sipnab-center"])?;
        let asked = parsed.run_as.asked();
        assert_eq!(
            (asked.flag_user, asked.config_user, asked.no_priv_drop),
            (Some("sipnab-center"), None, false),
            "success --user is the user a pass started as root reads the history files as"
        );
        Ok(())
    }

    #[test]
    fn success_the_command_line_takes_no_priv_drop() -> TestResult {
        let parsed = flags(&["--no-priv-drop"])?;
        let asked = parsed.run_as.asked();
        assert_eq!(
            (asked.flag_user, asked.no_priv_drop),
            (None, true),
            "success --no-priv-drop is passed on to the plan of the command"
        );
        Ok(())
    }

    #[test]
    fn failure_the_command_line_refuses_user_without_a_name() {
        let refused = flags(&["--user"]).err().unwrap_or_default();
        assert!(
            refused.contains("--user <USER>"),
            "failure --user needs the name of a user: {refused}"
        );
    }

    #[test]
    fn edge_the_two_required_flags_name_no_user() -> TestResult {
        let parsed = flags(&[])?;
        assert_eq!(
            parsed.run_as,
            crate::cli::fleet_args::RunAs::default(),
            "edge with no flag a pass started as root runs as nobody"
        );
        Ok(())
    }

    // ---- the command ------------------------------------------------------

    /// A filed store under a key file, with the arguments that verify it.
    fn keyed() -> Result<(tempfile::TempDir, VerifyArgs, History), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let key_file = dir.path().join("store.key");
        write_new_key_file(&key_file, &system_draw)?;
        let key = read_key_file(&key_file, "--store-key-file")?;
        let store = dir.path().join("center.store");
        let history = History::open(&store, Arc::new(Keys::new(key, Vec::new())))?;
        history.file(&calls(20))?;
        history.file(&beats(30))?;
        let args = VerifyArgs {
            store,
            store_key_file: key_file,
            store_old_key_files: Vec::new(),
            class: None,
            from: None,
            to: None,
            json: false,
        };
        Ok((dir, args, history))
    }

    /// Run the command: its exit status, its output and its error output.
    fn ran(args: &VerifyArgs) -> Result<(i32, String, String), std::string::FromUtf8Error> {
        ran_confined(args, &mut |_| Ok(()))
    }

    /// Run the command with `confine` as the step between the key files and
    /// the history files: its exit status, its output and its error output.
    fn ran_confined(
        args: &VerifyArgs,
        confine: &mut dyn FnMut(&std::path::Path) -> Result<(), String>,
    ) -> Result<(i32, String, String), std::string::FromUtf8Error> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(args, at_ms(0), confine, &mut out, &mut err);
        Ok((status, String::from_utf8(out)?, String::from_utf8(err)?))
    }

    // ---- the step between the key files and the history files -------------
    //
    // A run started as root reads its key files as root and the history files
    // as the user it dropped to. `run` takes the drop as a step, so these
    // tests put their own step there and read what it saw.

    /// What `nobody` is told when it cannot read the history directory.
    const LACK: &str = "fleet verify: started as root, this command runs as user 'nobody', and \
                    'nobody' cannot read '/s' (the history store of --store). Nothing was \
                    created. Choose one: chown nobody '/s'; run it with --user USER, naming a \
                    user who can; or pass --no-priv-drop to keep root";

    #[test]
    fn success_the_step_is_taken_once_with_the_history_directory() -> TestResult {
        let (_dir, args, history) = keyed()?;
        let mut seen = Vec::new();
        let (status, _, err) = ran_confined(&args, &mut |dir| {
            seen.push(dir.to_path_buf());
            Ok(())
        })?;
        assert_eq!(
            (status, err.as_str(), seen),
            (0, "", vec![history.dir().to_path_buf()]),
            "success the drop is one step, and it is given the directory the pass reads"
        );
        Ok(())
    }

    #[test]
    fn success_the_key_files_are_read_before_the_step() -> TestResult {
        let (_dir, args, _history) = keyed()?;
        let key_file = args.store_key_file.clone();
        let mut removed = Vec::new();
        let (status, out, err) = ran_confined(&args, &mut |_| {
            // A key file root alone may read is out of reach from here on.
            removed.push(std::fs::remove_file(&key_file).is_ok());
            Ok(())
        })?;
        assert_eq!(
            removed,
            [true],
            "success the key file was there when the step ran"
        );
        assert_eq!(
            (status, out.as_str(), err.as_str()),
            (
                0,
                "calls: 1 files, 1 clean, 0 refused, 0 gone, 20 rows\n\
             members: 1 files, 1 clean, 0 refused, 0 gone, 30 rows\n",
                ""
            ),
            "success a key file that is gone after the step was read before it"
        );
        Ok(())
    }

    #[test]
    fn success_an_old_key_file_is_read_before_the_step() -> TestResult {
        let (dir, mut args, history) = keyed()?;
        // The files are under the key that becomes the old one.
        let new_key = dir.path().join("new.key");
        write_new_key_file(&new_key, &system_draw)?;
        args.store_old_key_files = vec![args.store_key_file.clone()];
        args.store_key_file = new_key;
        let old = args.store_old_key_files.clone();
        let (status, out, err) = ran_confined(&args, &mut |_| {
            for file in &old {
                std::fs::remove_file(file).map_err(|e| e.to_string())?;
            }
            Ok(())
        })?;
        assert!(
            args.store_old_key_files.iter().all(|file| !file.exists()),
            "success the step ran and removed the old key file"
        );
        assert_eq!(
            (status, err.as_str()),
            (0, ""),
            "success an old key file gone after the step was read before it: {out}"
        );
        assert!(
            history.dir().is_dir() && out.contains("calls: 1 files, 1 clean"),
            "success the files under the old key were read with it: {out}"
        );
        Ok(())
    }

    #[test]
    fn success_the_history_files_are_read_after_the_step() -> TestResult {
        let (_dir, args, history) = keyed()?;
        let rel = one(&history, "calls")?;
        let path = history.dir().join(&rel);
        let (status, out, _) = ran_confined(&args, &mut |_| {
            // What the step leaves is what the pass reads.
            std::fs::write(&path, b"").map_err(|e| e.to_string())
        })?;
        assert_eq!(
            status, 1,
            "success a file the step emptied is read after it: {out}"
        );
        assert!(
            out.starts_with(&format!("refused: {rel}: ")),
            "success the pass read the file as the step left it: {out}"
        );
        Ok(())
    }

    #[test]
    fn success_the_history_directory_is_listed_after_the_step() -> TestResult {
        let (_dir, args, history) = keyed()?;
        let members = history.dir().join("members");
        let (status, out, err) = ran_confined(&args, &mut |_| {
            std::fs::remove_dir_all(&members).map_err(|e| e.to_string())
        })?;
        assert_eq!(
            (status, out.as_str(), err.as_str()),
            (
                0,
                "calls: 1 files, 1 clean, 0 refused, 0 gone, 20 rows\n\
             members: 0 files, 0 clean, 0 refused, 0 gone, 0 rows\n",
                ""
            ),
            "success a class removed in the step was not listed before it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_refused_step_exits_2_with_its_text() -> TestResult {
        let (_dir, args, _history) = keyed()?;
        let (status, out, err) = ran_confined(&args, &mut |_| Err(LACK.to_string()))?;
        assert_eq!(
            (status, out.as_str(), err),
            (2, "", format!("sipnab {LACK}\n")),
            "failure a drop user that cannot read the store ends the run with the refusal alone"
        );
        Ok(())
    }

    #[test]
    fn failure_a_refused_step_reads_no_history_file() -> TestResult {
        let (_dir, args, history) = keyed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (status, out, err) = ran_confined(&args, &mut |_| Err(LACK.to_string()))?;
        assert_eq!(
            (status, out.as_str()),
            (2, ""),
            "failure a file that a pass would refuse is not read when the step refuses: {err}"
        );
        assert!(
            !err.contains(&rel),
            "failure the refusal names no history file: {err}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_refused_step_prints_no_json() -> TestResult {
        let (_dir, mut args, _history) = keyed()?;
        args.json = true;
        let (status, out, err) = ran_confined(&args, &mut |_| Err(LACK.to_string()))?;
        assert_eq!(
            (status, out.as_str(), err.lines().count()),
            (2, "", 1),
            "failure --json prints no document for a pass that did not run: {err}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_refused_key_file_ends_the_run_before_the_step() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        args.store_key_file = dir.path().join("no.key");
        let mut steps = Vec::new();
        let (status, _, err) = ran_confined(&args, &mut |_| {
            steps.push(());
            Ok(())
        })?;
        assert_eq!(
            (status, steps.len()),
            (2, 0),
            "failure a run whose key file is refused does not go on to the drop: {err}"
        );
        assert!(
            err.contains("--store-key-file"),
            "failure the message is the key file's: {err}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_refused_old_key_file_ends_the_run_before_the_step() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        args.store_old_key_files = vec![dir.path().join("no-old.key")];
        let mut steps = Vec::new();
        let (status, _, err) = ran_confined(&args, &mut |_| {
            steps.push(());
            Ok(())
        })?;
        assert_eq!(
            (status, steps.len()),
            (2, 0),
            "failure a run whose old key file is refused does not go on to the drop: {err}"
        );
        assert!(
            err.contains("--store-old-key-file"),
            "failure the message is the old key file's: {err}"
        );
        Ok(())
    }

    #[test]
    fn edge_refused_days_end_the_run_before_any_file_is_read() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        // Both are wrong: the days are refused first, and no key file is read.
        args.store_key_file = dir.path().join("no.key");
        args.from = Some(day("2026-11-12")?);
        args.to = Some(day("2026-11-11")?);
        let mut steps = Vec::new();
        let (status, _, err) = ran_confined(&args, &mut |_| {
            steps.push(());
            Ok(())
        })?;
        assert_eq!(
            (status, steps.len(), err.as_str()),
            (
                2,
                0,
                "sipnab fleet verify: --from 2026-11-12 is after --to 2026-11-11\n"
            ),
            "edge the arguments are checked before a key file is read or the step is taken"
        );
        Ok(())
    }

    #[test]
    fn edge_the_step_is_taken_when_there_is_no_history_directory() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        args.store = dir.path().join("other.store");
        let mut seen = Vec::new();
        let (status, _, err) = ran_confined(&args, &mut |dir| {
            seen.push(dir.to_path_buf());
            Ok(())
        })?;
        assert_eq!(
            (status, seen),
            (2, vec![dir.path().join("other.store.parquet")]),
            "edge the run drops before it looks for the history directory: {err}"
        );
        assert!(
            err.starts_with("sipnab fleet verify: no history directory '"),
            "edge the refusal is the pass's own, told as the drop user: {err}"
        );
        Ok(())
    }

    #[test]
    fn edge_a_step_that_refuses_without_the_command_name_is_given_it() -> TestResult {
        let (_dir, args, _history) = keyed()?;
        let (status, _, err) = ran_confined(&args, &mut |_| Err("no such user".to_string()))?;
        assert_eq!(
            (status, err.as_str()),
            (2, "sipnab fleet verify: no such user\n"),
            "edge every refusal names the command once"
        );
        Ok(())
    }

    #[test]
    fn success_the_command_prints_the_summary_and_exits_0() -> TestResult {
        let (_dir, args, _history) = keyed()?;
        assert_eq!(
            ran(&args)?,
            (
                0,
                "calls: 1 files, 1 clean, 0 refused, 0 gone, 20 rows\n\
             members: 1 files, 1 clean, 0 refused, 0 gone, 30 rows\n"
                    .to_string(),
                String::new()
            ),
            "success a clean store prints one line for each class and exits 0"
        );
        Ok(())
    }

    #[test]
    fn success_the_command_prints_one_json_document() -> TestResult {
        let (_dir, mut args, _history) = keyed()?;
        args.json = true;
        let (status, out, err) = ran(&args)?;
        let json: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            (
                status,
                json["result"].as_str(),
                json["classes"].as_array().map(Vec::len),
                json["refused"].as_array().map(Vec::len),
                err.as_str()
            ),
            (0, Some("clean"), Some(2), Some(0), ""),
            "success --json prints the report as one JSON document"
        );
        Ok(())
    }

    #[test]
    fn failure_the_command_prints_the_refused_file_and_exits_1() -> TestResult {
        let (_dir, args, history) = keyed()?;
        let rel = one(&history, "calls")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (status, out, _) = ran(&args)?;
        assert_eq!(status, 1, "failure a refused file gives exit 1");
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines
                .first()
                .is_some_and(|line| line.starts_with(&format!("refused: {rel}: "))),
            "failure the refused file is printed before the summary: {lines:?}"
        );
        assert_eq!(
            lines.get(1).copied(),
            Some("calls: 1 files, 0 clean, 1 refused, 0 gone, 0 rows"),
            "failure the summary counts it"
        );
        Ok(())
    }

    #[test]
    fn failure_a_key_file_that_is_absent_exits_2() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        args.store_key_file = dir.path().join("no.key");
        let (status, out, err) = ran(&args)?;
        assert_eq!(
            (status, out.as_str()),
            (2, ""),
            "failure the pass does not run without its key"
        );
        assert!(
            err.starts_with("sipnab fleet verify: ") && err.contains("--store-key-file"),
            "failure the message names the flag: {err}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_store_with_no_history_directory_exits_2() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        args.store = dir.path().join("other.store");
        let (status, out, err) = ran(&args)?;
        assert_eq!(
            (status, out.as_str()),
            (2, ""),
            "failure no history directory beside --store is not a clean pass"
        );
        assert!(
            err.starts_with("sipnab fleet verify: no history directory '")
                && err.ends_with("': nothing to verify\n"),
            "failure the message names the directory: {err}"
        );
        Ok(())
    }

    #[test]
    fn failure_from_after_to_exits_2() -> TestResult {
        let (_dir, mut args, _history) = keyed()?;
        args.from = Some(day("2026-11-12")?);
        args.to = Some(day("2026-11-11")?);
        assert_eq!(
            ran(&args)?,
            (
                2,
                String::new(),
                "sipnab fleet verify: --from 2026-11-12 is after --to 2026-11-11\n".to_string()
            ),
            "failure a window that ends before it starts is refused before any read"
        );
        Ok(())
    }

    #[test]
    fn failure_the_json_of_a_refused_pass_exits_1() -> TestResult {
        let (_dir, mut args, history) = keyed()?;
        args.json = true;
        let rel = one(&history, "members")?;
        std::fs::write(history.dir().join(&rel), b"")?;
        let (status, out, _) = ran(&args)?;
        let json: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            (
                status,
                json["result"].as_str(),
                json["refused"][0]["file"].as_str()
            ),
            (1, Some("refused"), Some(rel.as_str())),
            "failure --json prints no refused line of its own: the list holds the file"
        );
        assert!(
            !out.contains("refused: "),
            "failure the output is the JSON document only: {out}"
        );
        Ok(())
    }

    #[test]
    fn edge_the_command_reads_one_class_when_asked() -> TestResult {
        let (_dir, mut args, _history) = keyed()?;
        args.class = Some("members");
        assert_eq!(
            ran(&args)?.1,
            "members: 1 files, 1 clean, 0 refused, 0 gone, 30 rows\n",
            "edge --class members prints the one class"
        );
        Ok(())
    }

    #[test]
    fn edge_a_window_with_no_file_exits_0() -> TestResult {
        let (_dir, mut args, _history) = keyed()?;
        args.from = Some(day("2027-01-01")?);
        assert_eq!(
            ran(&args)?,
            (
                0,
                "calls: 0 files, 0 clean, 0 refused, 0 gone, 0 rows\n\
             members: 0 files, 0 clean, 0 refused, 0 gone, 0 rows\n"
                    .to_string(),
                String::new()
            ),
            "edge days that hold nothing are a clean pass over no file"
        );
        Ok(())
    }

    #[test]
    fn edge_an_old_key_file_is_read() -> TestResult {
        let (dir, mut args, _history) = keyed()?;
        let new_key = dir.path().join("new.key");
        write_new_key_file(&new_key, &system_draw)?;
        args.store_old_key_files = vec![args.store_key_file.clone()];
        args.store_key_file = new_key;
        assert_eq!(
            ran(&args)?.0,
            0,
            "edge files under the old key are read when --store-old-key-file names it"
        );
        args.store_old_key_files.clear();
        assert_eq!(ran(&args)?.0, 1, "edge and refused when it does not");
        Ok(())
    }

    // ---- an entry that is not a file (FLEET-HISTORY-READS-A-FIFO) ----------

    /// What a reader says of a FIFO under a history file's name.
    const NOT_A_FILE: &str = "is a pipe or FIFO, not a file of the history store";

    /// Make a FIFO at `rel` under the history directory.
    fn fifo_at(history: &History, rel: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = history.dir().join(rel);
        std::fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        let made = std::process::Command::new("mkfifo").arg(&path).status()?;
        if made.success() {
            Ok(path)
        } else {
            Err(format!("mkfifo: {made}").into())
        }
    }

    /// The answer of `read`, run on a thread of its own. A read that has
    /// no answer at the deadline waits on the FIFO: the test then opens and
    /// closes the write end, so the read ends, and reports the wait.
    fn without_waiting<T: Send + 'static>(
        fifo: &std::path::Path,
        read: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(read());
        });
        let answer = rx.recv_timeout(std::time::Duration::from_secs(20));
        if answer.is_err() {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo);
        }
        let _ = reader.join();
        answer.map_err(|_| "the read waited on the FIFO for a writer".to_string())
    }

    #[test]
    fn failure_a_fifo_under_a_history_name_is_refused_and_not_waited_on() -> TestResult {
        let (_dir, history) = store()?;
        let rel = rel_of(&calls(3))?;
        let fifo = fifo_at(&history, &rel)?;
        let (reader, path) = (history.clone(), rel.clone());
        let checked = without_waiting(&fifo, move || check_file::<IntakeRecord>(&reader, &path))?;
        assert_eq!(
            checked,
            Checked::Refused(NOT_A_FILE.to_string()),
            "failure a FIFO under a history file's name is a refused file with a reason"
        );
        Ok(())
    }

    #[test]
    fn failure_the_centers_read_of_a_fifo_is_refused_and_not_waited_on() -> TestResult {
        let (_dir, history) = store()?;
        let rel = rel_of(&beats(3))?;
        let fifo = fifo_at(&history, &rel)?;
        let (reader, path) = (history.clone(), rel.clone());
        let read = without_waiting(&fifo, move || {
            reader
                .read::<MemberRecord>(&path, &Query::all())
                .map(|decoded| decoded.rows.len())
        })?;
        assert_eq!(
            read,
            Err(format!("{rel}: {NOT_A_FILE}")),
            "failure the read a question to the center makes refuses a FIFO and names the file"
        );
        Ok(())
    }

    #[test]
    fn failure_a_pass_reports_a_fifo_and_reads_the_other_files() -> TestResult {
        let (_dir, history) = filed()?;
        let rel = format!(
            "{CLASS_CALLS}/{DAY}/{}",
            IntervalName {
                first_ms: 1,
                last_ms: 2,
                mark: 3
            }
            .text()
        );
        let fifo = fifo_at(&history, &rel)?;
        let reader = history.clone();
        let (report, lines) = without_waiting(&fifo, move || pass(&reader, &everything()?))??;
        assert_eq!(
            lines,
            [format!("refused: {rel}: {NOT_A_FILE}")],
            "failure the FIFO has one refused line"
        );
        let calls = of(&report, CLASS_CALLS)?;
        assert_eq!(
            (calls.files, calls.clean, calls.refused, report.exit_code()),
            (2, 1, 1, 1),
            "failure the pass went on to the file after the FIFO"
        );
        Ok(())
    }

    #[test]
    fn edge_a_link_to_a_fifo_under_a_history_name_is_refused() -> TestResult {
        let (dir, history) = store()?;
        let rel = rel_of(&calls(3))?;
        let fifo = fifo_at(&history, "outside/pipe")?;
        let link = history.dir().join(&rel);
        std::fs::create_dir_all(link.parent().ok_or("no parent")?)?;
        std::os::unix::fs::symlink(&fifo, &link)?;
        let (reader, path) = (history.clone(), rel.clone());
        let checked = without_waiting(&fifo, move || check_file::<IntakeRecord>(&reader, &path))?;
        assert_eq!(
            checked,
            Checked::Refused(NOT_A_FILE.to_string()),
            "edge the type is read from what was opened, so a link to a FIFO is refused too"
        );
        drop(dir);
        Ok(())
    }

    #[test]
    fn edge_a_directory_under_a_history_name_is_not_listed() -> TestResult {
        let (_dir, history) = store()?;
        let rel = rel_of(&calls(3))?;
        std::fs::create_dir_all(history.dir().join(&rel))?;
        let (report, lines) = pass(&history, &everything()?)?;
        assert_eq!(
            (of(&report, CLASS_CALLS)?.files, lines.len()),
            (0, 0),
            "edge a directory under a file's name is not a file of the store"
        );
        Ok(())
    }
}
