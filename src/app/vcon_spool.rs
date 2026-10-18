// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The vCon export spool's state: what is waiting, what was delivered, what
//! was refused and why.
//!
//! One function, [`snapshot`], answers for every door: the MCP tool
//! `vcon_spool_status`, `GET /v1/vcon/spool` and
//! `sipnab --vcon-spool-status`. Each door adds only its own envelope (the
//! MCP door fences the store's answer and cuts it to `--mcp-max-body-bytes`),
//! so the three cannot come to count one spool differently.
//!
//! It reads files and does nothing else. The forwarder
//! ([`crate::app::vcon_forward`]) is a separate process that moves files out
//! of the spool, and the process that answers here sends nothing, fetches
//! nothing, and moves, deletes or creates no file. The answer is therefore a
//! snapshot, dated by its `as_of`.
//!
//! The file rules are the forwarder's own: [`pending`] decides what a
//! container is, [`failed_containers`] leaves out the `.error.json` records,
//! and [`FailureRecord`] is the type the forwarder writes those records from.

use std::io::Read as _;
use std::path::Path;

use serde::Serialize;

use crate::app::vcon_forward::{
    ERROR_RECORD_SUFFIX, FailureRecord, default_done_dir, default_failed_dir, failed_containers,
    pending,
};

/// The one sentence every answer carries.
pub const SPOOL_NOTE: &str = "A snapshot of files on disk at as_of. The vCon \
     forwarder (sipnab --vcon-forward) is a separate process that moves files \
     out of the spool; whatever produced this answer sends, fetches, moves and \
     deletes nothing. The delivered and failed directories are the forwarder's \
     defaults beside the spool; a forwarder started with --vcon-forward-done or \
     --vcon-forward-failed moves files elsewhere, and those are not counted.";

/// The most bytes of one `<file>.error.json` record [`snapshot`] reads.
///
/// Not a setting: a record larger than this is reported as too large rather
/// than read into memory. The forwarder's own default keeps 8 KiB of an
/// answer, so a default record is far below it.
pub const MAX_RECORD_READ: u64 = 1024 * 1024;

/// Which failed records one answer carries.
#[derive(Debug, Clone, Copy)]
pub struct SpoolPage<'a> {
    /// The last file name of the previous page; records sort after it.
    pub after: Option<&'a str>,
    /// Most records in this page.
    pub limit: usize,
}

impl SpoolPage<'_> {
    /// Every failed record, on one page: what the command-line door prints.
    #[must_use]
    pub fn all() -> Self {
        Self {
            after: None,
            limit: usize::MAX,
        }
    }
}

/// One directory the snapshot read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct SpoolDirectory {
    /// The path, as this process resolved it.
    pub path: String,
    /// Whether the directory existed when it was read. A directory that does
    /// not exist holds nothing, and is counted as zero.
    pub exists: bool,
}

/// One refused container, and the record the forwarder wrote beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct SpoolFailure {
    /// The container's file name in the failed directory.
    pub file: String,
    /// The `<file>.error.json` record: the status, the method and URL, and
    /// the start of the store's answer, or the forwarder's own reason. Null
    /// when the record is missing or unreadable, and `record_problem` says
    /// which.
    pub record: Option<FailureRecord>,
    /// Why `record` is null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_problem: Option<String>,
}

/// The spool's state: three counts and one page of failed records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct SpoolStatus {
    /// Version of this envelope.
    pub schema_version: u32,
    /// When the directories were read, RFC 3339 UTC. The forwarder is another
    /// process and may have moved files since.
    pub as_of: String,
    /// What this answer is, in one sentence.
    pub note: String,
    /// The `--export-vcon-dir` spool: containers waiting to be delivered.
    pub spool: SpoolDirectory,
    /// Where the forwarder moves a delivered container by default.
    pub delivered_dir: SpoolDirectory,
    /// Where the forwarder moves a refused container by default, beside its
    /// `<file>.error.json` record.
    pub failed_dir: SpoolDirectory,
    /// Containers in the spool, by the forwarder's own rule: regular files
    /// ending in `.json` whose names do not start with a dot.
    pub pending: usize,
    /// Containers in the delivered directory.
    pub delivered: usize,
    /// Containers in the failed directory, records not counted.
    pub failed: usize,
    /// This page of failed containers, by file name.
    pub failures: Vec<SpoolFailure>,
    /// Rows in `failures`.
    pub returned: usize,
    /// Whether failed containers remain after this page. Pass `next_cursor`
    /// back to continue.
    pub truncated: bool,
    /// Opaque cursor (the last file name returned) to pass to the next call.
    /// Null on the final page.
    pub next_cursor: Option<String>,
    /// The export rule whose spool this is, when the answer came from a run
    /// (`--export-vcon-when`, or a `[[vcon.rule]]` name). Absent from
    /// `sipnab --vcon-spool-status <DIR>`, which reads a directory, not a run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// Read the spool, its delivered and failed directories, and one page of
/// failure records.
///
/// A function of the directory, the page and the clock, so a test can drive
/// it over a temporary spool at a fixed instant. It opens files for reading
/// and nothing else. A directory that does not exist counts as empty.
///
/// # Arguments
///
/// * `spool` — the `--export-vcon-dir` directory.
/// * `page` — which failed records to carry.
/// * `now` — the instant stamped as `as_of`.
///
/// # Errors
///
/// A message naming the directory when one exists and cannot be read.
pub fn snapshot(
    spool: &Path,
    page: SpoolPage<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SpoolStatus, String> {
    let done = default_done_dir(spool);
    let failed = default_failed_dir(spool);
    let (spool_dir, pending_names) = read_names(spool, pending)?;
    let (done_dir, delivered_names) = read_names(&done, pending)?;
    let (failed_dir, failed_names) = read_names(&failed, failed_containers)?;

    let remaining: Vec<&String> = failed_names
        .iter()
        .filter(|name| page.after.is_none_or(|c| name.as_str() > c))
        .collect();
    let truncated = remaining.len() > page.limit;
    let shown = &remaining[..remaining.len().min(page.limit)];
    let next_cursor = truncated
        .then(|| shown.last())
        .flatten()
        .map(|n| (*n).clone());
    let failures: Vec<SpoolFailure> = shown
        .iter()
        .map(|name| {
            let record_path = failed.join(format!("{name}{ERROR_RECORD_SUFFIX}"));
            match read_record(&record_path) {
                Ok(record) => SpoolFailure {
                    file: (*name).clone(),
                    record: Some(record),
                    record_problem: None,
                },
                Err(problem) => SpoolFailure {
                    file: (*name).clone(),
                    record: None,
                    record_problem: Some(problem),
                },
            }
        })
        .collect();

    Ok(SpoolStatus {
        schema_version: 1,
        as_of: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        note: SPOOL_NOTE.to_owned(),
        spool: spool_dir,
        delivered_dir: done_dir,
        failed_dir,
        pending: pending_names.len(),
        delivered: delivered_names.len(),
        failed: failed_names.len(),
        returned: failures.len(),
        failures,
        truncated,
        next_cursor,
        rule: None,
    })
}

/// List one directory by `rule`, treating a missing directory as empty.
///
/// # Errors
///
/// A message naming the directory for any other read failure.
fn read_names(
    dir: &Path,
    rule: fn(&Path) -> std::io::Result<Vec<String>>,
) -> Result<(SpoolDirectory, Vec<String>), String> {
    let path = dir.display().to_string();
    match rule(dir) {
        Ok(names) => Ok((SpoolDirectory { path, exists: true }, names)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
            SpoolDirectory {
                path,
                exists: false,
            },
            Vec::new(),
        )),
        Err(e) => Err(format!("cannot read '{path}': {e}")),
    }
}

/// Read one failure record as the forwarder wrote it.
///
/// # Errors
///
/// A sentence naming the record when it is missing, too large, unreadable, or
/// not in the shape the forwarder writes.
fn read_record(path: &Path) -> Result<FailureRecord, String> {
    let shown = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("{shown} is missing beside the container"));
        }
        Err(e) => return Err(format!("{shown} cannot be read: {e}")),
    };
    if size > MAX_RECORD_READ {
        return Err(format!(
            "{shown} is {size} bytes, past the {MAX_RECORD_READ}-byte bound this \
             reads; read the file on the host"
        ));
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_RECORD_READ).read_to_string(&mut text))
        .map_err(|e| format!("{shown} cannot be read: {e}"))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("{shown} is not a forwarder failure record: {e}"))
}

/// Unit tests for the parts no door can reach: the clock is a parameter.
/// One export rule's spool: the rule's name and the directory it writes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spool {
    /// The rule's name; the flag rule is `--export-vcon-when`.
    pub rule: String,
    /// The directory the rule writes its containers to.
    pub dir: std::path::PathBuf,
}

/// The run's spools: the flag rule's, when `--export-vcon-dir` is given, then
/// one per `[[vcon.rule]]`, in the order the plan resolves them.
#[must_use]
pub fn spools(cli: &crate::cli::Cli, config: &crate::config::Config) -> Vec<Spool> {
    let mut out: Vec<Spool> = Vec::new();
    if cli.output_args.export_vcon_when.is_some()
        && let Some(dir) = cli.output_args.export_vcon_dir.clone()
    {
        out.push(Spool {
            rule: "--export-vcon-when".to_owned(),
            dir,
        });
    }
    out.extend(config.vcon.rule.iter().filter_map(|r| {
        r.dir.clone().map(|dir| Spool {
            rule: r.name.clone(),
            dir,
        })
    }));
    out
}

/// Why no spool was picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickError {
    /// The run has no export rule, so no spool.
    NoSpool,
    /// Several rules write spools and none was named; holds the names.
    Ambiguous(Vec<String>),
    /// The named rule is not one of the run's; holds it and the names.
    Unknown(String, Vec<String>),
}

impl std::fmt::Display for PickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSpool => f.write_str(
                "this run has no vCon export spool: start sipnab with --export-vcon-when \
                 <EXPR> --export-vcon-dir <DIR>, or with a [[vcon.rule]] in the config",
            ),
            Self::Ambiguous(names) => write!(
                f,
                "this run writes {} spools; name one with rule: {}",
                names.len(),
                names.join(", ")
            ),
            Self::Unknown(rule, names) => write!(
                f,
                "this run has no export rule '{rule}'; its rules are: {}",
                names.join(", ")
            ),
        }
    }
}

/// The spool `rule` names, or the only one when the run has one and `rule` is
/// unset. The one choice the REST route and the MCP tool both make.
///
/// # Errors
///
/// No spool, several and none named, or a name the run does not use.
pub fn pick<'a>(spools: &'a [Spool], rule: Option<&str>) -> Result<&'a Spool, PickError> {
    let names = || spools.iter().map(|s| s.rule.clone()).collect::<Vec<_>>();
    match (spools, rule) {
        ([], _) => Err(PickError::NoSpool),
        ([only], None) => Ok(only),
        (_, None) => Err(PickError::Ambiguous(names())),
        (_, Some(name)) => spools
            .iter()
            .find(|s| s.rule == name)
            .ok_or_else(|| PickError::Unknown(name.to_owned(), names())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// `as_of` is the instant passed in, not the moment of the call, so a
    /// caller comparing two doors can hold the clock still.
    #[test]
    fn as_of_is_the_instant_given() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 10, 11, 12, 0, 0)
            .single()
            .ok_or("a real instant")?;
        let status = snapshot(dir.path(), SpoolPage::all(), at)?;
        assert_eq!(status.as_of, "2026-10-11T12:00:00.000Z");
        assert!(status.spool.exists && !status.delivered_dir.exists);
        Ok(())
    }

    fn spool(rule: &str, dir: &str) -> Spool {
        Spool {
            rule: rule.to_owned(),
            dir: std::path::PathBuf::from(dir),
        }
    }

    /// One spool needs no name; several need one, and the refusal lists the
    /// names; a name nothing uses is refused the same way; no spool at all is
    /// its own answer.
    #[test]
    fn a_spool_is_picked_by_rule_name_when_there_are_several() {
        let one = [spool("--export-vcon-when", "/s")];
        assert_eq!(
            pick(&one, None).map(|s| s.rule.as_str()),
            Ok("--export-vcon-when")
        );
        let two = [spool("support", "/a"), spool("all", "/b")];
        assert_eq!(
            pick(&two, Some("all")).map(|s| s.dir.clone()),
            Ok("/b".into())
        );
        let ambiguous = pick(&two, None)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(ambiguous.contains("support, all"), "{ambiguous}");
        let unknown = pick(&two, Some("nope"))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            unknown.contains("'nope'") && unknown.contains("support, all"),
            "{unknown}"
        );
        assert_eq!(pick(&[], None).err(), Some(PickError::NoSpool));
    }
}
