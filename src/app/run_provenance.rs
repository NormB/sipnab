// SPDX-License-Identifier: MIT OR Apache-2.0

//! One record, written once at startup, saying how this run was invoked
//! (AUDIT1).
//!
//! # The gap this closes
//!
//! A JSON report, a vCon container and an exported pcap all say what sipnab
//! CONCLUDED. Nothing in them says which invocation produced it — which
//! capture, which filter, which port range, which retention caps. `--portrange`
//! alone changes what a run is able to see, and a report produced under a
//! narrow range is afterwards indistinguishable from one that examined
//! everything. Anyone reconciling two reports of the same traffic has no way
//! to ask why they differ.
//!
//! `--mcp-audit-file` already answers the equivalent question for an AGENT's
//! tool calls. It answers nothing for a human running the binary: before this
//! module, nothing in `src/app/` or `src/main.rs` read [`std::env::args`] at
//! all, so a run's own arguments reached no log, no report and no export.
//!
//! # Fail-closed, and why that is the right rule HERE
//!
//! A provenance record that could not be written stops the run, naming the
//! path. A best-effort line would be worse than none: its absence would then
//! mean either "not enabled" or "the disk was full", and no reader could tell
//! which. The cost of the rule is bounded because of WHERE it runs — before
//! the config is loaded, before any capture device is opened, before a single
//! packet exists. Stopping here loses nothing, which is exactly the argument
//! that does NOT hold for the TUI action trail mid-session; see
//! `tui::action_trail` for the opposite decision and its reasons. Named as
//! text rather than linked: that module exists only in a `tui` build and this
//! one compiles without it.
//!
//! # Privacy
//!
//! `argv` routinely holds a capture path and a path routinely holds a
//! customer name, so this file gets the same `0600` the MCP audit file gets,
//! and for the same reason. It is created by
//! [`crate::app::audit::AuditSink`], which is the only writer in the tree —
//! one set of open flags, one mode, one numbering scheme.

use std::path::{Path, PathBuf};

use crate::app::audit::AuditSink;
use crate::cli::Cli;

/// How one run of sipnab was invoked.
///
/// Owned rather than borrowed, unlike
/// [`AuditRecord`](crate::app::audit::AuditRecord): this is built once per
/// process, so an allocation per field costs nothing, while `argv` and the
/// resolved user name have no longer-lived owner to borrow from.
#[derive(Debug, Clone)]
pub struct RunProvenance {
    /// The command line as the kernel handed it over, argument by argument.
    ///
    /// A LIST and not a joined string, deliberately. Joining loses where each
    /// argument ended, and a capture path containing a space then reads as
    /// two arguments to whoever reconstructs the command later — which is the
    /// one thing this record exists to make impossible to get wrong.
    pub argv: Vec<String>,
    /// The working directory the run started in, so a relative `-I` in
    /// `argv` resolves to the file it actually read.
    pub cwd: String,
    /// Effective user id. Numeric and authoritative: a container renumbers
    /// names, and the kernel's answer is the one that decided what this run
    /// was allowed to open.
    pub uid: u32,
    /// The password-database name for [`Self::uid`], empty when the uid maps
    /// to no entry. A convenience beside the number, never instead of it.
    pub user: String,
    /// Process id, so this record pairs with a syslog line or a core file
    /// from the same run.
    pub pid: u32,
    /// Wall-clock time the run began.
    pub started: chrono::DateTime<chrono::Utc>,
    /// Full version banner — semver, commit, dirty marker and features, the
    /// same string `--version` prints.
    pub version: String,
    /// The compiled feature set on its own, from
    /// [`crate::cli::compiled_features`]. Present as well as inside
    /// [`Self::version`] because a reader filtering "which runs could export
    /// a vCon" is asking about this list, and parsing it back out of a banner
    /// is how that filter goes wrong.
    pub features: Vec<&'static str>,
    /// Which capture this run started with — the SAME token the MCP and REST
    /// surfaces stamp on their answers, taken from
    /// [`crate::provenance::run_identity`] rather than minted here.
    pub capture: crate::provenance::CaptureEtag,
}

impl RunProvenance {
    /// Collect the facts about the run in progress.
    ///
    /// # Returns
    ///
    /// The record. Every field is read here rather than at write time, so the
    /// line describes the process as it started even if something later
    /// changes the working directory or drops privileges.
    ///
    /// # Side effects
    ///
    /// Reads the process arguments, the working directory and the effective
    /// uid, and resolves that uid through the system password database. The
    /// password lookup is the reason this belongs at single-threaded startup:
    /// the first `getpw*_r` in a process makes glibc `dlopen` the NSS
    /// backends, and that loader work can deadlock against concurrent thread
    /// creation. See `privilege::resolve_user`, which has the same
    /// constraint for the same reason.
    #[must_use]
    pub fn of_this_run() -> Self {
        let uid = effective_uid();
        Self {
            // Lossy on purpose. An argument that is not UTF-8 is still part of
            // how the run was invoked, and refusing to record the line because
            // one byte was undecodable would lose the whole record over the
            // least interesting part of it.
            argv: std::env::args_os()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                // An unreadable cwd (deleted underneath the process) is a
                // fact about the run, not a reason to refuse to record it.
                .unwrap_or_default(),
            uid,
            user: user_name(uid),
            pid: std::process::id(),
            started: chrono::Utc::now(),
            version: crate::cli::build_version(),
            features: crate::cli::compiled_features(),
            // Generations 0 and 0 because nothing has been ingested yet, which
            // is the truth at startup and the reason the record is written
            // here: the instance is what joins this line to a later answer,
            // and the generations say where that answer's stores began.
            capture: crate::provenance::run_identity().etag(0, 0),
        }
    }

    /// Render this record as one JSON object, without a trailing newline.
    ///
    /// The same shape [`AuditRecord::to_line`](crate::app::audit::AuditRecord::to_line)
    /// produces and for the same reason: `serde_json` escapes every value, so
    /// a capture path containing a quote or a newline cannot end the line or
    /// forge a field. A `key=value` console line cannot promise that, and
    /// `argv` is operator text.
    ///
    /// # Arguments
    ///
    /// * `seq` — the sequence number the sink allocated.
    /// * `ts` — when the sink wrote the line.
    #[must_use]
    pub fn to_line(&self, seq: u64, ts: chrono::DateTime<chrono::Utc>) -> String {
        serde_json::json!({
            "seq": seq,
            "ts": ts.to_rfc3339(),
            // A discriminator, because this file and the MCP audit file have
            // the same shape and an operator will eventually point both flags
            // at one path. A reader selecting `.record` never has to guess
            // which kind of line it is holding.
            "record": "run",
            "argv": self.argv,
            "cwd": self.cwd,
            "uid": self.uid,
            "user": self.user,
            "pid": self.pid,
            "started": self.started.to_rfc3339(),
            "version": self.version,
            "features": self.features,
            "capture": self.capture,
        })
        .to_string()
    }
}

/// The effective uid of this process.
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, reads kernel state and is defined
    // never to fail. There is no pointer and no error case.
    unsafe { libc::geteuid() }
}

/// The password-database name for `uid`, or an empty string when it has none.
///
/// Uses the reentrant `getpwuid_r` for the same reason
/// `privilege::resolve_user` uses `getpwnam_r`: the non-reentrant form returns
/// a pointer into a shared static buffer that a concurrent lookup on another
/// thread can overwrite between the call and reading the fields.
///
/// A uid with no entry is normal — a container, or a run under a uid the host
/// does not name — so it returns empty rather than an error. The number is the
/// authoritative field; this one is the courtesy.
fn user_name(uid: u32) -> String {
    // Initial scratch-buffer size for the string fields; grow on ERANGE.
    // SAFETY: `sysconf` takes no pointers and only reads a system constant.
    let mut buf_len: usize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 16_384,
    };
    loop {
        // SAFETY: `libc::passwd` is a plain-old-data C struct for which
        // all-zero bytes is a valid (if meaningless) value; `getpwuid_r`
        // overwrites it before any field is read.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `getpwuid_r` writes the entry into our owned `pwd` and its
        // string fields into our owned `buf`; on success `result` points at
        // `pwd`. `pw_name` is read below only while both are still alive, and
        // is copied out before either drops.
        let ret =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf_len, &mut result) };
        if ret == libc::ERANGE && buf_len < (1 << 20) {
            buf_len *= 2;
            continue;
        }
        if ret != 0 || result.is_null() {
            return String::new();
        }
        // SAFETY: `result` is non-null, so `pwd.pw_name` is a NUL-terminated
        // C string living in `buf`, which is still owned and alive here.
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        return name.to_string_lossy().into_owned();
    }
}

/// Who this process is running as, as one `uid=<n> user=<name>` token.
///
/// The caller identity for a surface that has no network peer to name. The
/// MCP audit record answers "who called" with a socket and an admission
/// record; a person at a terminal has neither, so what the process can
/// actually prove is the account it is running as. One spelling in one place,
/// because the run provenance record and the TUI action trail both report it
/// and two renderings of one fact are two things to keep in step.
///
/// # Returns
///
/// `uid=1000 user=alice`, or `uid=1000` alone when the uid maps to no
/// password-database entry.
///
/// # Side effects
///
/// Reads the effective uid and resolves it through the system password
/// database — see [`RunProvenance::of_this_run`] for why that belongs at
/// single-threaded startup.
#[must_use]
pub fn effective_user_label() -> String {
    let uid = effective_uid();
    let name = user_name(uid);
    if name.is_empty() {
        format!("uid={uid}")
    } else {
        format!("uid={uid} user={name}")
    }
}

/// Write the run's provenance record, when `--run-provenance-file` named a
/// path.
///
/// # Arguments
///
/// * `cli` — the parsed command line, read only for the flag. The RECORD is
///   built from the process itself, not from `cli`: a reconstruction from
///   parsed flags would print clap's idea of the invocation rather than the
///   invocation, and the two differ wherever a default filled in.
///
/// # Returns
///
/// `Ok(None)` when the flag was absent — the off-by-default path, where
/// nothing is created and nothing changes. `Ok(Some(path))` when the record
/// was written.
///
/// # Errors
///
/// A message naming the path and what went wrong, for every failure to open
/// or write. The caller stops the run on it; see this module's header for why
/// a best-effort record would be worse than none.
///
/// # Side effects
///
/// Creates the file when absent, mode `0600` on Unix, and appends one line.
/// An existing file is appended to and never truncated, so successive runs
/// accumulate and a reader can follow which invocation produced which
/// artefact.
pub fn write_record(cli: &Cli) -> Result<Option<PathBuf>, String> {
    let Some(path) = cli.security_args.run_provenance_file.as_deref() else {
        return Ok(None);
    };
    let path = Path::new(path);
    let sink = AuditSink::open(path).map_err(|e| {
        format!(
            "--run-provenance-file {}: {e}. sipnab refuses to run without the \
             provenance record it was asked for -- a missing record would \
             otherwise be indistinguishable from a run nobody asked to record",
            path.display()
        )
    })?;
    let record = RunProvenance::of_this_run();
    sink.append_with(|seq, ts| record.to_line(seq, ts))
        .map_err(|e| {
            format!(
                "--run-provenance-file {}: {e}. sipnab refuses to run without the \
                 provenance record it was asked for -- a missing record would \
                 otherwise be indistinguishable from a run nobody asked to record",
                path.display()
            )
        })?;
    Ok(Some(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record carries the invocation, not a reconstruction of it.
    #[test]
    fn the_record_holds_argv_cwd_user_version_and_the_capture_instance() {
        let rec = RunProvenance::of_this_run();
        let line = rec.to_line(1, chrono::Utc::now());
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON record");

        assert_eq!(v["record"], "run");
        assert!(
            v["argv"].as_array().is_some_and(|a| !a.is_empty()),
            "argv must carry at least the program name: {v}"
        );
        assert!(
            !v["cwd"].as_str().unwrap_or_default().is_empty(),
            "the working directory decides what a relative -I resolved to: {v}"
        );
        assert_eq!(v["uid"].as_u64(), Some(u64::from(effective_uid())));
        assert!(
            v["version"]
                .as_str()
                .unwrap_or_default()
                .starts_with(env!("CARGO_PKG_VERSION")),
            "the record must name the build that produced the report: {v}"
        );
        assert_eq!(
            v["capture"]["instance"].as_str(),
            Some(crate::provenance::run_identity().instance()),
            "the record must name the SAME capture instance every other \
             surface stamps, or nothing can be joined to it: {v}"
        );
        assert_eq!(v["capture"]["dialog_generation"], 0);
        assert_eq!(v["capture"]["stream_generation"], 0);
    }

    /// A hostile capture path cannot forge a second record or end a field.
    ///
    /// `argv` is whatever the shell handed over, and a directory an attacker
    /// can name is a directory whose name they choose. A newline in it would
    /// append a line that reads exactly like a genuine record of a run that
    /// never happened, which is worse than a missing record: it is a false
    /// one.
    #[test]
    fn a_newline_in_argv_cannot_forge_a_second_record() {
        let mut rec = RunProvenance::of_this_run();
        rec.argv = vec![
            "sipnab".into(),
            "-I".into(),
            "/tmp/a\n{\"record\":\"run\",\"argv\":[\"sipnab\",\"--everything\"]}".into(),
        ];
        let line = rec.to_line(1, chrono::Utc::now());
        assert_eq!(
            line.lines().count(),
            1,
            "the path forged a second record: {line}"
        );
        let v: serde_json::Value = serde_json::from_str(&line).expect("one valid JSON line");
        assert!(
            v["argv"][2]
                .as_str()
                .expect("argv[2]")
                .contains("--everything"),
            "the hostile text must still be RECORDED, only defanged: {v}"
        );
    }

    /// The uid resolves to the name of the account running the test, when the
    /// host names it at all.
    #[test]
    fn the_effective_uid_resolves_or_reports_nothing() {
        let name = user_name(effective_uid());
        // Not asserted non-empty: a container uid with no passwd entry is a
        // legitimate answer, and this must not fail there. What it must never
        // do is return a name for a uid that has none.
        assert!(
            user_name(u32::MAX - 1).is_empty(),
            "a uid with no password entry must report no name, not a guess"
        );
        assert!(
            !name.contains('\0'),
            "a resolved name must be a real string: {name:?}"
        );
    }
}
