// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one place a test decides what to do when something it needs from its
//! environment is missing.
//!
//! The lib's unit tests reach it as `crate::test_prereq`; integration tests
//! mount this same file with `#[path = "../src/test_prereq.rs"]`, so both
//! sides use one definition.
//!
//! # The defect
//!
//! A test that needs passwordless sudo, a tool on `PATH` or a kernel feature
//! looked for it and returned `Ok(())` when it was not there. libtest and
//! nextest report that as `ok`, the same word they use for a test that ran
//! and passed, so a suite could be green while those tests tested nothing.
//! Printing a notice first did not help: libtest drops a passing test's
//! captured `eprintln!` output, and nextest's `suite` profile drops a passing
//! test's whole output.
//!
//! # The rule
//!
//! [`verdict`] is the rule, as a pure function:
//!
//! - a prerequisite that is present: the test runs;
//! - a [`Need::Required`] prerequisite that is missing: the test fails,
//!   naming it;
//! - a [`Need::Optional`] prerequisite that is missing: the test is skipped,
//!   unless [`REQUIRE_VAR`] names it (or says `all`), and then it fails.
//!
//! A skip writes a notice to the process's real stderr (not `eprintln!`) and
//! appends one line to the ledger file [`LEDGER_VAR`] names, so
//! `scripts/parallel-tests.py` can count every skip of a suite run and print
//! the total. A skip the ledger cannot record fails the test instead.
//!
//! `tests/prereq_skip_gate_test.rs` refuses an early return from a test that
//! does not go through this module.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Names the optional prerequisites that are required in this environment,
/// comma- or space-separated; `all` names every one. CI sets it to what its
/// runners install.
pub const REQUIRE_VAR: &str = "SIPNAB_REQUIRE_PREREQS";

/// Names the file each skip appends one line to:
/// `binary<TAB>test<TAB>prerequisite<TAB>reason`.
pub const LEDGER_VAR: &str = "SIPNAB_PREREQ_SKIP_LEDGER";

/// The fragment every skip notice carries, for tests and for `grep`.
pub const NOTICE_MARKER: &str = "did NOT run";

/// The test name used when the running thread has none.
pub const UNNAMED_TEST: &str = "<unnamed test>";

/// Every prerequisite name a test may ask for. A name not listed here fails
/// the test, on every host: a misspelled name would never match the require
/// list, and the test it guards could skip in CI unseen.
pub const KNOWN: &[&str] = &[
    // An account or a privilege.
    "sudo",
    "root",
    "non-root",
    "cap-net-raw",
    "capture-refused",
    "no-new-privs-off",
    // A kernel or platform feature.
    "landlock",
    "seccomp",
    "dev-full",
    "proc-maps",
    "ipv6-loopback",
    "raw-ipv6-loopback",
    "non-loopback-address",
    "separate-shm",
    "monotonic-uptime",
    "instant-range",
    "os-random",
    "user-namespace",
    "ca-bundle",
    "tls-library",
    "lsm-list",
    // A tool on PATH.
    "addr2line",
    "cross-linker",
    "editcap",
    "fc-list",
    "gh",
    "git",
    "groff",
    "node",
    "python3",
    "setpriv",
    "strings",
    "tar",
    "tshark",
    // Data that is not in every checkout.
    "corpus",
    "vcon-datasets",
    "real-world-captures",
    "tfps-ctl",
    "tfps-labels",
    "git-checkout",
    "git-dir",
    "tracked-file",
    "home",
    "local-backlog",
    "release-history",
];

/// How a test needs a prerequisite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Missing fails the test.
    Required,
    /// Missing skips the test, unless [`REQUIRE_VAR`] names the
    /// prerequisite. The text says why a host may lack it.
    Optional(&'static str),
}

/// The need of a test that writes to `/dev/full` to make a write fail.
pub const DEV_FULL: Need =
    Need::Optional("/dev/full exists on Linux only; CI's Linux runners have it.");

/// `/dev/full`, when this host has it.
///
/// # Errors
/// When it does not.
pub fn dev_full() -> Result<PathBuf, String> {
    path_exists(Path::new("/dev/full"))
}

/// The need of a test that sets an `Instant` in the past: a monotonic clock
/// that started more recently than that cannot hold it.
pub const MONOTONIC_UPTIME: Need = Need::Optional(
    "a host that booted moments ago has a monotonic clock too young to go back that far.",
);

/// The `Instant` `ago` before now, when the monotonic clock reaches back
/// that far.
///
/// # Errors
/// When it does not.
pub fn instant_ago(ago: std::time::Duration) -> Result<std::time::Instant, String> {
    std::time::Instant::now()
        .checked_sub(ago)
        .ok_or_else(|| format!("the monotonic clock is younger than {ago:?}"))
}

/// What a test does about one prerequisite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Run the test.
    Run,
    /// Skip the test, with a notice and a ledger line.
    Skip,
    /// Fail the test.
    Fail,
}

/// Why [`check_in`] failed a test.
#[derive(Debug)]
pub enum PrereqError {
    /// The prerequisite is missing and required here.
    Missing {
        /// The test.
        test: String,
        /// The prerequisite.
        prereq: String,
        /// The probe's answer.
        why: String,
        /// Whether [`REQUIRE_VAR`] made an optional prerequisite required.
        by_require_list: bool,
    },
    /// The skip could not be written to the ledger.
    Uncounted {
        /// The test.
        test: String,
        /// The ledger file.
        ledger: PathBuf,
        /// The write's error.
        error: String,
    },
    /// The prerequisite's name is not in [`KNOWN`].
    Unknown {
        /// The test.
        test: String,
        /// The name.
        prereq: String,
    },
}

impl fmt::Display for PrereqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing {
                test,
                prereq,
                why,
                by_require_list,
            } => {
                write!(f, "test `{test}` needs `{prereq}`, which is missing: {why}")?;
                if *by_require_list {
                    write!(f, " ({REQUIRE_VAR} names it, so it is required here)")?;
                }
                Ok(())
            }
            Self::Uncounted {
                test,
                ledger,
                error,
            } => write!(
                f,
                "test `{test}` skipped, and the skip could not be counted in {} \
                 ({LEDGER_VAR}): {error}",
                ledger.display()
            ),
            Self::Unknown { test, prereq } => write!(
                f,
                "test `{test}` asks for prerequisite `{prereq}`, which is not in \
                 test_prereq::KNOWN"
            ),
        }
    }
}

impl std::error::Error for PrereqError {}

/// Where a check runs: the test, the require list and the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The test binary.
    pub binary: String,
    /// The test.
    pub test: String,
    /// The value of [`REQUIRE_VAR`], when set and not empty.
    pub require: Option<String>,
    /// The value of [`LEDGER_VAR`], when set and not empty.
    pub ledger: Option<PathBuf>,
}

impl Context {
    /// The context of the running test, from its thread's name and the
    /// environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_values(
            env!("CARGO_CRATE_NAME"),
            std::thread::current().name().map(str::to_owned),
            std::env::var_os(REQUIRE_VAR),
            std::env::var_os(LEDGER_VAR),
        )
    }

    /// The context built from given values, so each can be driven.
    ///
    /// # Arguments
    /// * `binary` — the test binary's crate name.
    /// * `thread` — the running thread's name; libtest names it after the
    ///   test, and `main` is not a test.
    /// * `require`, `ledger` — the two variables' values; empty is unset.
    #[must_use]
    pub fn from_values(
        binary: &str,
        thread: Option<String>,
        require: Option<OsString>,
        ledger: Option<OsString>,
    ) -> Self {
        let test = thread
            .filter(|name| name != "main" && !name.is_empty())
            .unwrap_or_else(|| UNNAMED_TEST.to_owned());
        Self {
            binary: binary.to_owned(),
            test,
            require: require
                .map(|v| v.to_string_lossy().into_owned())
                .filter(|v| !v.is_empty()),
            ledger: ledger.filter(|v| !v.is_empty()).map(PathBuf::from),
        }
    }
}

/// Whether the require list `list` names `prereq`, or says `all`.
#[must_use]
pub fn listed(prereq: &str, list: &str) -> bool {
    list.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .any(|item| item == prereq || item == "all")
}

/// The rule: what a test does about a prerequisite.
///
/// # Arguments
/// * `present` — whether the probe found it.
/// * `prereq` — its name.
/// * `need` — how the test needs it.
/// * `require` — the require list, when set.
#[must_use]
pub fn verdict(present: bool, prereq: &str, need: Need, require: Option<&str>) -> Verdict {
    if present {
        return Verdict::Run;
    }
    match need {
        Need::Required => Verdict::Fail,
        Need::Optional(_) if require.is_some_and(|list| listed(prereq, list)) => Verdict::Fail,
        Need::Optional(_) => Verdict::Skip,
    }
}

/// One field of a ledger line: tabs and line breaks become spaces.
fn field(text: &str) -> String {
    text.chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// The ledger line of one skip, without its line break.
#[must_use]
pub fn ledger_line(binary: &str, test: &str, prereq: &str, reason: &str) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        field(binary),
        field(test),
        field(prereq),
        field(reason)
    )
}

/// The notice of one skip, without its line break.
fn notice_line(test: &str, prereq: &str, why: &str, reason: &str) -> String {
    format!(
        "NOTICE: test `{}` {NOTICE_MARKER}: `{}` is missing ({}); {} \
         Set {REQUIRE_VAR}={} to make this a failure.",
        field(test),
        field(prereq),
        field(why),
        field(reason),
        field(prereq)
    )
}

/// Skips in this process.
static SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// How many tests this process has skipped through [`check_in`].
#[must_use]
pub fn skipped() -> usize {
    SKIPPED.load(Ordering::Relaxed)
}

/// Append `line` to `ledger`.
fn append(ledger: &Path, line: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger)?;
    // One write of the whole line: appends of one short write do not
    // interleave between the processes of one suite run.
    file.write_all(format!("{line}\n").as_bytes())
}

/// Decide about one prerequisite, with every input given.
///
/// # Arguments
/// * `ctx` — the test, the require list and the ledger.
/// * `err` — where a skip's notice goes (the real stderr in a test).
/// * `prereq` — a name from [`KNOWN`].
/// * `need` — how the test needs it.
/// * `probe` — what was found, or why nothing was.
///
/// # Returns
/// `Ok(Some(value))` to run, `Ok(None)` to skip (notice written, skip
/// counted).
///
/// # Errors
/// [`PrereqError::Unknown`] for a name not in [`KNOWN`];
/// [`PrereqError::Missing`] when the verdict is to fail;
/// [`PrereqError::Uncounted`] when the ledger cannot take the skip.
pub fn check_in<T>(
    ctx: &Context,
    err: &mut dyn Write,
    prereq: &str,
    need: Need,
    probe: Result<T, String>,
) -> Result<Option<T>, PrereqError> {
    if !KNOWN.contains(&prereq) {
        return Err(PrereqError::Unknown {
            test: ctx.test.clone(),
            prereq: prereq.to_owned(),
        });
    }
    let present = probe.is_ok();
    match (
        verdict(present, prereq, need, ctx.require.as_deref()),
        probe,
    ) {
        (Verdict::Run, Ok(value)) => Ok(Some(value)),
        (Verdict::Fail, Err(why)) => Err(PrereqError::Missing {
            test: ctx.test.clone(),
            prereq: prereq.to_owned(),
            why,
            by_require_list: matches!(need, Need::Optional(_)),
        }),
        (_, probe) => {
            let why = probe.err().unwrap_or_default();
            let reason = match need {
                Need::Optional(reason) => reason,
                Need::Required => "",
            };
            if let Some(ledger) = &ctx.ledger {
                append(ledger, &ledger_line(&ctx.binary, &ctx.test, prereq, reason)).map_err(
                    |e| PrereqError::Uncounted {
                        test: ctx.test.clone(),
                        ledger: ledger.clone(),
                        error: e.to_string(),
                    },
                )?;
            }
            SKIPPED.fetch_add(1, Ordering::Relaxed);
            // A write error is ignored: the ledger holds the count, and a
            // closed stderr must not turn a counted skip into a failure.
            let _ = writeln!(err, "{}", notice_line(&ctx.test, prereq, &why, reason));
            Ok(None)
        }
    }
}

/// Decide about one prerequisite for the running test.
///
/// # Errors
/// As [`check_in`].
pub fn check<T>(
    prereq: &str,
    need: Need,
    probe: Result<T, String>,
) -> Result<Option<T>, PrereqError> {
    // The real stderr, NOT eprintln!: libtest discards a passing test's
    // captured print output.
    check_in(
        &Context::from_env(),
        &mut std::io::stderr(),
        prereq,
        need,
        probe,
    )
}

/// A prerequisite the running test cannot do without.
///
/// # Errors
/// As [`check_in`], with [`Need::Required`].
pub fn required<T>(prereq: &str, probe: Result<T, String>) -> Result<T, PrereqError> {
    check(prereq, Need::Required, probe)?.ok_or_else(|| PrereqError::Unknown {
        // Unreachable: a required prerequisite is never skipped.
        test: Context::from_env().test,
        prereq: prereq.to_owned(),
    })
}

/// The `Option` form, for a helper that cannot return an error: the value
/// to run with, or `None` to skip.
///
/// # Panics
/// When the verdict is to fail, with the error's text, so the test fails by
/// name. This is the one place a prerequisite fails a test by panicking.
#[must_use]
pub fn decide<T>(prereq: &str, need: Need, probe: Result<T, String>) -> Option<T> {
    match check(prereq, need, probe) {
        Ok(found) => found,
        Err(e) => panic!("{e}"), // gate: panic because a bool or Option caller has no error to return, and failing loudly is this helper's contract
    }
}

/// The `if` form: `true` to run, `false` to skip.
///
/// # Panics
/// As [`decide`].
#[must_use]
pub fn present(prereq: &str, need: Need, probe: Result<(), String>) -> bool {
    decide(prereq, need, probe).is_some()
}

/// The need of a test whose case root cannot build: root is granted what
/// the case denies.
pub const NON_ROOT: Need = Need::Optional(
    "root is granted what the case denies, so the case cannot be built as root; \
     CI runs the suite as an ordinary user.",
);

/// The `if` form of the `non-root` prerequisite, given whether the test
/// process runs as root.
///
/// # Panics
/// As [`present`].
#[must_use]
pub fn not_root(is_root: bool) -> bool {
    present("non-root", NON_ROOT, root_probe(is_root))
}

/// The probe of the `non-root` prerequisite, given whether the test process
/// runs as root.
///
/// # Errors
/// When it does.
pub fn root_probe(is_root: bool) -> Result<(), String> {
    if is_root {
        Err("this test process runs as root".to_owned())
    } else {
        Ok(())
    }
}

/// The first file named `tool` in the directories of `path`.
///
/// # Errors
/// When none of them holds a file of that name.
pub fn on_path_in(tool: &str, path: Option<&OsStr>) -> Result<PathBuf, String> {
    path.into_iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{tool} is not on PATH"))
}

/// The first file named `tool` on this process's `PATH`.
///
/// # Errors
/// As [`on_path_in`].
pub fn on_path(tool: &str) -> Result<PathBuf, String> {
    on_path_in(tool, std::env::var_os("PATH").as_deref())
}

/// `path`, when it exists.
///
/// # Errors
/// When it does not.
pub fn path_exists(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        Ok(path.to_path_buf())
    } else {
        Err(format!("{} does not exist", path.display()))
    }
}

/// The value of `var`, given as `value`, when it is set and not empty.
///
/// # Errors
/// When it is unset or empty.
pub fn env_value(var: &str, value: Option<OsString>) -> Result<String, String> {
    value
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{var} is not set"))
}

/// The value of the environment variable `var`, when set and not empty.
///
/// # Errors
/// As [`env_value`].
pub fn env(var: &str) -> Result<String, String> {
    env_value(var, std::env::var_os(var))
}
