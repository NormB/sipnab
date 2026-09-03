// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TFPS peer: finding `tfps_ctl`, asking it, and reading what it answers.
//!
//! # TFPS is optional peer software
//!
//! TFPS is a toll-fraud prevention system an operator may run on the same host
//! as sipnab. It decides which sources to condemn and enforces that decision
//! in the firewall; sipnab captures and analyzes and never bans anything. The
//! two meet through one program, `tfps_ctl`, which sipnab runs as a child
//! process and reads JSON from. There is no `tfps` crate in the manifest and
//! `tfps_label_corpus_test::sipnab_does_not_depend_on_tfps` keeps it that way.
//!
//! A machine with no TFPS runs sipnab unchanged and silent. Nothing here runs
//! at startup: the executable is looked for on `PATH` only when a TFPS tool is
//! invoked, and its absence is an ANSWER -- `installed: false` with the reason
//! -- rather than an error. A non-zero exit or unreadable output IS an error,
//! and it carries `tfps_ctl`'s standard error verbatim, because that text is
//! the only diagnosis anyone will get. One exception, and it is TFPS's own
//! convention: `ban` and `unban` exit 1 when a request was REFUSED, and still
//! print the structured result. A refusal is an answer -- the peer saying no,
//! and why -- so it is reported as one rather than raised.
//!
//! # The contract
//!
//! What `tfps_ctl` prints is pinned by fixtures under `tests/fixtures/` that
//! are byte-identical with the copies in the TFPS tree -- `tfps_contract_test`
//! pins each file's SHA-256 and proves each parses into the type here. Every
//! field is present on every row and `null` when TFPS does not know it, which
//! is why so many are `Option`. The argument shapes sipnab sends follow
//! `tfps_ctl`'s own grammar -- `--db PATH`, `--ttl N`, `--limit N`, each a
//! flag and a value as two `argv` elements -- and are pinned by
//! [`TfpsCommand::argv`]. Nothing a caller typed is ever interpolated into a
//! shell line, and an address reaches the positional slot only after it has
//! parsed as one.
//!
//! # Testable by construction
//!
//! The executable is an INPUT. [`TfpsLocator::with_search_path`] replaces the
//! `PATH` the lookup walks and an explicit path replaces the lookup itself, so
//! a test hands the locator a shell script that echoes a fixture, or exits 3
//! with a message, or a directory holding nothing -- and never needs a real
//! TFPS, and never edits the process environment.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The executable's name, as looked for on `PATH`.
pub const TFPS_CTL: &str = "tfps_ctl";

/// How long one `tfps_ctl` invocation may run before sipnab stops waiting.
///
/// A peer that hangs must not hang the MCP session or the REST request that
/// asked. Ten seconds is generous for a local SQLite read and far short of
/// any HTTP client's patience.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most bytes of standard output sipnab reads back from one invocation.
///
/// `tfps_labels` with no limit asks for the whole verdict log, which is large
/// on a long-lived installation and still far under this. A peer that streams
/// past it is reported rather than read into memory without bound.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// The answer every TFPS surface gives when the peer is not installed.
///
/// One string, in one place: both doors and the documentation quote it.
pub const NOT_INSTALLED_REASON: &str = "tfps_ctl not found on PATH; pass --tfps-ctl or [tfps] ctl";

/// Where `tfps_ctl` is, or how to look for it.
///
/// Built once from the command line and the config file and carried by both
/// the MCP server and the REST state. Cheap to clone: two optional paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TfpsLocator {
    /// `--tfps-ctl` or `[tfps] ctl`. `None` means look on `PATH` when asked.
    ctl: Option<PathBuf>,
    /// `[tfps] db`, passed through as `--db <path>` on every invocation.
    db: Option<PathBuf>,
    /// The `PATH` to walk instead of the process's own. Tests only; `None`
    /// reads the environment at the moment of the call.
    search_path: Option<OsString>,
}

impl TfpsLocator {
    /// A locator from an explicit executable and an optional database.
    #[must_use]
    pub fn new(ctl: Option<PathBuf>, db: Option<PathBuf>) -> Self {
        Self {
            ctl,
            db,
            search_path: None,
        }
    }

    /// Resolve the flag against the config file: the flag wins.
    ///
    /// # Arguments
    ///
    /// * `cli_ctl` — `--tfps-ctl`, when given.
    /// * `config_ctl` — `[tfps] ctl`, when set.
    /// * `config_db` — `[tfps] db`, when set. There is no flag for it: the
    ///   database is a property of the installation, not of a run.
    #[must_use]
    pub fn resolve(
        cli_ctl: Option<&Path>,
        config_ctl: Option<&Path>,
        config_db: Option<&Path>,
    ) -> Self {
        Self::new(
            cli_ctl.or(config_ctl).map(Path::to_path_buf),
            config_db.map(Path::to_path_buf),
        )
    }

    /// Walk this `PATH` instead of the process's own.
    ///
    /// The executable is an input to every test, and the process environment
    /// is shared by every test in the binary; this is how a test says "no
    /// TFPS here" without unsetting `PATH` for its neighbors.
    #[must_use]
    pub fn with_search_path(mut self, path: impl Into<OsString>) -> Self {
        self.search_path = Some(path.into());
        self
    }

    /// The explicit executable, when one was configured.
    #[must_use]
    pub fn ctl(&self) -> Option<&Path> {
        self.ctl.as_deref()
    }

    /// The database passed through as `--db`, when one was configured.
    #[must_use]
    pub fn db(&self) -> Option<&Path> {
        self.db.as_deref()
    }

    /// Where `tfps_ctl` is, or `None` when it is nowhere sipnab may look.
    ///
    /// An explicit path is returned as given, whether or not it exists: the
    /// operator named it, and a name that does not run is reported by the
    /// spawn as an error naming the path, not folded into "not installed".
    /// With no explicit path, every directory of `path_var` is searched for a
    /// regular file named [`TFPS_CTL`].
    ///
    /// # Arguments
    ///
    /// * `path_var` — the `PATH` value to walk; `None` is an empty path.
    #[must_use]
    pub fn locate_in(&self, path_var: Option<&OsStr>) -> Option<PathBuf> {
        if let Some(ctl) = &self.ctl {
            return Some(ctl.clone());
        }
        let path_var = path_var?;
        std::env::split_paths(path_var)
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(|dir| dir.join(TFPS_CTL))
            .find(|candidate| candidate.is_file())
    }

    /// [`Self::locate_in`] over the search path this locator carries, or the
    /// process's `PATH` when it carries none.
    #[must_use]
    pub fn locate(&self) -> Option<PathBuf> {
        match &self.search_path {
            Some(p) => self.locate_in(Some(p.as_os_str())),
            None => self.locate_in(std::env::var_os("PATH").as_deref()),
        }
    }

    /// Run one command against the peer and hand back what it wrote.
    ///
    /// # Errors
    ///
    /// [`TfpsError`] for a peer that could not be started, overran
    /// [`DEFAULT_TIMEOUT`], or wrote more than [`MAX_OUTPUT_BYTES`]. A
    /// non-zero exit is NOT an error here -- the typed readers decide what it
    /// means, because for `ban` and `unban` it means "refused" and the
    /// result is still on standard output. A peer that is not installed is
    /// not an error either: see [`Invocation::NotInstalled`].
    pub fn invoke(&self, cmd: &TfpsCommand) -> Result<Invocation, TfpsError> {
        self.invoke_with(cmd, DEFAULT_TIMEOUT)
    }

    /// [`Self::invoke`] with the wait bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// As [`Self::invoke`].
    pub fn invoke_with(
        &self,
        cmd: &TfpsCommand,
        timeout: Duration,
    ) -> Result<Invocation, TfpsError> {
        let Some(ctl) = self.locate() else {
            return Ok(Invocation::NotInstalled {
                reason: NOT_INSTALLED_REASON.to_string(),
            });
        };
        let ran = run_bounded(&ctl, &cmd.argv(self.db()), timeout)?;
        Ok(Invocation::Answered {
            ctl,
            status: ran.status,
            stdout: ran.stdout,
            stderr: ran.stderr,
        })
    }

    /// `tfps_ctl status --json`.
    ///
    /// # Errors
    ///
    /// As [`Self::invoke`], plus [`TfpsError::Failed`] on a non-zero exit and
    /// [`TfpsError::Unparseable`] when the output is not one status object.
    pub fn status(&self) -> Result<Reply<TfpsStatus>, TfpsError> {
        self.ask(&TfpsCommand::Status, parse_object)
    }

    /// `tfps_ctl banned --json`: every source currently condemned.
    ///
    /// # Errors
    ///
    /// As [`Self::status`].
    pub fn banned(&self) -> Result<Reply<Vec<TfpsBanned>>, TfpsError> {
        self.ask(&TfpsCommand::Banned, parse_lines)
    }

    /// `tfps_ctl dropped --json`: what the enforcement has dropped, per source.
    ///
    /// # Errors
    ///
    /// As [`Self::status`].
    pub fn dropped(&self) -> Result<Reply<Vec<TfpsDropped>>, TfpsError> {
        self.ask(&TfpsCommand::Dropped, parse_lines)
    }

    /// `tfps_ctl log --json [--limit N]`: the verdict log the label harness
    /// scores against. `None` is the whole log, which is TFPS's own default
    /// for the export.
    ///
    /// # Errors
    ///
    /// As [`Self::status`].
    pub fn labels(&self, limit: Option<u64>) -> Result<Reply<Vec<TfpsLabel>>, TfpsError> {
        self.ask(&TfpsCommand::Labels { limit }, parse_lines)
    }

    /// `tfps_ctl ban <ip> --json [--ttl N]`.
    ///
    /// An operator action. sipnab relays it and reports what TFPS decided,
    /// including a refusal -- which TFPS signals with exit 1 and the same
    /// structured line; it does not decide anything itself.
    ///
    /// # Errors
    ///
    /// As [`Self::status`], except that exit 1 beside a readable result is a
    /// refusal, not an error.
    pub fn ban(&self, ip: IpAddr, ttl_secs: Option<u64>) -> Result<Reply<TfpsAction>, TfpsError> {
        self.ask(&TfpsCommand::Ban { ip, ttl_secs }, parse_action)
    }

    /// `tfps_ctl unban <ip> --json`.
    ///
    /// # Errors
    ///
    /// As [`Self::ban`].
    pub fn unban(&self, ip: IpAddr) -> Result<Reply<TfpsAction>, TfpsError> {
        self.ask(&TfpsCommand::Unban { ip }, parse_action)
    }

    /// Invoke `cmd` and read its output with `parse`.
    ///
    /// A zero exit is parsed. A non-zero exit is parsed only when the
    /// command is one whose refusal comes with a result (`ban`, `unban`) --
    /// and if that parse fails, the exit is reported as the failure it was,
    /// stderr and all.
    fn ask<T>(
        &self,
        cmd: &TfpsCommand,
        parse: fn(&str) -> Result<T, String>,
    ) -> Result<Reply<T>, TfpsError> {
        match self.invoke(cmd)? {
            Invocation::NotInstalled { reason } => Ok(Reply::NotInstalled { reason }),
            Invocation::Answered {
                ctl,
                status,
                stdout,
                stderr,
            } => {
                let succeeded = status == Some(0);
                if !succeeded && !cmd.refusal_carries_a_result() {
                    return Err(TfpsError::Failed {
                        ctl,
                        subcommand: cmd.subcommand().to_string(),
                        status,
                        stderr,
                    });
                }
                match parse(&stdout) {
                    Ok(value) => Ok(Reply::Answered { ctl, value }),
                    Err(what) if succeeded => Err(TfpsError::Unparseable {
                        ctl,
                        subcommand: cmd.subcommand().to_string(),
                        what,
                    }),
                    Err(_) => Err(TfpsError::Failed {
                        ctl,
                        subcommand: cmd.subcommand().to_string(),
                        status,
                        stderr,
                    }),
                }
            }
        }
    }
}

/// One thing sipnab asks `tfps_ctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TfpsCommand {
    /// `status --json`.
    Status,
    /// `banned --json`.
    Banned,
    /// `dropped --json`.
    Dropped,
    /// `log --json [--limit N]`; `None` is the whole log.
    Labels {
        /// Rows TFPS may return, newest first; `None` for all of them.
        limit: Option<u64>,
    },
    /// `ban <ip> --json [--ttl N]`. TFPS's `ban` takes no reason.
    Ban {
        /// The source to condemn.
        ip: IpAddr,
        /// How long the ban lasts, seconds; `0` is forever; TFPS's default
        /// (3600) when absent.
        ttl_secs: Option<u64>,
    },
    /// `unban <ip> --json`.
    Unban {
        /// The source to release.
        ip: IpAddr,
    },
}

impl TfpsCommand {
    /// The subcommand word, for messages.
    #[must_use]
    pub fn subcommand(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Banned => "banned",
            Self::Dropped => "dropped",
            Self::Labels { .. } => "log",
            Self::Ban { .. } => "ban",
            Self::Unban { .. } => "unban",
        }
    }

    /// Whether a non-zero exit from this command still comes with the
    /// structured result on standard output.
    ///
    /// `ban` and `unban` exit 1 when the request was refused -- the host's
    /// own address, an `ignoreip` entry, an address that was not blocked --
    /// and print the same line they print for success, with `refused` filled
    /// in. That is TFPS answering, not TFPS failing.
    #[must_use]
    pub fn refusal_carries_a_result(&self) -> bool {
        matches!(self, Self::Ban { .. } | Self::Unban { .. })
    }

    /// The arguments handed to `tfps_ctl`, in its own grammar.
    ///
    /// Every option is a flag and a value as two elements (`--ttl`, `3600`),
    /// which is the only spelling `tfps_ctl` parses. The address is a parsed
    /// [`IpAddr`] rendered back, so nothing but an address can reach the
    /// positional slot, and nothing here ever goes through a shell.
    #[must_use]
    pub fn argv(&self, db: Option<&Path>) -> Vec<OsString> {
        let mut out: Vec<OsString> = vec![self.subcommand().into(), "--json".into()];
        match self {
            Self::Status | Self::Banned | Self::Dropped => {}
            Self::Labels { limit } => {
                if let Some(n) = limit {
                    out.push("--limit".into());
                    out.push(n.to_string().into());
                }
            }
            Self::Ban { ip, ttl_secs } => {
                out.push(ip.to_string().into());
                if let Some(ttl) = ttl_secs {
                    out.push("--ttl".into());
                    out.push(ttl.to_string().into());
                }
            }
            Self::Unban { ip } => out.push(ip.to_string().into()),
        }
        if let Some(db) = db {
            out.push("--db".into());
            out.push(db.as_os_str().to_os_string());
        }
        out
    }
}

/// What came back from running `tfps_ctl`, before it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// No executable to run. A result, not an error: the ordinary case on a
    /// machine without TFPS.
    NotInstalled {
        /// [`NOT_INSTALLED_REASON`], so every surface says the same thing.
        reason: String,
    },
    /// The peer ran to completion.
    Answered {
        /// The executable that answered, for the record.
        ctl: PathBuf,
        /// Its exit status; `None` when a signal ended it.
        status: Option<i32>,
        /// Its standard output.
        stdout: String,
        /// Its standard error.
        stderr: String,
    },
}

/// A typed answer from the peer, or the fact that there is no peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply<T> {
    /// No executable to run; see [`Invocation::NotInstalled`].
    NotInstalled {
        /// [`NOT_INSTALLED_REASON`].
        reason: String,
    },
    /// The peer answered and its output parsed.
    Answered {
        /// The executable that answered.
        ctl: PathBuf,
        /// What it said.
        value: T,
    },
}

/// Why an invocation did not produce a usable answer.
///
/// Every variant that reached the peer carries its standard error verbatim.
/// That text is the peer's own diagnosis and the only one a caller will get;
/// paraphrasing it would lose the part that matters.
#[derive(Debug)]
pub enum TfpsError {
    /// The executable could not be started.
    Spawn {
        /// What sipnab tried to run.
        ctl: PathBuf,
        /// The operating system's reason.
        error: std::io::Error,
    },
    /// The peer exited non-zero without a result.
    Failed {
        /// What ran.
        ctl: PathBuf,
        /// Which subcommand.
        subcommand: String,
        /// The exit status, or `None` when a signal ended it.
        status: Option<i32>,
        /// Its standard error, verbatim.
        stderr: String,
    },
    /// The peer exited zero and wrote something this reader cannot use.
    Unparseable {
        /// What ran.
        ctl: PathBuf,
        /// Which subcommand.
        subcommand: String,
        /// What was wrong with the output.
        what: String,
    },
    /// The peer did not finish inside the wait.
    TimedOut {
        /// What ran.
        ctl: PathBuf,
        /// How long sipnab waited.
        after: Duration,
        /// Whatever it had written to standard error by then.
        stderr: String,
    },
    /// The peer wrote more standard output than sipnab reads.
    OutputTooLarge {
        /// What ran.
        ctl: PathBuf,
        /// The cap it passed.
        cap: usize,
    },
}

impl fmt::Display for TfpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { ctl, error } => {
                write!(f, "cannot run {}: {error}", ctl.display())
            }
            Self::Failed {
                ctl,
                subcommand,
                status,
                stderr,
            } => {
                let status =
                    status.map_or_else(|| "a signal".to_string(), |s| format!("status {s}"));
                write!(
                    f,
                    "{} {subcommand} exited with {status}: {}",
                    ctl.display(),
                    stderr.trim_end()
                )
            }
            Self::Unparseable {
                ctl,
                subcommand,
                what,
            } => write!(
                f,
                "{} {subcommand} answered something this sipnab cannot read: {what}",
                ctl.display()
            ),
            Self::TimedOut { ctl, after, stderr } => write!(
                f,
                "{} did not finish within {:.1}s and was stopped: {}",
                ctl.display(),
                after.as_secs_f64(),
                stderr.trim_end()
            ),
            Self::OutputTooLarge { ctl, cap } => write!(
                f,
                "{} wrote more than {cap} bytes of output; sipnab stopped reading",
                ctl.display()
            ),
        }
    }
}

impl std::error::Error for TfpsError {}

/// What one bounded run of the peer produced.
struct Ran {
    /// The exit status; `None` when a signal ended it.
    status: Option<i32>,
    /// Standard output, lossily decoded.
    stdout: String,
    /// Standard error, lossily decoded.
    stderr: String,
}

/// Run `ctl` with `argv`, capture both streams, and stop it at `timeout`.
///
/// Both streams are drained on their own threads so a peer that fills one
/// pipe cannot block on the other, and each read stops at
/// [`MAX_OUTPUT_BYTES`].
///
/// On Unix the peer runs in its own process group and a timeout kills the
/// group, not just the peer: `tfps_ctl` may itself be a shell wrapper, and
/// killing the shell alone leaves whatever it started holding the pipe --
/// so the reader would wait on a grandchild for as long as it chose to run.
/// For the same reason the timeout path reads what the peer wrote so far
/// without waiting for the pipe to close.
fn run_bounded(ctl: &Path, argv: &[OsString], timeout: Duration) -> Result<Ran, TfpsError> {
    let mut command = Command::new(ctl);
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = spawn_waiting_out_etxtbsy(&mut command).map_err(|error| TfpsError::Spawn {
        ctl: ctl.to_path_buf(),
        error,
    })?;

    let stdout = child.stdout.take().map(drain_in_background);
    let stderr = child.stderr.take().map(drain_in_background);

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                // Stopped rather than abandoned: a child left running would
                // keep the pipes open, and the reader threads with them.
                stop_tree(&mut child);
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                stop_tree(&mut child);
                return Err(TfpsError::Spawn {
                    ctl: ctl.to_path_buf(),
                    error,
                });
            }
        }
    };

    let Some(status) = status else {
        // Whatever reached stderr before the stop. Not joined: a grandchild
        // that survived the group kill (a different group, a different user)
        // would hold the pipe open, and this must return regardless.
        let err = stderr.map_or_else(String::new, |d| d.snapshot());
        return Err(TfpsError::TimedOut {
            ctl: ctl.to_path_buf(),
            after: timeout,
            stderr: err,
        });
    };

    let (out, out_overflowed) = stdout.map_or((String::new(), false), Drained::finish);
    let (err, _) = stderr.map_or((String::new(), false), Drained::finish);
    if out_overflowed {
        return Err(TfpsError::OutputTooLarge {
            ctl: ctl.to_path_buf(),
            cap: MAX_OUTPUT_BYTES,
        });
    }
    Ok(Ran {
        status: status.code(),
        stdout: out,
        stderr: err,
    })
}

/// Longest sipnab waits for an executable that is open for writing.
///
/// `ETXTBSY` is a moment, not a state: the installer that just wrote
/// `tfps_ctl` is closing it, or a child forked by another thread of THIS
/// process inherited the write descriptor and has not exec'd yet -- the
/// ordinary fork/exec race on Linux, and the one the test suite hits when
/// two tests write their fakes at once. Half a second covers both; a file
/// still busy after that is reported as the spawn failure it is.
const ETXTBSY_PATIENCE: Duration = Duration::from_millis(500);

/// Spawn `command`, waiting out a transient `ETXTBSY`.
fn spawn_waiting_out_etxtbsy(command: &mut Command) -> std::io::Result<std::process::Child> {
    let started = Instant::now();
    loop {
        match command.spawn() {
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && started.elapsed() < ETXTBSY_PATIENCE =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

/// Stop the peer and everything it started.
fn stop_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child is its own group leader (see `run_bounded`), so its pid
        // names the group; a negative pid kills every member.
        let pid = child.id();
        if let Ok(pid) = i32::try_from(pid) {
            // SAFETY: `kill(2)` with a negative pid signals a process group;
            // the group is the one this call created, so it cannot name
            // anything but the peer and its descendants.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A pipe being read on its own thread.
///
/// The bytes live behind a lock the reader appends to, so the timeout path
/// can take a snapshot without waiting for the pipe to close.
struct Drained {
    /// What has been read so far, and whether the cap was hit.
    buf: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
    /// The reader, joined only when the peer has exited.
    reader: std::thread::JoinHandle<()>,
}

impl Drained {
    /// Everything read so far, lossily decoded, without waiting.
    fn snapshot(&self) -> String {
        let guard = self
            .buf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&guard.0).into_owned()
    }

    /// Wait for the pipe to close and hand back everything, lossily decoded,
    /// with whether the cap was hit.
    fn finish(self) -> (String, bool) {
        let _ = self.reader.join();
        let guard = self
            .buf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (String::from_utf8_lossy(&guard.0).into_owned(), guard.1)
    }
}

/// Read `pipe` to its end, or to [`MAX_OUTPUT_BYTES`], on its own thread.
fn drain_in_background<R: Read + Send + 'static>(mut pipe: R) -> Drained {
    let buf = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), false)));
    let shared = std::sync::Arc::clone(&buf);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let mut guard = shared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if guard.0.len() + n > MAX_OUTPUT_BYTES {
                        guard.1 = true;
                        return;
                    }
                    guard.0.extend_from_slice(&chunk[..n]);
                }
            }
        }
    });
    Drained { buf, reader }
}

/// Parse one JSON object.
///
/// # Errors
///
/// A message naming what was wrong, for [`TfpsError::Unparseable`].
fn parse_object<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, String> {
    serde_json::from_str(text.trim()).map_err(|e| format!("not the agreed JSON object: {e}"))
}

/// Parse JSON Lines: one object per line, blank lines skipped.
///
/// A line that does not parse is an error rather than a skipped row, for the
/// reason the label harness gives: an answer quietly missing rows describes a
/// smaller world than the peer reported.
///
/// # Errors
///
/// A message naming the line, for [`TfpsError::Unparseable`].
fn parse_lines<T: for<'de> Deserialize<'de>>(text: &str) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        out.push(row);
    }
    Ok(out)
}

/// Parse the one action line `ban <ip>` or `unban <ip>` prints.
///
/// sipnab names one address per call, so TFPS answers one line. More than
/// one would mean sipnab and TFPS disagree about what was asked, and that is
/// reported rather than resolved by picking a line.
///
/// # Errors
///
/// A message naming what was wrong, for [`TfpsError::Unparseable`].
fn parse_action(text: &str) -> Result<TfpsAction, String> {
    let mut rows: Vec<TfpsAction> = parse_lines(text)?;
    match rows.len() {
        1 => Ok(rows.remove(0)),
        0 => Err("no result line".to_string()),
        n => Err(format!("{n} result lines for one address")),
    }
}

// ── The contract ─────────────────────────────────────────────────────

/// `tfps_ctl status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsStatus {
    /// `active` when bans reach the firewall, `inactive` when no block map
    /// could be opened -- and the reason for that goes to TFPS's stderr.
    pub enforcement: String,
    /// How the firewall is driven, in TFPS's vocabulary (`native`, ...);
    /// `null` when it could not look.
    pub mode: Option<String>,
    /// The interface enforcement applies to; `null` when unknown.
    pub interface: Option<String>,
    /// Sources blocked at this moment.
    pub blocked_now: u64,
    /// The database TFPS answered from.
    pub db: String,
    /// The TFPS version.
    pub version: String,
}

/// One row of `tfps_ctl banned --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsBanned {
    /// The condemned source.
    pub ip: String,
    /// The TFPS rule that condemned it; `null` when the block predates the
    /// audit row that would say.
    pub rule: Option<String>,
    /// What the rule saw. For `user-agent` this is the sender's own text.
    /// `null` when unknown.
    pub detail: Option<String>,
    /// When the ban began, RFC 3339; `null` when unknown.
    pub first_seen: Option<String>,
    /// When it lapses, RFC 3339; `null` for a ban that does not.
    pub expires: Option<String>,
    /// Whether the firewall holds it, or TFPS is only observing.
    pub enforced: bool,
}

/// One row of `tfps_ctl dropped --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsDropped {
    /// The source whose packets were dropped.
    pub ip: String,
    /// Packets the enforcement dropped.
    pub dropped: u64,
    /// Events TFPS recorded for the source.
    pub events: u64,
    /// The most recent, RFC 3339.
    pub last_seen: String,
    /// The rule behind the block; `null` when unknown.
    pub rule: Option<String>,
    /// The last request line the source sent -- the sender's own text;
    /// `null` when none was recorded.
    pub last_request: Option<String>,
}

/// One row of `tfps_ctl log --json`: a verdict about one source.
///
/// The same shape `tests/fixtures/tfps-labels-golden.jsonl` pins for the
/// label harness, which reads it structurally rather than through this type
/// for the reason its header gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsLabel {
    /// The source the verdict is about.
    pub ip: String,
    /// The rule that reached it.
    pub rule: String,
    /// What the rule saw.
    pub detail: String,
    /// Unix seconds when the verdict was reached.
    pub first_seen: u64,
    /// Unix seconds when a block lapses; `0` for never; `null` when nothing
    /// was blocked.
    pub expires: Option<i64>,
    /// Unix seconds when an operator lifted the block, when one did.
    pub unbanned_at: Option<u64>,
    /// Whether the firewall held it.
    pub enforced: bool,
    /// `blocked`, `would-block` or `exempt`.
    pub verdict: String,
}

/// `tfps_ctl ban --json`, `unban --json`, and every line `ingest` answers
/// with: what TFPS did about one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsAction {
    /// The address, or `null` when the input did not name a valid one.
    pub ip: Option<String>,
    /// `ban` or `unban`.
    pub action: String,
    /// Whether the firewall was written. False for a refusal and a dry run.
    pub applied: bool,
    /// Why not: `self`, `ignoreip`, `not-blocked`, `invalid`; `null` when it
    /// was applied.
    pub refused: Option<String>,
    /// When the block lapses, RFC 3339; `null` for never, for an unban, and
    /// for anything refused.
    pub expires: Option<String>,
    /// Who asked: `operator` for the two commands, `sipnab` for `ingest`.
    pub source: String,
}

// ── What both doors answer with ───────────────────────────────────────

/// `tfps_status`'s answer, on every surface.
///
/// One type, serialized by the MCP tool and the REST route alike, so the two
/// doors cannot drift apart. `installed: false` carries `reason` and nothing
/// else; `installed: true` carries which executable answered and its answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsStatusAnswer {
    /// Whether a `tfps_ctl` was found to ask.
    pub installed: bool,
    /// Why not, when `installed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The executable that answered, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfps_ctl: Option<String>,
    /// What it said, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TfpsStatus>,
}

impl From<Reply<TfpsStatus>> for TfpsStatusAnswer {
    fn from(reply: Reply<TfpsStatus>) -> Self {
        match reply {
            Reply::NotInstalled { reason } => Self {
                installed: false,
                reason: Some(reason),
                tfps_ctl: None,
                status: None,
            },
            Reply::Answered { ctl, value } => Self {
                installed: true,
                reason: None,
                tfps_ctl: Some(ctl.display().to_string()),
                status: Some(value),
            },
        }
    }
}

/// A list answer -- `tfps_banned`, `tfps_dropped`, `tfps_labels` -- bounded
/// by the door's row cap.
///
/// The rows sit under `rows`, beside `total` (how many the peer returned),
/// `returned` (how many are here) and `truncated`, the same page shape every
/// list-style tool on the MCP surface answers with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsListAnswer<T> {
    /// Whether a `tfps_ctl` was found to ask.
    pub installed: bool,
    /// Why not, when `installed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The executable that answered, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfps_ctl: Option<String>,
    /// The rows, at most the door's row cap of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<T>>,
    /// Rows the peer returned before the cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// Rows in `rows`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned: Option<usize>,
    /// Whether the cap withheld any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

impl<T> TfpsListAnswer<T> {
    /// Bound `reply`'s rows to `cap`.
    ///
    /// # Arguments
    ///
    /// * `reply` — the peer's answer.
    /// * `cap` — the door's row ceiling (`--mcp-max-rows`, `--api-max-rows`).
    #[must_use]
    pub fn bounded(reply: Reply<Vec<T>>, cap: usize) -> Self {
        match reply {
            Reply::NotInstalled { reason } => Self {
                installed: false,
                reason: Some(reason),
                tfps_ctl: None,
                rows: None,
                total: None,
                returned: None,
                truncated: None,
            },
            Reply::Answered { ctl, mut value } => {
                let total = value.len();
                value.truncate(cap);
                Self {
                    installed: true,
                    reason: None,
                    tfps_ctl: Some(ctl.display().to_string()),
                    total: Some(total),
                    returned: Some(value.len()),
                    truncated: Some(value.len() < total),
                    rows: Some(value),
                }
            }
        }
    }
}

/// `tfps_ban`'s and `tfps_unban`'s answer, on every surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TfpsActionAnswer {
    /// Whether a `tfps_ctl` was found to ask.
    pub installed: bool,
    /// Why not, when `installed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The executable that answered, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfps_ctl: Option<String>,
    /// What TFPS did, when it was asked -- a refusal included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<TfpsAction>,
}

impl From<Reply<TfpsAction>> for TfpsActionAnswer {
    fn from(reply: Reply<TfpsAction>) -> Self {
        match reply {
            Reply::NotInstalled { reason } => Self {
                installed: false,
                reason: Some(reason),
                tfps_ctl: None,
                action: None,
            },
            Reply::Answered { ctl, value } => Self {
                installed: true,
                reason: None,
                tfps_ctl: Some(ctl.display().to_string()),
                action: Some(value),
            },
        }
    }
}
