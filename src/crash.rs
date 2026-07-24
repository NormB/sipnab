// SPDX-License-Identifier: MIT OR Apache-2.0

//! Crash handling: a process-wide panic hook driven by the `[crash]`
//! config section.
//!
//! Release builds use `panic = "abort"`, so the TUI's unwind-based
//! terminal guard never runs on a panic there: the message prints into
//! the raw-mode alternate screen (unreadable), the process aborts with
//! no backtrace, and the shell is left with mouse reporting enabled.
//! The hook installed here runs BEFORE the abort: it restores the
//! terminal, writes a crash report (optionally with a full backtrace),
//! and then either exits cleanly or lets the OS produce a core dump.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::config::CrashConfig;

/// Effective crash policy resolved from the `[crash]` config section.
#[derive(Debug, Clone, PartialEq)]
pub struct CrashPolicy {
    /// Write a crash-report file at all.
    pub reports: bool,
    /// Include a full backtrace in the report.
    pub backtrace: bool,
    /// Directory reports are written to.
    pub report_dir: PathBuf,
    /// Abort (core-dumpable) instead of exiting cleanly.
    pub core: bool,
}

impl CrashPolicy {
    /// Resolve the effective policy from the config section, applying the
    /// documented defaults for unset fields (reports on, backtrace on,
    /// core off, `~/.local/state/sipnab` report dir).
    pub fn from_config(cfg: &CrashConfig) -> Self {
        Self {
            reports: cfg.reports_enabled(),
            backtrace: cfg.backtrace_enabled(),
            report_dir: cfg.effective_report_dir(),
            core: cfg.core_enabled(),
        }
    }
}

/// What to do with the process once the crash report is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostAction {
    /// `std::process::abort()`: raises SIGABRT so the kernel can write a
    /// core dump (subject to `ulimit -c` and `core_pattern`).
    Abort,
    /// `std::process::exit(code)`: no signal, no core dump.
    Exit(i32),
}

/// Decide the post-report action from the `core` policy: `Abort`
/// (core-dumpable) when `core` is true, else a clean `Exit(101)`. Pure.
pub fn post_report_action(core: bool) -> PostAction {
    if core {
        PostAction::Abort
    } else {
        PostAction::Exit(101)
    }
}

/// Render the crash-report text: panic message, location, thread,
/// version, and (when captured) a full backtrace.
///
/// # Arguments
/// * `message` - the panic payload text.
/// * `location` - `file:line:col` where the panic originated.
/// * `thread` - name of the panicking thread.
/// * `backtrace` - captured backtrace text; `None` renders a line
///   explaining that capture was disabled by config.
///
/// # Returns
/// The complete report as a string; nothing is written anywhere. Pure.
pub fn build_crash_report(
    message: &str,
    location: &str,
    thread: &str,
    backtrace: Option<&str>,
) -> String {
    let mut report = format!(
        "sipnab {} crash report\n\n\
         Thread:   {thread}\n\
         Location: {location}\n\
         Message:  {message}\n\n",
        env!("CARGO_PKG_VERSION"),
    );
    match backtrace {
        Some(bt) => {
            report.push_str("Backtrace:\n");
            report.push_str(bt);
            report.push('\n');
        }
        None => {
            report.push_str("Backtrace capture disabled ([crash] backtrace = false).\n");
        }
    }
    report
}

/// Distinguishes reports written by this process within the same second:
/// the timestamp+pid name alone collides when two threads crash at once,
/// and the second report would silently overwrite the first.
static REPORT_SEQ: AtomicU64 = AtomicU64::new(0);

/// How many times [`write_crash_report`] retries with a fresh name when
/// the exclusive create loses a race (another thread/process, or a
/// planted file/symlink at the predicted name).
const REPORT_CREATE_ATTEMPTS: u32 = 8;

/// Exclusively create the report file at `path` without following a
/// symlink and without truncating an existing file.
///
/// On Unix this is `O_CREAT | O_EXCL | O_NOFOLLOW` with mode `0600`. The
/// `O_EXCL`/`create_new` guarantees we never overwrite a pre-existing
/// file, and `O_NOFOLLOW` guarantees a pre-planted symlink at the target
/// is refused rather than followed onto a victim file a hostile
/// co-tenant chose (CWE-59, CWE-377). On non-Unix the exclusive create
/// alone is used.
fn open_new_report_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Create `dir` (and parents) if missing, restricting a freshly created
/// leaf to owner-only (`0700`) on Unix so a crash report written into it
/// is not exposed to other users on the host.
fn create_report_dir(dir: &Path) -> std::io::Result<()> {
    let existed = dir.exists();
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: tightening our own new directory. A pre-existing
        // directory's mode is the operator's responsibility (documented).
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let _ = existed;
    Ok(())
}

/// Reason a crash-report directory is rejected as unsafe to write into.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsafeReportDir {
    /// The path is a symlink; a hostile co-tenant could repoint it.
    Symlink,
    /// The directory is not owned by this process's effective UID.
    NotOwned,
    /// World-writable without the sticky bit, so any user on the host can
    /// plant entries in it.
    WorldWritable,
}

#[cfg(unix)]
impl UnsafeReportDir {
    /// Human-readable clause for the refusal message ("it is ...").
    fn describe(self) -> &'static str {
        match self {
            Self::Symlink => "it is a symlink",
            Self::NotOwned => "it is not owned by this process's user",
            Self::WorldWritable => "it is world-writable without the sticky bit",
        }
    }
}

/// Decide whether a report directory is safe to write crash reports into,
/// from its `lstat` facts. Pure, so the owner-mismatch and permission-mode
/// cases are unit-testable without having to actually create directories
/// owned by another user.
///
/// A directory is unsafe if it is a symlink (repointable), not owned by
/// the effective UID, or world-writable without the sticky bit. Group
/// writability is *not* rejected: under the ubiquitous user-private-group
/// scheme (umask 0002) directories are group-writable by default, so the
/// group's membership is the operator's responsibility — matching how
/// [`create_report_dir`] treats a pre-existing directory's mode. A sticky
/// world-writable directory (e.g. `/tmp`) is accepted: only the owner can
/// rename/replace their own entries there, and the exclusive `O_NOFOLLOW`
/// create already blocks the plant-and-follow attack.
#[cfg(unix)]
fn classify_report_dir(
    is_symlink: bool,
    dir_uid: u32,
    euid: u32,
    mode: u32,
) -> Result<(), UnsafeReportDir> {
    if is_symlink {
        return Err(UnsafeReportDir::Symlink);
    }
    if dir_uid != euid {
        return Err(UnsafeReportDir::NotOwned);
    }
    let world_writable = mode & 0o002 != 0;
    let sticky = mode & 0o1000 != 0;
    if world_writable && !sticky {
        return Err(UnsafeReportDir::WorldWritable);
    }
    Ok(())
}

/// Refuse to write into an existing report directory that a co-tenant
/// could subvert (symlink, foreign owner, or others-writable without
/// sticky). A directory that does not yet exist is allowed: it is created
/// fresh and owned by us at `0700` in [`create_report_dir`].
///
/// This is `lstat`-based so a symlinked directory is caught, not followed.
/// It is a no-op on non-Unix targets.
#[cfg(unix)]
fn ensure_safe_report_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        // Not yet created — create_report_dir will make it ours at 0700.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // SAFETY: geteuid() takes no arguments, never fails, and only reads
    // the caller's effective UID — it has no preconditions.
    let euid = unsafe { libc::geteuid() };
    classify_report_dir(meta.file_type().is_symlink(), meta.uid(), euid, meta.mode()).map_err(
        |reason| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to write crash reports into {}: {}",
                    dir.display(),
                    reason.describe()
                ),
            )
        },
    )
}

/// No-op on non-Unix targets: the Unix ownership/mode checks do not
/// apply, so every directory is accepted.
#[cfg(not(unix))]
fn ensure_safe_report_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Write `contents` to a new timestamped `sipnab-crash-*.log` file in
/// `dir` (created if missing) and return its path.
///
/// The file is created exclusively and without following symlinks, so a
/// crash in a privileged process cannot be redirected to overwrite an
/// attacker-chosen file even when `dir` is shared or attacker-writable
/// (see `open_new_report_file`). On a name collision — a planted
/// file/symlink, or two threads crashing in the same second — the write
/// retries with a fresh sequence suffix.
///
/// # Errors
/// The directory is classified unsafe (see `ensure_safe_report_dir`),
/// cannot be created, the file cannot be created after all retry
/// attempts, or the write itself fails.
///
/// # Side effects
/// Creates `dir` (0700 when fresh, on Unix), creates the report file
/// (0600 on Unix), and advances the process-wide report sequence counter.
pub fn write_crash_report(dir: &Path, contents: &str) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    ensure_safe_report_dir(dir)?;
    create_report_dir(dir)?;

    let mut last_err = None;
    for _ in 0..REPORT_CREATE_ATTEMPTS {
        let name = format!(
            "sipnab-crash-{}-{}-{}.log",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            std::process::id(),
            REPORT_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(name);
        match open_new_report_file(&path) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "exhausted crash-report name attempts",
        )
    }))
}

// ── Terminal state flag ─────────────────────────────────────────────

/// Whether the TUI currently owns the terminal (raw mode + alternate
/// screen + mouse capture). Set by the TUI on entry/exit so the panic
/// hook knows to restore the terminal before printing anything.
static TERMINAL_RAW: AtomicBool = AtomicBool::new(false);

/// Record whether the TUI owns the terminal, so the panic hook knows
/// to restore it before printing the crash report. Writes the
/// process-wide `TERMINAL_RAW` flag.
pub fn set_terminal_raw(raw: bool) {
    TERMINAL_RAW.store(raw, Ordering::SeqCst);
}

/// Restore the terminal if the TUI flagged it raw — used by both the
/// panic hook and the TUI's own exit path.
///
/// # Side effects
/// Atomically clears the `TERMINAL_RAW` flag (so a second caller is a
/// no-op) and, when it was set, disables mouse capture, re-shows the
/// cursor, leaves the alternate screen, and exits raw mode on stdout;
/// terminal errors are deliberately ignored.
#[cfg(feature = "tui")]
pub fn restore_terminal_if_raw() {
    if TERMINAL_RAW.swap(false, Ordering::SeqCst) {
        let mut out = std::io::stdout();
        let _ = crossterm::execute!(
            out,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show,
            crossterm::terminal::LeaveAlternateScreen
        );
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(not(feature = "tui"))]
/// No terminal to restore without the TUI feature.
pub fn restore_terminal_if_raw() {}

// ── Hook installation ───────────────────────────────────────────────

/// Install the process-wide panic hook for the given policy.
///
/// # Side effects
/// Replaces any previously installed panic hook for the whole process.
/// When a panic later fires, the hook restores the terminal, writes the
/// crash report per `policy`, and terminates the process (abort or
/// exit 101) — it never returns to the unwinding machinery.
pub fn install_panic_hook(policy: CrashPolicy) {
    install_panic_hook_with(policy, |action| match action {
        PostAction::Abort => std::process::abort(),
        PostAction::Exit(code) => std::process::exit(code),
    });
}

/// Test seam: like [`install_panic_hook`] but with an injectable
/// terminator so tests can observe the decided [`PostAction`] without
/// killing the test process. Replaces the process-wide panic hook.
pub fn install_panic_hook_with<F>(policy: CrashPolicy, terminator: F)
where
    F: Fn(PostAction) + Send + Sync + 'static,
{
    std::panic::set_hook(Box::new(move |info| {
        hook_body(&policy, info, &terminator);
    }));
}

/// Best-effort, never-panicking line write for the panic hook's stderr
/// reporting: formats `args` followed by a newline and IGNORES write
/// errors. `eprintln!` PANICS when stderr is closed/unwritable, and a
/// panic while processing a panic aborts the process before any crash
/// report can be written — so nothing in the hook path may use it.
fn hook_write_line(out: &mut dyn std::io::Write, args: std::fmt::Arguments<'_>) {
    writeln!(out, "{args}").ok();
}

/// Write one best-effort line to stderr from the panic hook. Never
/// panics; a closed stderr is silently ignored (see [`hook_write_line`]).
fn hook_eprintln(args: std::fmt::Arguments<'_>) {
    hook_write_line(&mut std::io::stderr(), args);
}

/// The hook body: restore terminal, report to stderr and file, decide
/// the post action and hand it to the terminator.
///
/// # Arguments
/// * `policy` - resolved crash policy controlling report/backtrace/core.
/// * `info` - the panic payload and location from the runtime.
/// * `terminator` - receives the decided `PostAction`; in production it
///   aborts or exits and never returns.
///
/// # Side effects
/// Restores the terminal, prints the panic (and any fallback backtrace)
/// to stderr, captures a backtrace when enabled, and writes the report
/// file per `policy`.
fn hook_body(
    policy: &CrashPolicy,
    info: &std::panic::PanicHookInfo<'_>,
    terminator: &(dyn Fn(PostAction) + Send + Sync),
) {
    // Nothing in here may panic: a panic while processing a panic aborts
    // the process before any report can be written.
    restore_terminal_if_raw();

    let message = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_string());
    let location = info
        .location()
        .map(|l| l.to_string())
        .unwrap_or_else(|| "unknown location".to_string());
    let thread = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string();

    hook_eprintln(format_args!("sipnab panicked at {location}:\n{message}"));

    // force_capture works regardless of RUST_BACKTRACE — the whole point
    // is a complete trace without the user having had to plan ahead.
    let backtrace = policy
        .backtrace
        .then(|| std::backtrace::Backtrace::force_capture().to_string());

    if policy.reports {
        let report = build_crash_report(&message, &location, &thread, backtrace.as_deref());
        match write_crash_report(&policy.report_dir, &report) {
            Ok(path) => hook_eprintln(format_args!("crash report written to {}", path.display())),
            Err(e) => {
                hook_eprintln(format_args!("failed to write crash report: {e}"));
                if let Some(ref bt) = backtrace {
                    hook_eprintln(format_args!("Backtrace:\n{bt}"));
                }
            }
        }
    } else if let Some(ref bt) = backtrace {
        hook_eprintln(format_args!("Backtrace:\n{bt}"));
    }

    terminator(post_report_action(policy.core));
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for crash-policy resolution, report rendering, safe report
/// file/directory creation, and end-to-end panic-hook behavior.
#[cfg(test)]
mod tests {
    use super::*;

    /// The panic hook is process-global state; tests that install one
    /// must not run concurrently with each other.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// An empty `[crash]` config resolves to reports+backtrace on, core
    /// off, and a sipnab-owned default report directory.
    #[test]
    fn policy_defaults_are_report_with_backtrace_no_core() {
        let policy = CrashPolicy::from_config(&CrashConfig::default());
        assert!(policy.reports, "reports default on");
        assert!(policy.backtrace, "backtrace default on");
        assert!(!policy.core, "core dumps default off");
        assert!(
            policy.report_dir.to_string_lossy().contains("sipnab"),
            "default report dir is sipnab-owned, got {:?}",
            policy.report_dir
        );
    }

    /// Explicitly set `[crash]` values override every default.
    #[test]
    fn policy_honors_explicit_config() {
        let cfg = CrashConfig {
            reports: Some(false),
            backtrace: Some(false),
            report_dir: Some(PathBuf::from("/tmp/xyz")),
            core: Some(true),
        };
        let policy = CrashPolicy::from_config(&cfg);
        assert!(!policy.reports);
        assert!(!policy.backtrace);
        assert!(policy.core);
        assert_eq!(policy.report_dir, PathBuf::from("/tmp/xyz"));
    }

    /// core=false decides a clean `Exit(101)` (no core dump).
    #[test]
    fn post_action_no_core_is_clean_exit_101() {
        assert_eq!(post_report_action(false), PostAction::Exit(101));
    }

    /// core=true decides `Abort` so the OS can produce a core dump.
    #[test]
    fn post_action_core_is_abort() {
        assert_eq!(post_report_action(true), PostAction::Abort);
    }

    /// The rendered report carries message, location, thread, version,
    /// and the backtrace section.
    #[test]
    fn report_contains_all_sections() {
        let r = build_crash_report(
            "range start index 3 out of range for slice of length 2",
            "src/tui/call_list.rs:509:71",
            "main",
            Some("0: sipnab::tui::call_list::render_call_list"),
        );
        assert!(r.contains("range start index 3 out of range"));
        assert!(r.contains("src/tui/call_list.rs:509:71"));
        assert!(r.contains("main"));
        assert!(r.contains(env!("CARGO_PKG_VERSION")));
        assert!(r.contains("Backtrace:"));
        assert!(r.contains("render_call_list"));
    }

    /// With backtrace capture off, the report says so instead of
    /// silently omitting the section.
    #[test]
    fn report_without_backtrace_says_disabled() {
        let r = build_crash_report("boom", "here.rs:1:1", "main", None);
        assert!(!r.contains("Backtrace:"));
        assert!(
            r.to_ascii_lowercase().contains("disabled"),
            "report must say why no backtrace is present, got: {r}"
        );
    }

    /// `write_crash_report` creates the (nested) directory and a
    /// timestamped `sipnab-crash-*.log` file holding the contents.
    #[test]
    fn write_report_creates_timestamped_file_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("nested").join("state");
        let path = write_crash_report(&sub, "the-contents").unwrap();
        assert!(path.starts_with(&sub), "report inside the dir");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.starts_with("sipnab-crash-") && name.ends_with(".log"),
            "got {name}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "the-contents");
    }

    /// Two reports written by the same process within the same second
    /// must land in two files — a timestamp+pid name alone collides, and
    /// the second crash silently overwrites the first (seen in CI: an
    /// unrelated test's panic routed through the installed hook clobbered
    /// the probe's report).
    #[test]
    fn write_report_same_second_does_not_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_crash_report(dir.path(), "first-crash").unwrap();
        let b = write_crash_report(dir.path(), "second-crash").unwrap();
        assert_ne!(a, b, "distinct paths for back-to-back reports");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "first-crash");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "second-crash");
    }

    /// A pre-existing symlink at the exact target path must NOT be
    /// followed: a hostile co-tenant who can write the report directory
    /// could otherwise redirect a privileged crash write onto a file of
    /// their choosing (CWE-59). `create_new` + `O_NOFOLLOW` makes the
    /// open fail instead, leaving the link target untouched.
    #[test]
    #[cfg(unix)]
    fn open_new_report_refuses_to_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "original").unwrap();
        let link = dir.path().join("sipnab-crash-planted.log");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = open_new_report_file(&link).expect_err("must refuse a symlink target");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::Other
            ) || err.raw_os_error() == Some(libc::ELOOP),
            "expected refusal, got {err:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "original",
            "the symlink target must be untouched"
        );
    }

    /// The open must be exclusive: an existing regular file at the target
    /// is never truncated/overwritten (`create_new` semantics).
    #[test]
    fn open_new_report_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sipnab-crash-existing.log");
        std::fs::write(&path, "keep-me").unwrap();
        let err = open_new_report_file(&path).expect_err("must refuse an existing file");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep-me");
    }

    /// Reports are created owner-read/write only (0600): a crash report can
    /// contain a backtrace with local paths and argument values that other
    /// users on the host should not read.
    #[test]
    #[cfg(unix)]
    fn crash_report_created_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_crash_report(dir.path(), "secret-backtrace").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "report must be owner-only, got {mode:o}");
    }

    // ── Report-directory safety classification (SN-03 follow-up) ──────

    /// An owner-private (0700) directory owned by us is accepted.
    #[test]
    #[cfg(unix)]
    fn classify_accepts_owned_private_dir() {
        // drwx------ owned by us: the safe, expected case.
        assert_eq!(classify_report_dir(false, 1000, 1000, 0o40700), Ok(()));
    }

    /// A /tmp-like sticky world-writable directory owned by us is accepted.
    #[test]
    #[cfg(unix)]
    fn classify_accepts_owned_sticky_world_writable_dir() {
        // /tmp-like: world-writable but sticky and owned by us — accepted,
        // because O_EXCL|O_NOFOLLOW already defeats plant-and-follow there.
        assert_eq!(classify_report_dir(false, 1000, 1000, 0o41777), Ok(()));
    }

    /// A symlinked report directory is rejected (repointable by a co-tenant).
    #[test]
    #[cfg(unix)]
    fn classify_rejects_symlink() {
        assert_eq!(
            classify_report_dir(true, 1000, 1000, 0o40700),
            Err(UnsafeReportDir::Symlink)
        );
    }

    /// A directory owned by a different UID is rejected.
    #[test]
    #[cfg(unix)]
    fn classify_rejects_dir_owned_by_another_user() {
        // Owned by root while we run as uid 1000: a privileged/foreign dir.
        assert_eq!(
            classify_report_dir(false, 0, 1000, 0o40700),
            Err(UnsafeReportDir::NotOwned)
        );
    }

    /// World-writable without the sticky bit is rejected.
    #[test]
    #[cfg(unix)]
    fn classify_rejects_world_writable_without_sticky() {
        assert_eq!(
            classify_report_dir(false, 1000, 1000, 0o40777),
            Err(UnsafeReportDir::WorldWritable),
            "world-writable, no sticky"
        );
    }

    /// Group-writable directories are accepted (user-private-group
    /// convention; group membership is the operator's responsibility).
    #[test]
    #[cfg(unix)]
    fn classify_accepts_group_writable_dir() {
        // umask 0002 (user-private-group) makes new dirs group-writable by
        // default; rejecting that would reject the common case. Group
        // membership is the operator's responsibility.
        assert_eq!(classify_report_dir(false, 1000, 1000, 0o40775), Ok(()));
        assert_eq!(classify_report_dir(false, 1000, 1000, 0o40770), Ok(()));
    }

    /// A symlinked report directory is refused end to end — nothing is
    /// written through the link.
    #[test]
    #[cfg(unix)]
    fn write_crash_report_refuses_symlinked_dir() {
        // A hostile co-tenant symlinks the report dir at a victim location.
        // The write must refuse rather than create reports through the link.
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim_dir");
        std::fs::create_dir(&victim).unwrap();
        let link = root.path().join("reports");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = write_crash_report(&link, "boom").expect_err("must refuse a symlinked dir");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read_dir(&victim).unwrap().count(),
            0,
            "nothing may be written through the link"
        );
    }

    /// A non-sticky world-writable report directory is refused end to end.
    #[test]
    #[cfg(unix)]
    fn write_crash_report_refuses_world_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let err =
            write_crash_report(dir.path(), "boom").expect_err("must refuse a world-writable dir");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// The safe (owned, private) directory path still works end to end.
    #[test]
    #[cfg(unix)]
    fn write_crash_report_accepts_owned_private_dir() {
        // The safe path still works end to end (regression guard).
        let dir = tempfile::tempdir().unwrap();
        let path = write_crash_report(dir.path(), "ok-contents").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ok-contents");
    }

    /// The hook's stderr writes must swallow I/O errors: `eprintln!`
    /// panics when stderr is closed, and a panic inside the panic hook
    /// aborts the process before any report can be written. A writer that
    /// always fails stands in for a closed stderr.
    #[test]
    fn hook_write_line_swallows_write_errors() {
        struct AlwaysFails;
        impl std::io::Write for AlwaysFails {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "stderr closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "stderr closed",
                ))
            }
        }
        // Must return normally — no panic, no abort.
        hook_write_line(
            &mut AlwaysFails,
            format_args!("sipnab panicked at x:\nboom"),
        );
    }

    /// The helper formats exactly one newline-terminated line, matching
    /// what `eprintln!` used to emit.
    #[test]
    fn hook_write_line_formats_single_line() {
        let mut out = Vec::new();
        hook_write_line(&mut out, format_args!("crash report written to {}", "p"));
        assert_eq!(out, b"crash report written to p\n");
    }

    /// End-to-end hook behavior in-process: a panicking thread triggers
    /// the hook, which writes the report and decides Exit(101) under the
    /// default no-core policy. The previous hook is restored afterwards.
    #[test]
    fn hook_writes_report_and_decides_clean_exit() {
        use std::sync::{Arc, Mutex};
        let _guard = HOOK_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy = CrashPolicy {
            reports: true,
            backtrace: true,
            report_dir: dir.path().to_path_buf(),
            core: false,
        };
        let decided: Arc<Mutex<Option<PostAction>>> = Arc::new(Mutex::new(None));
        let decided2 = decided.clone();
        let prev = std::panic::take_hook();
        install_panic_hook_with(policy, move |a| {
            *decided2.lock().unwrap() = Some(a);
        });
        let _ = std::thread::Builder::new()
            .name("crash-probe".into())
            .spawn(|| panic!("intentional hook-test panic"))
            .unwrap()
            .join();
        std::panic::set_hook(prev);

        assert_eq!(*decided.lock().unwrap(), Some(PostAction::Exit(101)));
        // The hook is process-global: while installed it also fires for
        // panics of unrelated concurrently running tests (seen in CI), so
        // identify the probe's report by content instead of assuming it
        // is alone in the directory.
        let reports: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        let ours: Vec<&String> = reports
            .iter()
            .filter(|c| c.contains("intentional hook-test panic"))
            .collect();
        assert_eq!(ours.len(), 1, "exactly one report for the probe panic");
        assert!(ours[0].contains("crash-probe"), "thread name recorded");
        assert!(ours[0].contains("Backtrace:"), "backtrace captured");
    }

    /// reports=false must not write any file but still decide the action.
    #[test]
    fn hook_respects_reports_disabled() {
        use std::sync::{Arc, Mutex};
        let _guard = HOOK_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy = CrashPolicy {
            reports: false,
            backtrace: true,
            report_dir: dir.path().to_path_buf(),
            core: true,
        };
        let decided: Arc<Mutex<Option<PostAction>>> = Arc::new(Mutex::new(None));
        let decided2 = decided.clone();
        let prev = std::panic::take_hook();
        install_panic_hook_with(policy, move |a| {
            *decided2.lock().unwrap() = Some(a);
        });
        let _ = std::thread::spawn(|| panic!("no-report panic")).join();
        std::panic::set_hook(prev);

        assert_eq!(*decided.lock().unwrap(), Some(PostAction::Abort));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "no report file with reports=false"
        );
    }
}
