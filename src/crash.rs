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
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Resolve the effective policy from the config section.
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

/// Decide the post-report action from the `core` policy.
pub fn post_report_action(core: bool) -> PostAction {
    if core {
        PostAction::Abort
    } else {
        PostAction::Exit(101)
    }
}

/// Render the crash-report text: panic message, location, thread,
/// version, and (when captured) a full backtrace.
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

/// Write `contents` to a new timestamped `sipnab-crash-*.log` file in
/// `dir` (created if missing) and return its path.
pub fn write_crash_report(dir: &Path, contents: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let name = format!(
        "sipnab-crash-{}-{}.log",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );
    let path = dir.join(name);
    std::fs::write(&path, contents)?;
    Ok(path)
}

// ── Terminal state flag ─────────────────────────────────────────────

/// Whether the TUI currently owns the terminal (raw mode + alternate
/// screen + mouse capture). Set by the TUI on entry/exit so the panic
/// hook knows to restore the terminal before printing anything.
static TERMINAL_RAW: AtomicBool = AtomicBool::new(false);

/// Record whether the TUI owns the terminal (see [`TERMINAL_RAW`]).
pub fn set_terminal_raw(raw: bool) {
    TERMINAL_RAW.store(raw, Ordering::SeqCst);
}

/// Restore the terminal if the TUI flagged it raw — used by both the
/// panic hook and the TUI's own exit path.
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
pub fn install_panic_hook(policy: CrashPolicy) {
    install_panic_hook_with(policy, |action| match action {
        PostAction::Abort => std::process::abort(),
        PostAction::Exit(code) => std::process::exit(code),
    });
}

/// Test seam: like [`install_panic_hook`] but with an injectable
/// terminator so tests can observe the decided [`PostAction`] without
/// killing the test process.
pub fn install_panic_hook_with<F>(policy: CrashPolicy, terminator: F)
where
    F: Fn(PostAction) + Send + Sync + 'static,
{
    std::panic::set_hook(Box::new(move |info| {
        hook_body(&policy, info, &terminator);
    }));
}

/// The hook body: restore terminal, report to stderr and file, decide
/// the post action and hand it to the terminator.
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

    eprintln!("sipnab panicked at {location}:\n{message}");

    // force_capture works regardless of RUST_BACKTRACE — the whole point
    // is a complete trace without the user having had to plan ahead.
    let backtrace = policy
        .backtrace
        .then(|| std::backtrace::Backtrace::force_capture().to_string());

    if policy.reports {
        let report = build_crash_report(&message, &location, &thread, backtrace.as_deref());
        match write_crash_report(&policy.report_dir, &report) {
            Ok(path) => eprintln!("crash report written to {}", path.display()),
            Err(e) => {
                eprintln!("failed to write crash report: {e}");
                if let Some(ref bt) = backtrace {
                    eprintln!("Backtrace:\n{bt}");
                }
            }
        }
    } else if let Some(ref bt) = backtrace {
        eprintln!("Backtrace:\n{bt}");
    }

    terminator(post_report_action(policy.core));
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The panic hook is process-global state; tests that install one
    /// must not run concurrently with each other.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    #[test]
    fn post_action_no_core_is_clean_exit_101() {
        assert_eq!(post_report_action(false), PostAction::Exit(101));
    }

    #[test]
    fn post_action_core_is_abort() {
        assert_eq!(post_report_action(true), PostAction::Abort);
    }

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

    #[test]
    fn report_without_backtrace_says_disabled() {
        let r = build_crash_report("boom", "here.rs:1:1", "main", None);
        assert!(!r.contains("Backtrace:"));
        assert!(
            r.to_ascii_lowercase().contains("disabled"),
            "report must say why no backtrace is present, got: {r}"
        );
    }

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
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "exactly one crash report");
        let contents = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
        assert!(contents.contains("intentional hook-test panic"));
        assert!(contents.contains("crash-probe"), "thread name recorded");
        assert!(contents.contains("Backtrace:"), "backtrace captured");
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
