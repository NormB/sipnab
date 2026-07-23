//! End-to-end crash-handling tests: spawn the real binary with
//! `--panic-selftest` and verify the `[crash]` policy — report file,
//! backtrace content, and the exit-vs-core decision.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

/// Spawns `sipnab --panic-selftest` under a `[crash]` config built from
/// `crash_toml`, with `ulimit -c 0` so no real core file is ever written.
///
/// # Arguments
/// * `crash_toml` — extra lines appended to the `[crash]` config section
///   (e.g. `core = true`); empty string for the default policy.
///
/// # Returns
/// `(exit_status, stderr, tempdir)` — the tempdir holds `reports/` and must
/// stay alive while report files are inspected.
///
/// # Side effects
/// Writes a temp config file and spawns the sipnab binary via `sh -c`.
fn run_selftest(crash_toml: &str) -> (std::process::ExitStatus, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let report_dir = dir.path().join("reports");
    let config_path = dir.path().join("crash.toml");
    let mut f = std::fs::File::create(&config_path).unwrap();
    writeln!(
        f,
        "[crash]\nreport_dir = \"{}\"\n{}",
        report_dir.display(),
        crash_toml
    )
    .unwrap();

    // ulimit -c 0: never write an actual core file on this box even when
    // the abort path is exercised; the SIGABRT itself is the observable.
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -c 0; exec {} -f {} --panic-selftest",
            env!("CARGO_BIN_EXE_sipnab"),
            config_path.display()
        ))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stderr, dir)
}

/// Lists crash-report files under the tempdir's `reports/` directory.
///
/// # Arguments
/// * `dir` — the tempdir returned by `run_selftest`.
///
/// # Returns
/// Paths of all report files; empty if the directory does not exist.
fn report_files(dir: &tempfile::TempDir) -> Vec<std::path::PathBuf> {
    let reports = dir.path().join("reports");
    match std::fs::read_dir(&reports) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Default crash policy: the process exits 101 (no signal), writes exactly one
/// report containing the panic message and a backtrace, and stderr names the file.
#[test]
fn default_policy_writes_report_with_backtrace_and_exits_101() {
    let (status, stderr, dir) = run_selftest("");
    assert_eq!(
        status.code(),
        Some(101),
        "no-core default must EXIT (no signal), stderr:\n{stderr}"
    );
    assert_eq!(status.signal(), None, "no signal death by default");

    let files = report_files(&dir);
    assert_eq!(
        files.len(),
        1,
        "exactly one crash report, stderr:\n{stderr}"
    );
    let contents = std::fs::read_to_string(&files[0]).unwrap();
    assert!(
        contents.contains("panic-selftest: intentional panic"),
        "report carries the panic message:\n{contents}"
    );
    assert!(
        contents.contains("Backtrace:") && contents.contains("main"),
        "report carries a full backtrace:\n{contents}"
    );
    assert!(
        stderr.contains("crash report written to"),
        "stderr points at the report:\n{stderr}"
    );
}

/// With `core = true` the process dies by SIGABRT (so the OS can dump core)
/// but still writes the crash report first.
#[test]
fn core_true_dies_by_sigabrt_for_core_dump() {
    let (status, stderr, dir) = run_selftest("core = true");
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "core=true must abort so the OS can dump core, stderr:\n{stderr}"
    );
    // The report is still written before the abort.
    assert_eq!(report_files(&dir).len(), 1, "stderr:\n{stderr}");
}

/// With `reports = false` no report file is written, but the backtrace still
/// reaches stderr and the exit code stays 101.
#[test]
fn reports_false_writes_nothing_but_backtrace_goes_to_stderr() {
    let (status, stderr, dir) = run_selftest("reports = false");
    assert_eq!(status.code(), Some(101));
    assert_eq!(report_files(&dir).len(), 0, "no report file");
    assert!(
        stderr.contains("Backtrace:"),
        "backtrace must not be lost when reports are off:\n{stderr}"
    );
}

/// With `backtrace = false` the report is written without a `Backtrace:`
/// section and instead notes that backtraces are disabled.
#[test]
fn backtrace_false_report_says_disabled() {
    let (status, _stderr, dir) = run_selftest("backtrace = false");
    assert_eq!(status.code(), Some(101));
    let files = report_files(&dir);
    assert_eq!(files.len(), 1);
    let contents = std::fs::read_to_string(&files[0]).unwrap();
    assert!(!contents.contains("Backtrace:"));
    assert!(contents.to_ascii_lowercase().contains("disabled"));
}
