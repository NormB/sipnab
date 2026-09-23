// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end crash-handling tests: spawn the real binary with
//! `--panic-selftest` and verify the `[crash]` policy — report file,
//! backtrace content, and the exit-vs-core decision.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

#[path = "support/mod.rs"]
mod support;

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
    //
    // discard_coverage_profile: `core = true` kills this child with SIGABRT,
    // which leaves a truncated .profraw that breaks the whole Coverage job.
    // See the helper for why that must not be retried past.
    let mut cmd = Command::new("sh");
    support::discard_coverage_profile(&mut cmd);
    let output = cmd
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

#[cfg(target_os = "linux")]
#[path = "support/dbgsym.rs"]
mod dbgsym;

/// The one crash report written under the default policy, as text.
fn default_report() -> String {
    let (status, stderr, dir) = run_selftest("");
    assert_eq!(status.code(), Some(101), "stderr:\n{stderr}");
    let files = report_files(&dir);
    assert_eq!(files.len(), 1, "stderr:\n{stderr}");
    std::fs::read_to_string(&files[0]).unwrap()
}

/// The `image+0x…` address of every frame the report attributes to the
/// executable itself.
fn executable_frames(report: &str) -> Vec<String> {
    report
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .filter_map(|w| w.strip_prefix("sipnab+"))
        .map(str::to_string)
        .collect()
}

/// (c) A stripped release binary's backtrace names no functions, so the report
/// records what survives stripping: the executable's GNU build ID (Linux) or
/// Mach-O UUID (macOS), its load base, the target triple, and the raw address
/// of every frame. The build ID is checked against the binary on disk.
#[test]
fn the_report_records_the_image_identity_and_raw_frames() {
    let report = default_report();
    assert!(report.contains("Load base: 0x"), "no load base:\n{report}");
    assert!(report.contains("Raw frames"), "no raw frames:\n{report}");
    let target = report
        .lines()
        .find_map(|l| l.trim().strip_prefix("Target:"))
        .map(str::trim)
        .unwrap_or_default();
    assert!(
        target.matches('-').count() >= 2,
        "no target triple naming the symbol file to fetch:\n{report}"
    );
    assert!(
        executable_frames(&report).len() >= 2,
        "fewer than two frames attributed to the executable:\n{report}"
    );

    #[cfg(target_os = "linux")]
    {
        let on_disk = dbgsym::build_id(std::path::Path::new(env!("CARGO_BIN_EXE_sipnab")))
            .expect("the test binary carries a build ID");
        assert!(
            report.contains(&format!("Build ID:  {on_disk}")),
            "the report must carry the binary's build ID {on_disk}:\n{report}"
        );
    }
    #[cfg(target_os = "macos")]
    assert!(report.contains("UUID:  "), "no Mach-O UUID:\n{report}");
}

/// (b)+(c) The whole chain on the real binary: split a copy of it into a
/// stripped binary and a `.debug` file, then resolve the report's frame
/// addresses against the `.debug` file. One must land on the exact line of the
/// `--panic-selftest` panic in `src/main.rs`, as the report's `Location:`
/// names it.
#[test]
#[cfg(target_os = "linux")]
fn the_report_frames_resolve_against_the_published_symbol_file() {
    if !dbgsym::have("llvm-symbolizer") && !dbgsym::have("addr2line") {
        eprintln!("SKIPPED: neither llvm-symbolizer nor addr2line is installed");
        return;
    }
    let report = default_report();
    let frames = executable_frames(&report);
    assert!(!frames.is_empty(), "no executable frames:\n{report}");

    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("sipnab");
    std::fs::copy(env!("CARGO_BIN_EXE_sipnab"), &copy).unwrap();
    let out = dbgsym::split(&copy, &dir.path().join("sipnab-test"));
    assert!(
        out.status.success(),
        "split failed:\n{}",
        dbgsym::text(&out)
    );
    let debug = dir.path().join("sipnab-test.debug");

    let resolved: String = frames
        .iter()
        .map(|f| dbgsym::symbolize(&debug, f).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("");
    // The panic's own `Location:` line, minus the column: a frame must
    // resolve to exactly that line. This does NOT pin the call-site rule
    // (return address minus one): in this unoptimized test binary both
    // resolve to the same line, measured by mutation. The unit test
    // `the_render_records_identity_load_base_and_raw_frames` pins it, and on
    // an optimized release build the return address resolved `sipnab::main`
    // to line 175 while the call site gave the panic's 152.
    let location = report
        .lines()
        .find_map(|l| l.strip_prefix("Location: "))
        .expect("report has a Location line")
        .trim();
    let file_line = location.rsplit_once(':').map_or(location, |(fl, _col)| fl);
    assert!(
        file_line.starts_with("src/main.rs:"),
        "the self-test panics in src/main.rs, report says {location}"
    );
    assert!(
        resolved.contains(file_line),
        "no frame resolved to the panic at {file_line}.\nframes: {frames:?}\n\
         resolved:\n{resolved}\nreport:\n{report}"
    );
}
