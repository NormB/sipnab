// SPDX-License-Identifier: MIT OR Apache-2.0

//! `scripts/parallel-tests.py` runs the suite's test binaries side by side.
//!
//! `cargo test` runs its ~355 test binaries one after another. Measured on
//! 2026-09-29 (14 cores): 355 s of running, of which 294 binaries took under a
//! second each, while a single core was busy. The pre-commit hook paid all of
//! it on every commit. The script has cargo hand each binary to a recording
//! runner instead of executing it -- so every binary is recorded with the exact
//! argv, working directory and environment cargo would have given it -- and
//! then runs the recordings in a pool, printing each binary's output as one
//! block so the hook's failure parser and homepage count read it unchanged.
//!
//! These drive the two halves directly: the recorder (`scripts/record-test-
//! binary.sh`) and the pool (`parallel-tests.py run-spool`), with small shell
//! scripts standing in for test binaries. The cargo wiring between them is
//! exercised by the pre-commit hook itself on every commit.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script(name: &str) -> PathBuf {
    repo().join("scripts").join(name)
}

/// An executable shell script standing in for a test binary.
fn fake_binary(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake binary");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// Run the real recorder the way cargo's runner hook would, from `cwd`, with
/// `env` added, treating `target` as cargo's target directory.
fn recorder(
    spool: &Path,
    target: &Path,
    cwd: &Path,
    binary: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> Output {
    Command::new("sh")
        .arg(script("record-test-binary.sh"))
        .arg(spool)
        .arg(target)
        .arg(binary)
        .args(args)
        .current_dir(cwd)
        .envs(env.iter().copied())
        .output()
        .expect("run the recorder")
}

/// Record `binary args` (a fake test binary in the directory above `spool`,
/// which stands in for the target directory).
fn record(spool: &Path, cwd: &Path, binary: &Path, args: &[&str], env: &[(&str, &str)]) {
    let target = spool.parent().expect("spool has a parent");
    let out = recorder(spool, target, cwd, binary, args, env);
    assert!(
        out.status.success(),
        "the recorder failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "the recorder must print nothing (cargo would show it as test output)"
    );
}

fn run_spool(spool: &Path, jobs: usize, durations: &Path) -> (Output, Duration) {
    let started = Instant::now();
    let out = Command::new("python3")
        .arg(script("parallel-tests.py"))
        .arg("run-spool")
        .args(["--jobs", &jobs.to_string()])
        .arg("--durations")
        .arg(durations)
        .arg(spool)
        .output()
        .expect("run the pool");
    (out, started.elapsed())
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn every_binary_runs_with_the_argv_cwd_and_env_cargo_gave_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir(&pkg).expect("pkg");
    let bin = fake_binary(
        tmp.path(),
        "echoer",
        r#"echo "cwd=$(pwd)"; echo "arg1=$1"; echo "arg2=$2"; echo "multi=$MULTI_LINE_VALUE"; echo "test result: ok. 3 passed; 0 failed""#,
    );
    record(
        &spool,
        &pkg,
        &bin,
        &["--quiet", "two words"],
        &[("MULTI_LINE_VALUE", "first\nsecond")],
    );
    let (out, _) = run_spool(&spool, 2, &tmp.path().join("durations.json"));
    let all = text(&out);
    assert!(
        out.status.success(),
        "a passing binary failed the run:\n{all}"
    );
    let pkg = pkg.canonicalize().expect("canonical pkg");
    for wanted in [
        format!("cwd={}", pkg.display()),
        "arg1=--quiet".to_string(),
        "arg2=two words".to_string(),
        "multi=first\nsecond".to_string(),
        "test result: ok. 3 passed; 0 failed".to_string(),
    ] {
        assert!(all.contains(&wanted), "missing {wanted:?} in:\n{all}");
    }
}

#[test]
fn a_failing_binary_fails_the_run_and_the_others_still_run() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let bad = fake_binary(
        tmp.path(),
        "bad",
        "echo 'test broken ... FAILED'; echo '---- broken stdout ----'; echo 'why it broke'; \
         echo 'test result: FAILED. 0 passed; 1 failed'; exit 101",
    );
    let good = fake_binary(
        tmp.path(),
        "good",
        "echo 'test result: ok. 7 passed; 0 failed'",
    );
    record(&spool, tmp.path(), &bad, &[], &[]);
    record(&spool, tmp.path(), &good, &[], &[]);
    let (out, _) = run_spool(&spool, 2, &tmp.path().join("durations.json"));
    let all = text(&out);
    assert!(
        !out.status.success(),
        "a failing binary must fail the run:\n{all}"
    );
    assert!(
        all.contains("test result: ok. 7 passed"),
        "the binary after a failure must still run (no fail-fast):\n{all}"
    );
    // The hook reads a failure's detail as the lines after `---- NAME `, so
    // a binary's output must stay one contiguous block.
    assert!(
        all.contains("test broken ... FAILED\n---- broken stdout ----\nwhy it broke\n"),
        "a binary's output was split up:\n{all}"
    );
}

#[test]
fn binaries_run_side_by_side_up_to_the_job_limit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    for n in 0..3 {
        let bin = fake_binary(
            tmp.path(),
            &format!("sleeper{n}"),
            "sleep 1; echo 'test result: ok. 1 passed; 0 failed'",
        );
        record(&spool, tmp.path(), &bin, &[], &[]);
    }
    let (out, parallel) = run_spool(&spool, 3, &tmp.path().join("d1.json"));
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        parallel < Duration::from_millis(2500),
        "three 1 s binaries with 3 jobs took {parallel:?}: they did not overlap"
    );
    // POSITIVE CONTROL: with one job the same three are serial, so the
    // timing above measures the pool and not a fast machine.
    let (out, serial) = run_spool(&spool, 1, &tmp.path().join("d2.json"));
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        serial >= Duration::from_secs(3),
        "one job ran three 1 s binaries in {serial:?}: they overlapped anyway"
    );
}

#[test]
fn the_slowest_binary_last_time_starts_first() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let order = tmp.path().join("order");
    // Named so the order they load in (by path) is the opposite of the
    // order they must start in: only the duration sort can put slow first.
    let quick = fake_binary(
        tmp.path(),
        "a_quick",
        &format!("echo quick >> {}", order.display()),
    );
    let slow = fake_binary(
        tmp.path(),
        "b_slow",
        &format!("echo slow >> {}", order.display()),
    );
    record(&spool, tmp.path(), &quick, &[], &[]);
    record(&spool, tmp.path(), &slow, &[], &[]);
    let durations = tmp.path().join("durations.json");
    std::fs::write(
        &durations,
        format!(
            "{{\"{}\": 0.1, \"{}\": 50.0}}",
            quick.display(),
            slow.display()
        ),
    )
    .expect("seed durations");
    let (out, _) = run_spool(&spool, 1, &durations);
    assert!(out.status.success(), "{}", text(&out));
    let ran = std::fs::read_to_string(&order).expect("order file");
    assert_eq!(
        ran, "slow\nquick\n",
        "with one job, the binary that took longest last time must start first"
    );
    let saved = std::fs::read_to_string(&durations).expect("durations saved");
    assert!(
        saved.contains(&slow.display().to_string()) && saved.contains(&quick.display().to_string()),
        "this run's durations must be saved for the next one: {saved}"
    );
}

#[test]
fn an_empty_spool_is_an_error_not_a_green_run() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let (out, _) = run_spool(&spool, 2, &tmp.path().join("durations.json"));
    assert!(
        !out.status.success(),
        "no recorded binaries means the capture failed; passing would be a \
         vacuous green:\n{}",
        text(&out)
    );
}

/// Doctests go through the runner too (since Rust 1.89), but rustdoc builds
/// each one in a temporary directory it deletes as soon as the runner
/// returns, so a recorded doctest is gone before the pool could run it. A
/// binary outside the target directory is therefore run on the spot, with its
/// output and exit status passed straight back to cargo.
#[test]
fn a_binary_outside_the_target_dir_runs_at_once_and_is_not_recorded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let spool = target.join("spool");
    std::fs::create_dir_all(&spool).expect("spool");
    let elsewhere = tmp.path().join("rustdoctestXYZ");
    std::fs::create_dir(&elsewhere).expect("doctest dir");
    let doctest = fake_binary(
        &elsewhere,
        "rust_out",
        "echo \"doctest ran with $1\"; exit 3",
    );
    let out = recorder(&spool, &target, tmp.path(), &doctest, &["--flag"], &[]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "the doctest's own exit status must reach cargo"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "doctest ran with --flag\n",
        "the doctest must run immediately, with its arguments"
    );
    assert_eq!(
        std::fs::read_dir(&spool).expect("read spool").count(),
        0,
        "a doctest must not be recorded: its file is deleted before the pool runs"
    );
}

/// One binary that cannot start is that binary's failure. It must not abort
/// the pool (a Python traceback instead of results), and the rest still run.
#[test]
fn a_binary_that_cannot_start_fails_that_binary_not_the_run() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let gone = fake_binary(tmp.path(), "a_gone", "echo never");
    let good = fake_binary(
        tmp.path(),
        "b_good",
        "echo 'test result: ok. 5 passed; 0 failed'",
    );
    record(&spool, tmp.path(), &gone, &[], &[]);
    record(&spool, tmp.path(), &good, &[], &[]);
    std::fs::remove_file(&gone).expect("remove");
    let (out, _) = run_spool(&spool, 1, &tmp.path().join("durations.json"));
    let all = text(&out);
    assert!(
        !out.status.success(),
        "a binary that could not start must fail the run:\n{all}"
    );
    assert!(
        !all.contains("Traceback"),
        "the pool crashed instead of reporting the binary:\n{all}"
    );
    assert!(
        all.contains("test result: ok. 5 passed"),
        "the other binaries must still run:\n{all}"
    );
    assert!(
        all.contains(&gone.display().to_string()),
        "the failure must name the binary that could not start:\n{all}"
    );
}

/// A stand-in `cargo` on PATH: `metadata` names `target`, and anything else
/// prints `test_output` and exits 0 without calling the runner -- the shape of
/// a run where cargo executed everything itself.
fn fake_cargo(dir: &Path, target: &Path, test_output: &str) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    fake_binary(
        &bin,
        "cargo",
        &format!(
            "case \"$*\" in\n*metadata*) echo '{{\"target_directory\": \"{}\"}}' ;;\n*) printf '%s' '{}' ;;\nesac",
            target.display(),
            test_output
        ),
    );
    bin
}

fn run_capture(bin: &Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new("python3")
        .arg(script("parallel-tests.py"))
        .args(["--jobs", "2", "--"])
        .args(args)
        .env("PATH", path)
        .output()
        .expect("run parallel-tests.py")
}

/// `-- --doc` records nothing -- every doctest runs on the spot -- and is a
/// real, passing run: cargo printed the results itself.
#[test]
fn a_run_whose_tests_all_ran_inside_cargo_passes_on_cargos_results() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let bin = fake_cargo(
        tmp.path(),
        &target,
        "test result: ok. 4 passed; 0 failed; 0 ignored\n",
    );
    let out = run_capture(&bin, &["--doc"]);
    let all = text(&out);
    assert!(out.status.success(), "a doctest-only run failed:\n{all}");
    assert!(
        all.contains("test result: ok. 4 passed"),
        "cargo's own results must be passed through:\n{all}"
    );
}

/// ... but a run in which NOTHING reported a result is a capture that did not
/// happen, and must not pass.
#[test]
fn a_run_where_nothing_ran_anywhere_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let bin = fake_cargo(tmp.path(), &target, "   Compiling sipnab\n");
    let out = run_capture(&bin, &[]);
    assert!(
        !out.status.success(),
        "no binary recorded and no result printed must fail:\n{}",
        text(&out)
    );
}
