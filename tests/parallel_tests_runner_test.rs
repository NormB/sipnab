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
///
/// A child process writes it, never this one. This process runs its tests on
/// many threads, and any of them may fork (every `Command` does); a child
/// forked while this process held the file open for writing would carry that
/// descriptor until its own `exec`, and executing the file meanwhile fails
/// with ETXTBSY -- the recorder's `exec` exits 126 instead of the binary's
/// own status. Under host load that gap is long enough to hit
/// (`a_fake_binary_runs_while_other_threads_are_forking`).
fn fake_binary(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::process::Stdio;

    let path = dir.join(name);
    let mut writer = Command::new("sh")
        .arg("-c")
        .arg("cat >\"$1\" && chmod 755 \"$1\"")
        .arg("sh")
        .arg(&path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("start the fake binary's writer");
    writer
        .stdin
        .take()
        .expect("writer stdin")
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .expect("write fake binary");
    let status = writer.wait().expect("wait for the fake binary's writer");
    assert!(
        status.success(),
        "writing {} failed: {status}",
        path.display()
    );
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

/// Overlap is asserted directly, not inferred from elapsed time: each binary
/// waits at a barrier until all three have started, which only a pool running
/// them side by side can satisfy, at any host load. The test used to time
/// three `sleep 1` binaries against a 2500 ms bound, and a loaded host alone
/// pushed that past the bound with the pool working correctly (3 of 15 runs
/// with the one-minute load average between 63 and 129).
#[test]
fn binaries_run_side_by_side_up_to_the_job_limit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    std::fs::create_dir(&spool).expect("spool");
    let started = tmp.path().join("started");
    for n in 0..3 {
        let bin = fake_binary(
            tmp.path(),
            &format!("meeter{n}"),
            &format!(
                "mark='{marks}'\n\
                 echo start >>\"$mark\"\n\
                 end=$(( $(date +%s) + 30 ))\n\
                 while [ \"$(grep -c start \"$mark\")\" -lt 3 ]; do\n\
                 \x20 if [ \"$(date +%s)\" -ge \"$end\" ]; then\n\
                 \x20   echo \"met $(grep -c start \"$mark\") of 3 within 30 s\"\n\
                 \x20   echo 'test result: FAILED. 0 passed; 1 failed'; exit 1\n\
                 \x20 fi\n\
                 \x20 sleep 0.05\n\
                 done\n\
                 echo 'met 3 of 3'\n\
                 echo 'test result: ok. 1 passed; 0 failed'",
                marks = started.display()
            ),
        );
        record(&spool, tmp.path(), &bin, &[], &[]);
    }
    let (out, _) = run_spool(&spool, 3, &tmp.path().join("d1.json"));
    let all = text(&out);
    assert_eq!(
        all.matches("met 3 of 3").count(),
        3,
        "with 3 jobs, each of three binaries must see all three running at \
         once:\n{all}"
    );
    assert!(out.status.success(), "{all}");

    // POSITIVE CONTROL: with one job the pool must not overlap them. Each
    // binary brackets its run with markers; one job means strictly
    // start/end pairs, whatever the load.
    let serial_spool = tmp.path().join("serial-spool");
    std::fs::create_dir(&serial_spool).expect("serial spool");
    let order = tmp.path().join("order");
    for n in 0..3 {
        let bin = fake_binary(
            tmp.path(),
            &format!("bracket{n}"),
            &format!(
                "echo start >>'{o}'; sleep 0.2; echo end >>'{o}'; \
                 echo 'test result: ok. 1 passed; 0 failed'",
                o = order.display()
            ),
        );
        record(&serial_spool, tmp.path(), &bin, &[], &[]);
    }
    let (out, _) = run_spool(&serial_spool, 1, &tmp.path().join("d2.json"));
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        std::fs::read_to_string(&order).expect("order file"),
        "start\nend\nstart\nend\nstart\nend\n",
        "one job ran binaries that overlapped"
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

/// A fake binary must run the moment `fake_binary` returns, however busy the
/// other test threads are. Linux refuses to execute a file that any process
/// still has open for writing (ETXTBSY), and the recorder's `exec` then
/// answers 126 instead of the binary's own status. A child forked by another
/// thread inherits every descriptor this process has open at that instant and
/// keeps it until its own `exec`; under host load that gap stretches. Here the
/// sibling children pause between fork and exec on purpose, so a writable
/// descriptor to the fake binary, if this process ever holds one, is caught.
#[test]
fn a_fake_binary_runs_while_other_threads_are_forking() {
    use std::os::unix::process::CommandExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let spool = target.join("spool");
    std::fs::create_dir_all(&spool).expect("spool");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("binary dir");

    let stop = Arc::new(AtomicBool::new(false));
    let forkers: Vec<_> = (0..16)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut child = Command::new("true");
                    // SAFETY: the hook only sleeps (nanosleep), which is
                    // async-signal-safe; it allocates nothing and takes no lock.
                    unsafe {
                        child.pre_exec(|| {
                            std::thread::sleep(Duration::from_millis(30));
                            Ok(())
                        });
                    }
                    let _ = child.status();
                }
            })
        })
        .collect();

    // Bounded by time, so a loaded host costs seconds rather than minutes
    // (400 fixed iterations once took over 3 minutes at load average 100).
    // `this_process_never_holds_a_fake_binary_open` is the exhaustive check;
    // this one keeps the symptom itself, the 126, under test.
    let started = Instant::now();
    let mut failure = None;
    let mut i = 0;
    while i < MIN_RUNS || (i < MAX_RUNS && started.elapsed() < RUN_BUDGET) {
        let bin = fake_binary(&elsewhere, &format!("bin{i}"), "exit 3");
        let out = recorder(&spool, &target, tmp.path(), &bin, &[], &[]);
        if out.status.code() != Some(3) {
            failure = Some(format!(
                "fake binary {i} exited {:?}, not its own 3: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
            break;
        }
        i += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for forker in forkers {
        forker.join().expect("forker thread");
    }
    if let Some(failure) = failure {
        panic!("{failure}");
    }
}

/// Fake binaries run at least, whatever the time.
const MIN_RUNS: usize = 10;
/// Fake binaries run at most, however fast the host.
const MAX_RUNS: usize = 400;
/// Past this, stop starting fake binaries once `MIN_RUNS` have run.
const RUN_BUDGET: Duration = Duration::from_secs(2);

/// The property behind the test above, checked where it is decided: this
/// process must never hold a descriptor on a fake binary, not even briefly.
///
/// The test above only sees a descriptor that a sibling child still holds
/// when the binary runs. A helper that opens the file here just to create it,
/// then has a child write it, closes its descriptor well before that, so the
/// run succeeds and the defect hides (that mutant survived 400 iterations).
///
/// Here probe children list their own descriptors -- copies of this process's
/// table at the instant they were created -- and report any that names a file
/// in the fake binaries' directory, so a catch depends only on a probe being
/// created inside the window. Probes are made with `clone(CLONE_VM)`, the way
/// `posix_spawn` makes the children that hit this in practice. Without a copy
/// of the address space they come about fifty times as often as `fork`
/// children did (12,000 to 16,000 a second against about 270, measured on
/// thor-02);
/// forked probes missed that mutant in 2 runs of 5, these caught it in 20 of
/// 20. Linux only: `clone` and `/proc/self/fd`.
#[cfg(target_os = "linux")]
#[test]
fn this_process_never_holds_a_fake_binary_open() {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let tmp = tempfile::tempdir().expect("tempdir");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("binary dir");
    let reports_path = tmp.path().join("held");
    let reports = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&reports_path)
        .expect("reports file");
    let mut prefix = elsewhere.as_os_str().as_bytes().to_vec();
    prefix.push(b'/');
    let probe = Arc::new(Probe {
        prefix,
        report_fd: reports.as_raw_fd(),
    });
    let lowest_free = std::fs::File::open("/dev/null").expect("open /dev/null");
    assert!(
        lowest_free.as_raw_fd() < SCANNED_FDS / 2,
        "descriptor {} is already in use here; a probe scanning {SCANNED_FDS} \
         could miss one",
        lowest_free.as_raw_fd()
    );
    drop(lowest_free);

    let stop = Arc::new(AtomicBool::new(false));
    let probes = Arc::new(AtomicU64::new(0));
    let probers: Vec<_> = (0..PROBERS)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let probes = Arc::clone(&probes);
            let probe = Arc::clone(&probe);
            std::thread::spawn(move || {
                let mut stack = vec![0_u8; 256 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    run_probe(&probe, &mut stack);
                    probes.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    for i in 0..CREATED {
        fake_binary(&elsewhere, &format!("bin{i}"), "exit 3");
    }
    stop.store(true, Ordering::Relaxed);
    for prober in probers {
        prober.join().expect("prober thread");
    }
    drop(reports);
    let probes = probes.load(Ordering::Relaxed);
    assert!(
        probes >= CREATED as u64,
        "only {probes} probes ran while {CREATED} fake binaries were made: the \
         check never had a chance"
    );
    let held = std::fs::read_to_string(&reports_path).expect("reports");
    assert!(
        held.is_empty(),
        "a child created while fake_binary ran inherited a descriptor on a fake \
         binary ({probes} probes): {held}"
    );
}

#[cfg(target_os = "linux")]
const PROBERS: usize = 4;
#[cfg(target_os = "linux")]
const CREATED: usize = 400;
/// Descriptors a probe looks at. One opened in this process takes the lowest
/// free number, so this only has to exceed how many are open at once; the
/// test checks that it does.
#[cfg(target_os = "linux")]
const SCANNED_FDS: i32 = 256;

/// What a probe child needs, built before any probe exists.
#[cfg(target_os = "linux")]
struct Probe {
    prefix: Vec<u8>,
    report_fd: i32,
}

/// Create one probe child and wait for it.
#[cfg(target_os = "linux")]
fn run_probe(probe: &Probe, stack: &mut [u8]) {
    extern "C" fn child(arg: *mut libc::c_void) -> libc::c_int {
        // SAFETY: `arg` is the `&Probe` passed below, alive until the parent's
        // wait returns, which is after this child has exited.
        let probe = unsafe { &*arg.cast::<Probe>() };
        report_held_descriptors(&probe.prefix, probe.report_fd);
        0
    }
    spawn_and_wait_in_this_address_space(child, std::ptr::from_ref(probe).cast_mut().cast(), stack);
}

/// Run `child(arg)` in a new process that shares this address space but has
/// its own copy of the descriptor table, and wait for it to exit.
///
/// `child` must make only async-signal-safe calls on its own stack and read
/// nothing `arg` does not keep alive; `stack` is its stack, untouched by this
/// process until the wait has returned.
#[cfg(target_os = "linux")]
fn spawn_and_wait_in_this_address_space(
    child: extern "C" fn(*mut libc::c_void) -> libc::c_int,
    arg: *mut libc::c_void,
    stack: &mut [u8],
) {
    // The stack grows down: hand clone the 16-byte-aligned top.
    let top = (stack.as_mut_ptr() as usize + stack.len()) & !15;
    // SAFETY: CLONE_VM without CLONE_FILES gives the child a copy of the
    // descriptor table and this address space, the way posix_spawn does. The
    // caller's contract above keeps the child off anything but its own stack
    // and `arg`, and this function waits for it before either can go away.
    let pid = unsafe {
        libc::clone(
            child,
            top as *mut libc::c_void,
            libc::CLONE_VM | libc::SIGCHLD,
            arg,
        )
    };
    assert!(pid > 0, "clone failed: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: waits for the child created above.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "{}", std::io::Error::last_os_error());
}

/// In a probe child: write the path of every descriptor that names a file
/// under `prefix`, one per line, to `report_fd`. Async-signal-safe: raw
/// fcntl(2), readlink(2) and write(2) on stack buffers, no allocation.
#[cfg(target_os = "linux")]
fn report_held_descriptors(prefix: &[u8], report_fd: i32) {
    const FD_DIR: &[u8] = b"/proc/self/fd/";
    for fd in 0..SCANNED_FDS {
        // Cheap filter first: only a regular file can be a fake binary.
        // SAFETY: `libc::stat` is plain integers, for which all-zero is valid.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is a live stack value fstat(2) fills in.
        let failed = unsafe { libc::fstat(fd, &mut stat) } < 0;
        if failed || stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            continue;
        }
        let mut link = [0_u8; 32];
        link[..FD_DIR.len()].copy_from_slice(FD_DIR);
        let mut digits = [0_u8; 10];
        let mut n = fd.unsigned_abs();
        let mut len = 0;
        loop {
            digits[len] = b'0' + (n % 10) as u8;
            len += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        for k in 0..len {
            link[FD_DIR.len() + k] = digits[len - 1 - k];
        }
        // `link` is zero-filled, so it is NUL-terminated after the digits.
        let mut target = [0_u8; 4096];
        // SAFETY: both buffers are live stack arrays of the stated sizes.
        let got = unsafe {
            libc::readlink(
                link.as_ptr().cast(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        let Ok(got) = usize::try_from(got) else {
            continue;
        };
        let target = &target[..got];
        if target.starts_with(prefix) {
            // SAFETY: writes from live buffers to a descriptor this child
            // inherited open.
            unsafe {
                libc::write(report_fd, target.as_ptr().cast(), target.len());
                libc::write(report_fd, b"\n".as_ptr().cast(), 1);
            }
        }
    }
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
