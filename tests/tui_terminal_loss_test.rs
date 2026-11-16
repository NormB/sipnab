// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Measurements of a lost terminal, for the hosts CI runs on: what a pane's
//! process sees after each way the TUI tests lose its terminal, and how long
//! sipnab takes to end after each.
//!
//! On 2026-11-12 a sipnab outlived its SIGKILLed tmux server by 30 s on a
//! macOS runner (MACOS-TUI-NOT-ENDING-AFTER-TMUX-KILL), and no log since has
//! said why. CI's macOS job runs these two tests with `--nocapture`, so a
//! passing run carries the numbers too:
//!
//! - `a_pane_sees_its_terminal_lost_each_way`: a pane runs this binary's
//!   `pane_probe`, which records every 100 ms what `poll(2)`, `FIONREAD`, a
//!   read, `tcgetattr` and a SIGHUP handler say of its terminal. The test
//!   loses the terminal by `tmux kill-session`, by `tmux kill-server` and by
//!   SIGKILL of the tmux server, and prints each record where a column
//!   changed. Pass rule: each way shows a sign of the loss (a hang-up bit, an
//!   end of file or error on the read, or SIGHUP) within [`SIGN_WITHIN`].
//! - `sipnab_ends_after_each_way_of_losing_its_terminal`: sipnab is launched
//!   and its terminal lost in each way, in turn, up to [`LAUNCHES_PER_WAY`]
//!   times a way within [`LAUNCH_BUDGET`], and the time each took to end is
//!   printed (fewest, median, most), with the state of any sipnab past
//!   [`DESCRIBE_AFTER`]. Pass rule: every sipnab ends within [`END_WITHIN`].
//!
//! They are `#[ignore]` and not in tests/tui_e2e_test.rs because the
//! pre-push hook runs that file's ignored tests on every push, and the launch
//! test takes minutes. Run them by hand with:
//!
//! ```sh
//! cargo test --features tui --test tui_terminal_loss_test -- --ignored --nocapture --test-threads=1
//! ```

/// The guarded scratch directories the sessions' config homes live in.
#[cfg(all(feature = "tui", unix))]
#[path = "../src/test_scratch.rs"]
mod test_scratch;

/// The tmux harness the TUI tests drive.
#[cfg(all(feature = "tui", unix))]
#[path = "support/tmux_pane.rs"]
mod tmux_pane;

#[cfg(all(feature = "tui", unix))]
mod terminal_loss {
    use crate::tmux_pane::{TerminalLoss, TuiSession, describe_process};
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    type TestError = Box<dyn std::error::Error>;

    /// How soon after a loss the pane's process must see a sign of it.
    const SIGN_WITHIN: Duration = Duration::from_secs(10);
    /// How long a launched sipnab has to end after its terminal is lost.
    const END_WITHIN: Duration = Duration::from_secs(10);
    /// A sipnab still running this long after the loss is described.
    const DESCRIBE_AFTER: Duration = Duration::from_secs(5);
    /// The most launches a way, and the time all launches may take.
    const LAUNCHES_PER_WAY: usize = 20;
    const LAUNCH_BUDGET: Duration = Duration::from_secs(360);
    /// The environment variable that names the probe's output file; without
    /// it `pane_probe` returns at once.
    const PROBE_OUT: &str = "SIPNAB_PANE_PROBE_OUT";
    /// The probe's interval, its longest run, and how long it keeps
    /// recording after the first sign of the loss.
    const PROBE_EVERY: Duration = Duration::from_millis(100);
    const PROBE_AT_MOST: Duration = Duration::from_secs(35);
    const PROBE_AFTER_SIGN: Duration = Duration::from_secs(3);

    /// What the probe saw of its terminal (fd 0) at one moment.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Sample {
        /// Milliseconds since the Unix epoch.
        at_ms: u64,
        /// `revents` of `poll(2)` asked 0, POLLHUP, POLLIN and POLLOUT, with
        /// no wait; -1 when `poll` failed.
        revents: [i32; 4],
        /// What `FIONREAD` reported queued, or -errno.
        queued: i64,
        /// A non-blocking read: the bytes it returned, or -errno.
        read: i64,
        /// `tcgetattr`: 0, or the errno it failed with.
        tcgetattr: i32,
        /// When SIGHUP first arrived, ms since the epoch, or 0.
        sighup_ms: u64,
        /// The parent pid.
        ppid: i32,
    }

    impl Sample {
        /// One line of the probe's file.
        fn line(&self) -> String {
            format!(
                "at={} ask0={} hup={} in={} out={} queued={} read={} tcgetattr={} sighup={} ppid={}",
                self.at_ms,
                self.revents[0],
                self.revents[1],
                self.revents[2],
                self.revents[3],
                self.queued,
                self.read,
                self.tcgetattr,
                self.sighup_ms,
                self.ppid
            )
        }

        /// A line of the probe's file read back, `None` when it is not one.
        fn parse(line: &str) -> Option<Self> {
            let mut fields = std::collections::HashMap::new();
            for word in line.split_whitespace() {
                let (key, value) = word.split_once('=')?;
                fields.insert(key, value);
            }
            let get = |key: &str| fields.get(key).copied();
            if fields.len() != 10 {
                return None;
            }
            Some(Sample {
                at_ms: get("at")?.parse().ok()?,
                revents: [
                    get("ask0")?.parse().ok()?,
                    get("hup")?.parse().ok()?,
                    get("in")?.parse().ok()?,
                    get("out")?.parse().ok()?,
                ],
                queued: get("queued")?.parse().ok()?,
                read: get("read")?.parse().ok()?,
                tcgetattr: get("tcgetattr")?.parse().ok()?,
                sighup_ms: get("sighup")?.parse().ok()?,
                ppid: get("ppid")?.parse().ok()?,
            })
        }

        /// Whether this sample shows the terminal lost: a hang-up or error
        /// bit in any answer, a read at end of file or failing with EIO or
        /// ENXIO, or SIGHUP received.
        fn shows_loss(&self) -> bool {
            let gone = i32::from(libc::POLLHUP | libc::POLLERR | libc::POLLNVAL);
            self.revents.iter().any(|&r| r > 0 && r & gone != 0)
                || self.read == 0
                || self.read == -i64::from(libc::EIO)
                || self.read == -i64::from(libc::ENXIO)
                || self.sighup_ms != 0
        }

        /// The sample with its time left out, to compare two samples.
        fn state(&self) -> Self {
            Sample {
                at_ms: 0,
                ..self.clone()
            }
        }
    }

    /// The samples of a probe file, in order; lines that are not samples
    /// (a line cut by the end of a run) are left out.
    fn samples(text: &str) -> Vec<Sample> {
        text.lines().filter_map(Sample::parse).collect()
    }

    /// The milliseconds from `lost_ms` to the first sample at or after it
    /// that shows the loss, `None` when none does.
    fn first_sign_after(samples: &[Sample], lost_ms: u64) -> Option<u64> {
        samples
            .iter()
            .find(|s| s.at_ms >= lost_ms && s.shows_loss())
            .map(|s| s.at_ms - lost_ms)
    }

    /// The first sample and each one whose state differs from the one
    /// before it.
    fn changes(samples: &[Sample]) -> Vec<&Sample> {
        let mut out: Vec<&Sample> = Vec::new();
        for s in samples {
            if out.last().is_none_or(|last| last.state() != s.state()) {
                out.push(s);
            }
        }
        out
    }

    /// Fewest, median and most of `times`; `None` for none. The median of an
    /// even count is the lower middle one, so it is a measured value.
    fn spread(times: &[Duration]) -> Option<(Duration, Duration, Duration)> {
        let mut sorted = times.to_vec();
        sorted.sort();
        let median = *sorted.get((sorted.len().checked_sub(1)?) / 2)?;
        Some((*sorted.first()?, median, *sorted.last()?))
    }

    /// The ways to launch, in turn, `per_way` times each: one of each way,
    /// then the next round, so a budget that runs out leaves each way with
    /// about the same count.
    fn round_robin(ways: &[TerminalLoss], per_way: usize) -> Vec<TerminalLoss> {
        (0..per_way).flat_map(|_| ways.iter().copied()).collect()
    }

    /// The pass rule of the launch test: every launch ended within `bound`,
    /// and each way was launched at least once. The message names each
    /// launch that did not.
    fn launch_verdict(
        results: &[(TerminalLoss, Option<Duration>)],
        ways: &[TerminalLoss],
        bound: Duration,
    ) -> Result<(), String> {
        let mut problems = Vec::new();
        for way in ways {
            if !results.iter().any(|(w, _)| w == way) {
                problems.push(format!("{way:?}: no launch ran"));
            }
        }
        for (i, (way, took)) in results.iter().enumerate() {
            match took {
                Some(t) if *t <= bound => {}
                Some(t) => problems.push(format!("launch {i} ({way:?}) ended after {t:?}")),
                None => problems.push(format!(
                    "launch {i} ({way:?}) was still running {bound:?} after the loss"
                )),
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Milliseconds since the Unix epoch, through `clock_gettime`, which a
    /// signal handler may call.
    fn epoch_ms() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes the timespec it is given, which lives
        // on this stack frame for the call.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        u64::try_from(ts.tv_sec).unwrap_or(0) * 1000
            + u64::try_from(ts.tv_nsec).unwrap_or(0) / 1_000_000
    }

    /// When the probe first received SIGHUP, ms since the epoch, or 0.
    static SIGHUP_AT: AtomicU64 = AtomicU64::new(0);

    /// The probe's SIGHUP handler: it records the first arrival only.
    extern "C" fn on_sighup(_: libc::c_int) {
        let _ = SIGHUP_AT.compare_exchange(0, epoch_ms(), Ordering::SeqCst, Ordering::SeqCst);
    }

    /// The errno of the last failed call.
    fn errno() -> i64 {
        i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// What fd 0 looks like now.
    fn sample_terminal() -> Sample {
        let mut revents = [0i32; 4];
        for (slot, ask) in revents
            .iter_mut()
            .zip([0, libc::POLLHUP, libc::POLLIN, libc::POLLOUT])
        {
            let mut fd = libc::pollfd {
                fd: 0,
                events: ask,
                revents: 0,
            };
            // SAFETY: poll reads and writes the one pollfd given, with no
            // wait.
            let n = unsafe { libc::poll(&mut fd, 1, 0) };
            *slot = if n < 0 { -1 } else { i32::from(fd.revents) };
        }
        let mut queued: libc::c_int = 0;
        // SAFETY: FIONREAD writes one c_int to the pointer given.
        let rc = unsafe { libc::ioctl(0, libc::FIONREAD, &mut queued) };
        let queued = if rc < 0 { -errno() } else { i64::from(queued) };
        let mut buf = [0u8; 64];
        // SAFETY: read writes at most buf.len() bytes into buf; fd 0 is
        // non-blocking (set by the probe before its first sample).
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        let read = if n < 0 { -errno() } else { n as i64 };
        // SAFETY: tcgetattr writes the termios given, zeroed here.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes only the termios it is given.
        let rc = unsafe { libc::tcgetattr(0, &mut termios) };
        let tcgetattr = if rc < 0 { errno() as i32 } else { 0 };
        Sample {
            at_ms: epoch_ms(),
            revents,
            queued,
            read,
            tcgetattr,
            sighup_ms: SIGHUP_AT.load(Ordering::SeqCst),
            // SAFETY: getppid has no arguments and cannot fail.
            ppid: unsafe { libc::getppid() },
        }
    }

    /// The pane's side of `a_pane_sees_its_terminal_lost_each_way`: run by
    /// that test inside a tmux pane, with [`PROBE_OUT`] naming a file. Run
    /// any other way (no [`PROBE_OUT`]), it returns at once.
    #[test]
    #[ignore = "the pane's side of a_pane_sees_its_terminal_lost_each_way, which spawns it"]
    fn pane_probe() -> Result<(), TestError> {
        let Some(out) = std::env::var_os(PROBE_OUT) else {
            return Ok(());
        };
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(out)?;
        // SAFETY: the handler only stores into an atomic and reads the
        // clock, both async-signal-safe; the sigaction struct is zeroed and
        // then given that handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sighup as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut());
            let flags = libc::fcntl(0, libc::F_GETFL);
            libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let start = Instant::now();
        let mut sign_at: Option<Instant> = None;
        while start.elapsed() < PROBE_AT_MOST {
            let sample = sample_terminal();
            writeln!(file, "{}", sample.line())?;
            if sample.shows_loss() && sign_at.is_none() {
                sign_at = Some(Instant::now());
            }
            if sign_at.is_some_and(|at| at.elapsed() >= PROBE_AFTER_SIGN) {
                break;
            }
            std::thread::sleep(PROBE_EVERY);
        }
        Ok(())
    }

    /// The probe file's text once it has stopped growing for 1.5 s, or at
    /// `within`.
    fn settled(path: &std::path::Path, within: Duration) -> String {
        let deadline = Instant::now() + within;
        let mut last = (0, Instant::now());
        loop {
            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            if len != last.0 {
                last = (len, Instant::now());
            }
            if last.1.elapsed() >= Duration::from_millis(1500) || Instant::now() >= deadline {
                return std::fs::read_to_string(path).unwrap_or_default();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The probe's file has `n` samples, within `within`.
    fn wait_for_samples(path: &std::path::Path, n: usize, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if samples(&text).len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Each way of losing a pane's terminal: what the process in it saw,
    /// printed record by record, and how soon it saw a sign of the loss.
    #[test]
    #[ignore = "needs tmux on PATH; run by CI's macOS job with --ignored"]
    fn a_pane_sees_its_terminal_lost_each_way() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-pane-probe-")?;
        let exe = std::env::current_exe()?;
        let exe = exe.to_str().ok_or("the test binary's path is not UTF-8")?;
        let mut report = String::new();
        let mut failures = Vec::new();
        for way in TerminalLoss::ALL {
            let out = dir.join(format!("{way:?}.txt"));
            let out_text = out.to_str().ok_or("the scratch path is not UTF-8")?;
            let mut session = TuiSession::launch_program(
                80,
                24,
                env!("CARGO_MANIFEST_DIR"),
                exe,
                &[
                    "--exact",
                    "terminal_loss::pane_probe",
                    "--ignored",
                    "--nocapture",
                ],
                &[(PROBE_OUT, out_text)],
            )?;
            if !wait_for_samples(&out, 5, Duration::from_secs(20)) {
                failures.push(format!("{way:?}: the probe wrote no samples within 20 s"));
                continue;
            }
            let lost_ms = epoch_ms();
            session.lose_terminal(way)?;
            let all = samples(&settled(&out, PROBE_AT_MOST + Duration::from_secs(5)));
            let sign = first_sign_after(&all, lost_ms);
            report.push_str(&format!(
                "\n{way:?}: lost at {lost_ms}; first sign after {sign:?} ms; {} samples\n",
                all.len()
            ));
            for s in changes(&all) {
                let at = i128::from(s.at_ms) - i128::from(lost_ms);
                report.push_str(&format!("  {at:+} ms {}\n", s.line()));
            }
            match sign {
                Some(ms) if Duration::from_millis(ms) <= SIGN_WITHIN => {}
                other => failures.push(format!(
                    "{way:?}: no sign of the loss within {SIGN_WITHIN:?} (first: {other:?} ms)"
                )),
            }
        }
        eprintln!("terminal-loss probe ({}):{report}", std::env::consts::OS);
        assert!(failures.is_empty(), "{}\n{report}", failures.join("; "));
        Ok(())
    }

    /// sipnab, launched again and again, ends soon after its terminal is
    /// lost in each way; the times are printed per way.
    #[test]
    #[ignore = "needs tmux on PATH; run by CI's macOS job with --ignored"]
    fn sipnab_ends_after_each_way_of_losing_its_terminal() -> Result<(), TestError> {
        let started = Instant::now();
        let mut results: Vec<(TerminalLoss, Option<Duration>)> = Vec::new();
        for way in round_robin(&TerminalLoss::ALL, LAUNCHES_PER_WAY) {
            if started.elapsed() >= LAUNCH_BUDGET {
                break;
            }
            let mut session = TuiSession::launch_sip_call()?;
            session.wait_for("INVITE")?;
            let lost = Instant::now();
            session.lose_terminal(way)?;
            let mut described = false;
            let took = loop {
                if !session.sipnab.running() {
                    break Some(lost.elapsed());
                }
                if lost.elapsed() >= END_WITHIN {
                    eprintln!(
                        "launch {} ({way:?}) still running at {END_WITHIN:?}: {}",
                        results.len(),
                        describe_process(session.sipnab.pid)
                    );
                    session.sipnab.kill();
                    break None;
                }
                if !described && lost.elapsed() >= DESCRIBE_AFTER {
                    described = true;
                    eprintln!(
                        "launch {} ({way:?}) still running at {DESCRIBE_AFTER:?}: {}",
                        results.len(),
                        describe_process(session.sipnab.pid)
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            results.push((way, took));
        }
        let mut table = String::new();
        for way in TerminalLoss::ALL {
            let times: Vec<Duration> = results
                .iter()
                .filter(|(w, _)| *w == way)
                .filter_map(|(_, t)| *t)
                .collect();
            let count = results.iter().filter(|(w, _)| *w == way).count();
            table.push_str(&format!(
                "\n  {way:?}: {count} launches, {} ended; fewest, median, most: {:?}",
                times.len(),
                spread(&times)
            ));
        }
        eprintln!(
            "sipnab end after a lost terminal ({}, {:?} in all):{table}",
            std::env::consts::OS,
            started.elapsed()
        );
        launch_verdict(&results, &TerminalLoss::ALL, END_WITHIN)
            .map_err(|e| format!("{e}{table}").into())
    }

    /// The measurements' own rules, run everywhere: the probe's record, the
    /// sign of a loss, the spread and the pass rule of the launch test.
    mod rules {
        use super::*;

        /// A sample of a terminal with nothing to report, at `at_ms`.
        fn quiet(at_ms: u64) -> Sample {
            Sample {
                at_ms,
                revents: [0; 4],
                queued: 0,
                read: -i64::from(libc::EAGAIN),
                tcgetattr: 0,
                sighup_ms: 0,
                ppid: 0,
            }
        }

        fn ms(n: u64) -> Duration {
            Duration::from_millis(n)
        }

        // SUCCESS

        #[test]
        fn a_sample_reads_back_as_it_was_written() {
            let mut s = quiet(1_700_000_000_123);
            s.revents = [0, 16, 17, 4];
            s.queued = 3;
            s.read = -35;
            s.sighup_ms = 1_700_000_000_200;
            assert_eq!(
                Sample::parse(&s.line()),
                Some(s.clone()),
                "line: {}",
                s.line()
            );
        }

        #[test]
        fn the_first_sign_is_the_first_sample_after_the_loss_that_shows_it() {
            let mut gone = quiet(1300);
            gone.revents[1] = i32::from(libc::POLLHUP);
            let all = vec![quiet(1000), quiet(1100), quiet(1200), gone];
            assert_eq!(first_sign_after(&all, 1050), Some(250), "1300 - 1050");
        }

        #[test]
        fn changes_keep_the_first_sample_and_each_new_state() {
            let mut later = quiet(300);
            later.read = 0;
            let all = vec![quiet(100), quiet(200), later.clone(), quiet(400)];
            let got: Vec<u64> = changes(&all).iter().map(|s| s.at_ms).collect();
            assert_eq!(got, vec![100, 300, 400], "the first, then each change");
        }

        #[test]
        fn the_spread_of_an_odd_count_is_fewest_middle_most() {
            assert_eq!(
                spread(&[ms(30), ms(10), ms(20)]),
                Some((ms(10), ms(20), ms(30))),
                "sorted, then fewest, median, most"
            );
        }

        #[test]
        fn launches_take_the_ways_in_turn() {
            let got = round_robin(&TerminalLoss::ALL, 2);
            let mut want = TerminalLoss::ALL.to_vec();
            want.extend(TerminalLoss::ALL);
            assert_eq!(got, want, "one of each way per round");
        }

        #[test]
        fn launches_that_all_ended_in_time_pass() {
            let results: Vec<_> = TerminalLoss::ALL
                .iter()
                .map(|w| (*w, Some(ms(400))))
                .collect();
            assert_eq!(
                launch_verdict(&results, &TerminalLoss::ALL, ms(10_000)),
                Ok(()),
                "all ended"
            );
        }

        // FAILURE

        #[test]
        fn a_line_without_every_field_is_not_a_sample() {
            let line = quiet(5).line().replace(" ppid=0", "");
            assert_eq!(Sample::parse(&line), None, "nine fields: {line}");
        }

        #[test]
        fn a_line_with_a_field_the_probe_does_not_write_is_not_a_sample() {
            let line = format!("{} extra=1", quiet(5).line());
            assert_eq!(Sample::parse(&line), None, "eleven fields: {line}");
        }

        #[test]
        fn a_line_with_a_word_that_is_not_a_number_is_not_a_sample() {
            let line = quiet(5).line().replace("queued=0", "queued=many");
            assert_eq!(Sample::parse(&line), None, "not a number: {line}");
        }

        #[test]
        fn a_launch_that_ended_late_fails_by_name() {
            let mut results: Vec<_> = TerminalLoss::ALL
                .iter()
                .map(|w| (*w, Some(ms(400))))
                .collect();
            results[1].1 = Some(ms(12_000));
            let e = launch_verdict(&results, &TerminalLoss::ALL, ms(10_000)).unwrap_err();
            assert!(
                e.contains("launch 1") && e.contains("12s"),
                "names the late launch: {e}"
            );
        }

        #[test]
        fn a_launch_still_running_fails_by_name() {
            let mut results: Vec<_> = TerminalLoss::ALL
                .iter()
                .map(|w| (*w, Some(ms(400))))
                .collect();
            results[2].1 = None;
            let e = launch_verdict(&results, &TerminalLoss::ALL, ms(10_000)).unwrap_err();
            assert!(
                e.contains("launch 2") && e.contains("still running"),
                "names it: {e}"
            );
        }

        #[test]
        fn a_way_never_launched_fails() {
            let results = vec![(TerminalLoss::ALL[0], Some(ms(400)))];
            let e = launch_verdict(&results, &TerminalLoss::ALL, ms(10_000)).unwrap_err();
            assert!(
                e.contains("no launch ran"),
                "a way without a launch is no measurement: {e}"
            );
        }

        #[test]
        fn a_probe_that_never_saw_a_loss_has_no_first_sign() {
            let all = vec![quiet(1000), quiet(1100), quiet(1200)];
            assert_eq!(first_sign_after(&all, 1000), None, "nothing shows a loss");
        }

        // EDGE

        #[test]
        fn a_sign_before_the_loss_is_not_its_sign() {
            let mut early = quiet(900);
            early.read = 0;
            let all = vec![early, quiet(1100)];
            assert_eq!(
                first_sign_after(&all, 1000),
                None,
                "a sign before the loss does not count"
            );
        }

        #[test]
        fn a_failed_poll_is_not_a_hang_up() {
            let mut s = quiet(1);
            s.revents = [-1, -1, -1, -1];
            assert!(
                !s.shows_loss(),
                "poll's -1 has every bit set and is not an answer"
            );
        }

        #[test]
        fn a_read_at_end_of_file_or_failing_with_eio_shows_the_loss() {
            let mut eof = quiet(1);
            eof.read = 0;
            let mut eio = quiet(1);
            eio.read = -i64::from(libc::EIO);
            let mut again = quiet(1);
            again.read = -i64::from(libc::EAGAIN);
            assert!(
                eof.shows_loss() && eio.shows_loss(),
                "end of file and EIO are the loss"
            );
            assert!(
                !again.shows_loss(),
                "EAGAIN is a terminal with nothing to read"
            );
        }

        #[test]
        fn sighup_alone_shows_the_loss() {
            let mut s = quiet(1);
            s.sighup_ms = 5;
            assert!(s.shows_loss(), "SIGHUP is a sign of the loss");
        }

        #[test]
        fn a_change_of_time_alone_is_not_a_change() {
            let all = vec![quiet(100), quiet(200), quiet(300)];
            assert_eq!(
                changes(&all).len(),
                1,
                "the same state three times is one record"
            );
        }

        #[test]
        fn the_spread_of_nothing_is_none_and_of_an_even_count_takes_the_lower_middle() {
            assert_eq!(spread(&[]), None, "no launches, no spread");
            assert_eq!(
                spread(&[ms(40), ms(10), ms(30), ms(20)]),
                Some((ms(10), ms(20), ms(40))),
                "the lower middle of four is a measured value"
            );
        }

        #[test]
        fn a_cut_last_line_is_left_out_of_the_samples() {
            let text = format!(
                "{}\n{}\nat=12 ask0=0 hu",
                quiet(10).line(),
                quiet(11).line()
            );
            assert_eq!(samples(&text).len(), 2, "the cut line is not a sample");
        }

        #[test]
        fn a_launch_exactly_at_the_bound_passes() {
            let results: Vec<_> = TerminalLoss::ALL
                .iter()
                .map(|w| (*w, Some(ms(10_000))))
                .collect();
            assert_eq!(
                launch_verdict(&results, &TerminalLoss::ALL, ms(10_000)),
                Ok(()),
                "at the bound"
            );
        }
    }
}

include!("support/child_lifetime.rs");
