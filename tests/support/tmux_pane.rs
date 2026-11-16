// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! The tmux harness of the TUI tests: a session per test on its own tmux
//! server, the pane's process, and what that process is doing when a test
//! gives up waiting for it. tests/tui_e2e_test.rs and
//! tests/tui_terminal_loss_test.rs include it; each declares `test_scratch`
//! and includes support/child_lifetime.rs at its root.
#![allow(dead_code)]

/// The error a harness call returns: any error, boxed.
type TestError = Box<dyn std::error::Error>;

use crate::TiedToTest as _;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Per-process counter giving each test's tmux session a unique name
/// (tests in one binary run concurrently and must not share sessions).
pub(crate) static SESSION_SEQ: AtomicU32 = AtomicU32::new(0);

/// A `tmux` command on the server named `socket` (`tmux -L socket`). Each
/// session uses its own name as its server's socket, so no two tests
/// share a tmux server: a shared one exits when its last session ends,
/// and a test starting a session at that moment fails.
pub(crate) fn tmux_for(socket: &str) -> Command {
    let mut command = Command::new("tmux");
    command.args(["-L", socket]);
    command
}

/// A tmux session running sipnab; killed automatically on drop.
pub(crate) struct TuiSession {
    /// tmux session name, unique per process and per test.
    pub(crate) name: String,
    /// The session's own XDG_CONFIG_HOME, removed when the session drops
    /// by the guard it is.
    pub(crate) cfg_home: crate::test_scratch::ScratchDir,
    /// The socket of the session's own tmux server, removed when the
    /// session drops: `tmux kill-server` leaves it behind.
    pub(crate) socket: std::path::PathBuf,
    /// The session's tmux server, started by this test as its own child
    /// (`tmux -D`), so it is reaped here and, on Linux, dies with the
    /// thread that started it ([`spawn_server`]).
    pub(crate) server: Option<std::process::Child>,
    /// The pane's process, which is sipnab: the launch command `exec`s it.
    pub(crate) sipnab: PaneProcess,
}

/// The process a pane runs, identified by its pid and its start time, so
/// a pid the kernel has reused for another process is never taken for it
/// and never signaled.
#[derive(Debug, Clone)]
pub(crate) struct PaneProcess {
    /// The pid tmux reported for the pane.
    pub(crate) pid: libc::pid_t,
    /// Its start time as [`process_state`] reads it, `None` when it could
    /// not be read.
    pub(crate) start: Option<String>,
}

impl PaneProcess {
    /// The pane's process now, by the pid tmux reports for it.
    pub(crate) fn of(name: &str) -> Result<Self, TestError> {
        let out = tmux_for(name)
            .args(["display-message", "-p", "-t", name, "#{pane_pid}"])
            .output()?;
        let pid: libc::pid_t = String::from_utf8_lossy(&out.stdout).trim().parse()?;
        Ok(PaneProcess {
            pid,
            start: process_state(pid).map(|(_, start)| start),
        })
    }

    /// Whether the process is still running: it exists, it is the same
    /// process (same start time), and it is not a zombie.
    pub(crate) fn running(&self) -> bool {
        match process_state(self.pid) {
            Some((state, start)) => Some(start) == self.start && state != 'Z',
            None => false,
        }
    }

    /// Wait up to `within` for the process to end. One that has not is
    /// described on standard error ([`describe_process`]) before this
    /// returns `false`, while it is still in the state that kept it.
    pub(crate) fn ended_within(&self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while self.running() {
            if Instant::now() >= deadline {
                eprintln!(
                    "still running after {} s: {}",
                    within.as_secs(),
                    describe_process(self.pid)
                );
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }

    /// SIGKILL the process, if it is still the one the pane ran.
    pub(crate) fn kill(&self) {
        if self.running() {
            // SAFETY: kill(2) on the pane process this test started,
            // checked by start time to be that process still.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            }
        }
    }
}

/// The state letter and start time of `pid`, or `None` when it does not
/// exist. Linux reads `/proc/<pid>/stat` (state, and the start time in
/// clock ticks since boot); elsewhere `ps -o stat=,lstart=`.
pub(crate) fn process_state(pid: libc::pid_t) -> Option<(char, String)> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // Fields after the parenthesized command name, which may itself
        // hold spaces: state is the first, start time the 20th.
        let rest = stat.rsplit_once(')')?.1;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        Some((
            fields.first()?.chars().next()?,
            (*fields.get(19)?).to_string(),
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = Command::new("ps")
            .args(["-o", "stat=,lstart=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let (state, start) = text.trim().split_once(char::is_whitespace)?;
        Some((state.chars().next()?, start.trim().to_string()))
    }
}

/// The first `max` lines of `text`, then a count of the lines left out.
pub(crate) fn first_lines(text: &str, max: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= max {
        return lines.join("\n");
    }
    format!(
        "{}\n({} more lines)",
        lines[..max].join("\n"),
        lines.len() - max
    )
}

/// What `pid` is doing, for the output of a test that gave up waiting
/// for it to end: its state, CPU time, elapsed time and command from
/// `ps`, then each thread's name and state on Linux, and on macOS the
/// call graphs `sample` takes over one second. CPU time that grows with
/// the elapsed time is a busy loop; CPU time that stands still is a
/// blocked call, and the call graph names it.
pub(crate) fn describe_process(pid: libc::pid_t) -> String {
    let ps = Command::new("ps")
        .args(["-o", "stat=,time=,etime=,command=", "-p", &pid.to_string()])
        .output();
    let line = match ps {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => format!("ps did not run: {e}"),
    };
    if line.is_empty() {
        return format!("pid {pid}: no such process");
    }
    format!(
        "pid {pid}: state, CPU time, elapsed time, command: {line}{}",
        platform_detail(pid)
    )
}

/// Linux: each thread of `pid` with its state, from `/proc/<pid>/task`.
#[cfg(target_os = "linux")]
pub(crate) fn platform_detail(pid: libc::pid_t) -> String {
    let mut threads: Vec<(u64, String)> = Vec::new();
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for task in tasks.flatten() {
            let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
                continue;
            };
            // `tid (name) state ...`: the name may hold spaces.
            let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
                continue;
            };
            let tid = stat[..open].trim().parse().unwrap_or(0);
            let state = stat[close + 1..].split_whitespace().next().unwrap_or("?");
            threads.push((tid, format!("\n  {} {state}", &stat[open + 1..close])));
        }
    }
    threads.sort();
    let lines: String = threads.into_iter().map(|(_tid, line)| line).collect();
    format!("\nthreads (name, state):{lines}")
}

/// macOS: the call graphs `sample` takes of `pid` over one second, its
/// first 200 lines, or what `sample` said when it wrote no report.
#[cfg(target_os = "macos")]
pub(crate) fn platform_detail(pid: libc::pid_t) -> String {
    let text = match tempfile::tempdir() {
        Ok(dir) => {
            let file = dir.path().join("sample.txt");
            let ran = Command::new("sample")
                .args([&pid.to_string(), "1", "-mayDie", "-file"])
                .arg(&file)
                .output();
            match ran {
                Ok(out) => std::fs::read_to_string(&file).unwrap_or_else(|e| {
                    format!(
                        "no report ({e}); sample said: {}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    )
                }),
                Err(e) => format!("sample did not run: {e}"),
            }
        }
        Err(e) => format!("no directory for the report: {e}"),
    };
    format!("\nsample:\n{}", first_lines(&text, 200))
}

/// Other systems: `ps` is all there is.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn platform_detail(_pid: libc::pid_t) -> String {
    String::new()
}

/// How long sipnab has to end on its own once its tmux server is gone.
pub(crate) const SIPNAB_END_TIMEOUT: Duration = Duration::from_secs(15);

/// Start the tmux server for socket `name` as this test's own child,
/// in the foreground (`-D`), and wait until it listens.
///
/// tmux daemonizes a server it starts for `new-session`, so a test that
/// dies (killed by a hook's timeout, say) leaves that server and every
/// pane running: nothing kills them. A server that is the test's child
/// is reaped by the session's Drop, and on Linux it is SIGKILLed by the
/// kernel when the thread that started it ends (`PR_SET_PDEATHSIG`, set
/// by `tied_to_test` from `support/child_lifetime.rs`), so
/// it cannot outlive the test. Its panes then lose their terminal, and
/// sipnab ends on a lost terminal.
pub(crate) fn spawn_server(name: &str) -> Result<std::process::Child, TestError> {
    let mut cmd = tmux_for(name);
    cmd.arg("-D")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut server = cmd.tied_to_test().spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // `start-server` would start a daemonized server of its own if this
    // one were not up yet, so wait for this one's socket to answer.
    while !tmux_for(name)
        .args(["-N", "list-sessions"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        if let Some(status) = server.try_wait()? {
            return Err(format!("the tmux server for {name} exited: {status}").into());
        }
        if Instant::now() >= deadline {
            let _ = server.kill();
            let _ = server.wait();
            return Err(format!("the tmux server for {name} did not start within 10 s").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(server)
}

impl TuiSession {
    /// Launch sipnab in a detached tmux session of the given size, with the
    /// working directory set to `cwd` (so the file-open browser lists files
    /// there) and the given extra CLI args.
    ///
    /// # Arguments
    /// * `cols` / `rows` - Terminal size of the tmux session.
    /// * `cwd` - Working directory the binary starts in.
    /// * `args` - Extra CLI arguments appended after the binary path.
    ///
    /// # Side effects
    /// Spawns a detached tmux session running the real sipnab binary; the
    /// session is killed when the returned `TuiSession` is dropped.
    pub(crate) fn launch(
        cols: u16,
        rows: u16,
        cwd: &str,
        args: &[&str],
    ) -> Result<Self, TestError> {
        let bin = env!("CARGO_BIN_EXE_sipnab");
        let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("sipnab_e2e_{}_{}", std::process::id(), seq);

        // Every session gets its own XDG_CONFIG_HOME.
        //
        // sipnab stores manual address names in
        // `$XDG_CONFIG_HOME/sipnab/hosts`, and the Name-Address dialog SEEDS
        // its edit field from whatever is stored for that address. Without
        // this, `tui_name_address_resolves_in_columns` wrote "edge-proxy"
        // into the developer's real ~/.config/sipnab/hosts on every run,
        // then re-loaded it and appended on the next: after enough runs the
        // stored name passed MAX_NAME_LEN, every save was refused, and the
        // test could NEVER pass again on that machine. It was found at 250
        // bytes on the self-hosted runner, which shares $HOME with
        // everything else on the box.
        //
        // A test that writes to $HOME is not a test, it is a side effect
        // with an assertion attached.
        // A guarded directory: removed when the session drops, a panic
        // included, and named by tempfile so no other process can take it.
        let cfg_home = crate::test_scratch::ScratchDir::new("sipnab-e2e-cfg-")
            .map_err(|e| format!("scratch dir: {e}"))?;
        std::fs::create_dir_all(&cfg_home)?;

        // tmux runs the command via the shell; cd first so the file browser
        // and any relative paths resolve under the fixture directory.
        let cmd = format!(
            "cd {} && XDG_CONFIG_HOME={} exec {} {}",
            shell_quote(cwd),
            shell_quote(&cfg_home.to_string_lossy()),
            shell_quote(bin),
            args.iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
        );

        let mut server = spawn_server(&name)?;
        let status = tmux_for(&name)
            .args([
                "new-session",
                "-d",
                "-s",
                &name,
                "-x",
                &cols.to_string(),
                "-y",
                &rows.to_string(),
                &cmd,
            ])
            .status()?;
        if !status.success() {
            let _ = server.kill();
            let _ = server.wait();
        }
        assert!(status.success(), "tmux new-session failed");
        let out = tmux_for(&name)
            .args(["display-message", "-p", "#{socket_path}"])
            .output()?;
        let socket = std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        let sipnab = PaneProcess::of(&name)?;

        Ok(TuiSession {
            name,
            cfg_home,
            socket,
            server: Some(server),
            sipnab,
        })
    }

    /// End the session: kill its tmux server, reap it, and wait for
    /// sipnab to end on its own, as it must once its terminal is gone.
    /// A sipnab still running after [`SIPNAB_END_TIMEOUT`] is SIGKILLed,
    /// so no test leaves one behind, and this returns `false`.
    ///
    /// Idempotent: Drop calls it too.
    pub(crate) fn close(&mut self) -> bool {
        let _ = tmux_for(&self.name).arg("kill-server").status();
        if let Some(mut server) = self.server.take() {
            let deadline = Instant::now() + Duration::from_secs(5);
            while matches!(server.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = server.kill();
            let _ = server.wait();
        }
        let _ = std::fs::remove_file(&self.socket);
        if self.sipnab.ended_within(SIPNAB_END_TIMEOUT) {
            return true;
        }
        self.sipnab.kill();
        false
    }

    /// Default-size launch loading the bundled SIP call fixture.
    ///
    /// # Returns
    /// A 150x40 session started in `tests/fixtures` with `-I sip_call.pcap`.
    pub(crate) fn launch_sip_call() -> Result<Self, TestError> {
        Self::launch(150, 40, fixtures_dir(), &["-I", "sip_call.pcap"])
    }

    /// Capture the visible pane contents as text.
    ///
    /// # Returns
    /// The pane text from `tmux capture-pane -p` (lossy UTF-8).
    pub(crate) fn screen(&self) -> Result<String, TestError> {
        let out = tmux_for(&self.name)
            .args(["capture-pane", "-t", &self.name, "-p"])
            .output()?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Poll the screen until `needle` appears, returning the screen. An
    /// error carrying the last captured screen on timeout.
    ///
    /// # Arguments
    /// * `needle` - Substring polled for (50 ms interval, 5 s deadline).
    pub(crate) fn wait_for(&self, needle: &str) -> Result<String, TestError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let last = self.screen()?;
            if last.contains(needle) {
                return Ok(last);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {needle:?} in session {}.\nlast screen:\n{last}",
                    self.name
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Poll the screen until `pred` holds, returning the matching screen.
    /// An error naming `desc` and the last captured screen on timeout. Used
    /// for conditions a plain substring search can't express (e.g. an
    /// element must *disappear*, or a count must reach a value).
    ///
    /// # Arguments
    /// * `desc` - Human description of the awaited condition (for the timeout error).
    /// * `pred` - Predicate over the captured screen (50 ms interval, 5 s deadline).
    pub(crate) fn wait_until(
        &self,
        desc: &str,
        pred: impl Fn(&str) -> bool,
    ) -> Result<String, TestError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let last = self.screen()?;
            if pred(&last) {
                return Ok(last);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {desc} in session {}.\nlast screen:\n{last}",
                    self.name
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Capture repeatedly until two consecutive captures match — i.e. the
    /// render loop has settled after the last key — then return that
    /// stable screen. This replaces guessing a fixed post-key delay when
    /// the awaited content can't be named in advance (the assertion that
    /// follows is the real check). Falls back to the latest capture at the
    /// 5 s deadline.
    pub(crate) fn stable_screen(&self) -> Result<String, TestError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut prev = self.screen()?;
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let cur = self.screen()?;
            if cur == prev || Instant::now() >= deadline {
                return Ok(cur);
            }
            prev = cur;
        }
    }

    /// Send a named key (e.g. "Enter", "Tab", "Escape", "F1").
    pub(crate) fn key(&self, name: &str) -> Result<(), TestError> {
        self.send(&[name])?;
        Ok(())
    }

    /// Send literal characters (case-preserving), e.g. "v" or "O".
    pub(crate) fn literal(&self, chars: &str) -> Result<(), TestError> {
        self.send(&["-l", chars])?;
        Ok(())
    }

    /// Run `tmux send-keys` for this session with the given trailing args.
    ///
    /// Keys queue in the PTY and are consumed by the app in order, so no
    /// post-send sleep is needed for correctness; capture helpers
    /// (`wait_for`, `wait_until`, `stable_screen`) poll the screen and are
    /// what actually synchronize with the render loop.
    ///
    /// # Side effects
    /// Spawns tmux to deliver the key(s) to the pane.
    pub(crate) fn send(&self, tail: &[&str]) -> Result<(), TestError> {
        let mut args = vec!["send-keys", "-t", &self.name];
        args.extend_from_slice(tail);
        let status = tmux_for(&self.name).args(&args).status()?;
        assert!(status.success(), "tmux send-keys failed");
        Ok(())
    }

    /// True once the session has ended (the process exited).
    pub(crate) fn ended(&self) -> bool {
        !tmux_for(&self.name)
            .args(["has-session", "-t", &self.name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Poll until the session process has exited; an error if it is still alive after 5 s.
    pub(crate) fn wait_until_ended(&self) -> Result<(), TestError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.ended() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!("session {} did not exit", self.name).into())
    }
}

impl Drop for TuiSession {
    /// Best-effort `tmux kill-server` on the session's own server, so a
    /// failed test never leaks a running sipnab process or a server, then
    /// removal of that server's socket and of the session's own
    /// XDG_CONFIG_HOME, so a run leaves nothing in the temp directories.
    fn drop(&mut self) {
        if !self.close() {
            eprintln!(
                "sipnab (pid {}) of session {} was still running {} s after its tmux \
                 server ended; killed",
                self.sipnab.pid,
                self.name,
                SIPNAB_END_TIMEOUT.as_secs()
            );
        }
    }
}
/// Absolute path to `tests/fixtures` (bundled demo pcaps such as
/// `sip_call.pcap` and `udp_5060.pcap`).
pub(crate) fn fixtures_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")
}

/// Minimal single-quote shell quoting for paths/args.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
