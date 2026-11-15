// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The commands that end before the capture launch, started as root
//! (COMMANDS-KEEP-ROOT): `sipnab fleet serve`, `sipnab fleet inventory`,
//! `--vcon-forward` and `--vcon-fetch` read their key files as root and then
//! run as another user.
//!
//! Each test starts the real binary under `sudo` (through
//! `tests/support/root_run.rs`) and reads what the kernel says: the uids of
//! the running process from `/proc/<pid>/status`, and the owner of what the
//! run created. A network client is observed while a store in this test
//! holds its request unanswered, so the process is there to be read. Where
//! `sudo -n` does not work the test says so on the real stderr and returns.

#![cfg(all(target_os = "linux", feature = "vcon", feature = "api"))]

#[path = "support/root_run.rs"]
mod root_run;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use std::io::{BufRead as _, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

type TestError = Box<dyn std::error::Error>;

/// How long one run may live, from its start: every wait of a test shares
/// it. A bound on waiting, not a measurement: nothing here passes or fails
/// by how fast it ran. It is below the shortest cap a runner on the
/// development hosts puts on a test binary (600 s), so a test ends its own
/// run before a runner can end the test and leave the run behind.
const TEST_DEADLINE: Duration = Duration::from_secs(120);

/// Whether a `tail` that follows `file` is running: the stand-in command of
/// the two tests of the deadline, found by an argument no other process
/// carries.
fn a_tail_follows(file: &Path) -> Result<bool, TestError> {
    let wanted = text(file)?;
    for entry in std::fs::read_dir("/proc")? {
        let Ok(cmdline) = std::fs::read(entry?.path().join("cmdline")) else {
            continue;
        };
        let mut args = cmdline.split(|b| *b == 0);
        if args.next() == Some(b"tail".as_slice()) && args.any(|a| a == wanted.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A command that never ends by itself, tied to this test as a `sudo` run
/// is, and needing no `sudo`.
fn endless(file: &Path, within: Duration) -> Result<Run, TestError> {
    std::fs::write(file, b"")?;
    let mut command = root_run::tied()?;
    command.args(["tail", "-f"]).arg(file);
    let run = Run::spawn(command, file, within)?;
    // The command is started by the `sh` above it; wait until it is there.
    let seen_by = Instant::now() + Duration::from_secs(30);
    while !a_tail_follows(file)? {
        if Instant::now() > seen_by {
            return Err("the stand-in command did not start".into());
        }
        std::thread::yield_now();
    }
    Ok(run)
}

/// A run still there at its deadline is ended, and the test is told: it
/// does not wait on.
#[test]
fn a_run_past_its_deadline_is_ended_and_reported() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-early-exit-deadline-")?;
    let file = dir.path().join("followed");
    let run = endless(&file, Duration::from_secs(2))?;
    let err = match run.finish() {
        Ok(ended) => return Err(format!("an endless command ended by itself: {ended:?}").into()),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("did not end by its deadline"),
        "the test is told why it failed: {err}"
    );
    assert!(
        !a_tail_follows(&file)?,
        "the command is gone when `finish` returns"
    );
    Ok(())
}

/// A test that returns while its run is still there, as after a failed
/// assertion, ends the run on the way out.
#[test]
fn a_run_is_ended_when_its_test_leaves_it() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-early-exit-left-")?;
    let file = dir.path().join("followed");
    let run = endless(&file, TEST_DEADLINE)?;
    drop(run);
    assert!(
        !a_tail_follows(&file)?,
        "the command is gone when the run is dropped"
    );
    Ok(())
}

/// A wait for a line shares the run's deadline and reports what was logged.
#[test]
fn a_wait_for_a_line_ends_at_the_deadline() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-early-exit-line-")?;
    let file = dir.path().join("followed");
    let mut run = endless(&file, Duration::from_secs(2))?;
    let err = run.line_with("a line that never comes").err();
    assert!(
        err.is_some_and(|e| e.to_string().contains("no line with")),
        "a line that does not come is an error at the deadline, not a wait"
    );
    drop(run);
    assert!(!a_tail_follows(&file)?, "and the run is ended");
    Ok(())
}

const BIN: &str = env!("CARGO_BIN_EXE_sipnab");

/// Whether `sudo -n` works; when not, say on the real stderr that `test`
/// did not run.
fn sudo_or_skip(test: &str) -> bool {
    let works = root_run::sudo()
        .and_then(|mut sudo| sudo.arg("true").status())
        .map(|s| s.success())
        .unwrap_or(false);
    if !works {
        // `writeln!` and not `eprintln!`: libtest drops a passing test's
        // captured output, and a skip nobody reads is a gate that cannot fail.
        let _ = writeln!(
            std::io::stderr(),
            "NOTICE: as-root gate `{test}` did NOT run: passwordless sudo is not available."
        );
    }
    works
}

/// Run `program args` as root and require success.
fn as_root(program: &str, args: &[&str]) -> Result<(), TestError> {
    let status = root_run::sudo()?.arg(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("sudo {program} {args:?}: {status}").into())
    }
}

/// Removes a directory as root when it drops: a root run leaves files this
/// runner could not remove.
struct RootRemoves(PathBuf);

impl Drop for RootRemoves {
    fn drop(&mut self) {
        if let Ok(mut rm) = root_run::sudo() {
            let _ = rm.args(["rm", "-rf", "--"]).arg(&self.0).status();
        }
    }
}

/// A scratch directory every user can enter, removed as root at the end.
struct Scratch {
    dir: test_scratch::ScratchDir,
    _remove: RootRemoves,
}

impl Scratch {
    fn new(tag: &str) -> Result<Self, TestError> {
        let dir = test_scratch::ScratchDir::new(&format!("sipnab-early-exit-{tag}-"))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let remove = RootRemoves(dir.path().to_path_buf());
        Ok(Self {
            dir,
            _remove: remove,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// A directory `owner` owns, mode 0755.
    fn dir_of(&self, name: &str, owner: &str) -> Result<PathBuf, TestError> {
        let path = self.path(name);
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        as_root("chown", &[owner, text(&path)?])?;
        Ok(path)
    }

    /// A file holding `content` that only root can read: root's, mode 0600.
    fn root_only(&self, name: &str, content: &str) -> Result<PathBuf, TestError> {
        let path = self.path(name);
        std::fs::write(&path, content)?;
        make_root_only(&path)?;
        Ok(path)
    }
}

fn make_root_only(path: &Path) -> Result<(), TestError> {
    as_root("chown", &["root:root", text(path)?])?;
    as_root("chmod", &["600", text(path)?])
}

fn text(path: &Path) -> Result<&str, TestError> {
    path.to_str().ok_or_else(|| "path is not UTF-8".into())
}

/// The uid of the account `name`.
fn uid_of(name: &str) -> Result<u32, TestError> {
    let out = Command::new("id").args(["-u", name]).output()?;
    Ok(String::from_utf8(out.stdout)?.trim().parse()?)
}

/// The name of the account running this test.
fn me() -> Result<String, TestError> {
    let out = Command::new("id").arg("-un").output()?;
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// Every name under `dir`, sorted: what a refused start must leave as it
/// was.
fn names_under(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(next) = dirs.pop() {
        for entry in std::fs::read_dir(&next)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// A sipnab started under `sudo`, its stderr read line by line.
///
/// Three rules keep a run from outliving its test (2026-11-14: a test that
/// waited without a bound was left by its runner with four centers serving
/// as root):
///
/// - `tests/support/root_run.rs` ends the command when the test PROCESS
///   ends, by any cause (`tests/child_lifetime_test.rs` holds that).
/// - Every wait on the run shares one deadline, [`TEST_DEADLINE`] from its
///   start, shorter than any cap a runner puts on the test binary. A run
///   still there at the deadline is ended and the test fails.
/// - The run is a process group of its own. A test that ends first, by the
///   deadline, a failed assertion or an error, signals the group and waits
///   for the run before it returns (`Drop`).
struct Run {
    child: Child,
    reaped: bool,
    deadline: Instant,
    lines: Receiver<String>,
    seen: Vec<String>,
    marker: String,
}

impl Drop for Run {
    fn drop(&mut self) {
        if !self.reaped {
            self.end();
        }
    }
}

impl Run {
    /// Start `sipnab args` as root. `marker` is an argument no other
    /// process on this host carries, to find the process by.
    fn start(args: &[&str], marker: &Path) -> Result<Self, TestError> {
        let mut command = root_run::sudo()?;
        command.arg(BIN).args(args);
        Self::spawn(command, marker, TEST_DEADLINE)
    }

    /// Start `command` in a process group of its own, to be gone `within`
    /// that time.
    fn spawn(mut command: Command, marker: &Path, within: Duration) -> Result<Self, TestError> {
        use std::os::unix::process::CommandExt as _;
        let mut child = command
            .process_group(0)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        Ok(Self {
            child,
            reaped: false,
            deadline: Instant::now() + within,
            lines,
            seen: Vec::new(),
            marker: text(marker)?.to_string(),
        })
    }

    /// The time this run has left.
    fn left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Signal the run's process group with SIGTERM and wait for the run.
    /// `sudo` and the `sh` under it pass the signal on to a command this
    /// user may not signal itself, and that `sh` sends SIGKILL after its
    /// grace time when the test process is gone.
    fn end(&mut self) {
        if let Ok(pgid) = libc::pid_t::try_from(self.child.id()) {
            // SAFETY: the child was started as the leader of its own group
            // and has not been waited for, so the group id names its group
            // and no other.
            unsafe { libc::kill(-pgid, libc::SIGTERM) };
        }
        let _ = self.child.wait();
        self.reaped = true;
    }

    /// Wait for a stderr line holding `part`.
    fn line_with(&mut self, part: &str) -> Result<String, TestError> {
        loop {
            let left = self.left();
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(part) {
                        return Ok(line);
                    }
                }
                Err(_) => {
                    return Err(format!("no line with {part:?}; stderr:\n{}", self.log()).into());
                }
            }
        }
    }

    fn log(&self) -> String {
        self.seen.join("\n")
    }

    /// The real, effective, saved and filesystem uids of the sipnab process,
    /// from the kernel.
    fn uids(&self) -> Result<Vec<u32>, TestError> {
        for entry in std::fs::read_dir("/proc")? {
            let dir = entry?.path();
            let Ok(cmdline) = std::fs::read(dir.join("cmdline")) else {
                continue;
            };
            let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
            let is_it = args.first().is_some_and(|a| *a == BIN.as_bytes())
                && args
                    .iter()
                    .any(|a| String::from_utf8_lossy(a).contains(self.marker.as_str()));
            if !is_it {
                continue;
            }
            let status = std::fs::read_to_string(dir.join("status"))?;
            let line = status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .ok_or("no Uid line")?;
            return Ok(line
                .split_whitespace()
                .skip(1)
                .map(str::parse)
                .collect::<Result<_, _>>()?);
        }
        Err(format!("no sipnab process carries {}", self.marker).into())
    }

    /// Ask the run to stop (SIGTERM, which `sudo` and the `sh` above the
    /// command relay), and collect its exit code and the rest of its stderr.
    fn stop(mut self) -> Result<(Option<i32>, String), TestError> {
        let pgid = libc::pid_t::try_from(self.child.id())?;
        // SAFETY: as in `end`: the group of a child not yet waited for.
        unsafe { libc::kill(-pgid, libc::SIGTERM) };
        self.finish_mut()
    }

    /// Wait for the run to end by itself: its stderr closes when it does.
    /// A run that is still there at its deadline is ended and reported, so
    /// a command that serves where it should have refused fails its test in
    /// place of holding it.
    fn finish(mut self) -> Result<(Option<i32>, String), TestError> {
        self.finish_mut()
    }

    fn finish_mut(&mut self) -> Result<(Option<i32>, String), TestError> {
        use std::sync::mpsc::RecvTimeoutError;
        loop {
            let left = self.left();
            match self.lines.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    self.end();
                    return Err(format!(
                        "the run did not end by its deadline and was ended; stderr:\n{}",
                        self.log()
                    )
                    .into());
                }
            }
        }
        let status = self.child.wait()?;
        self.reaped = true;
        Ok((status.code(), self.log()))
    }
}

/// A store, or an instance, on loopback that takes one request and holds
/// it unanswered until the test lets go.
struct Held {
    addr: std::net::SocketAddr,
    request: Receiver<String>,
    release: Sender<&'static str>,
}

impl Held {
    fn listen() -> Result<Self, TestError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (seen, request) = channel();
        let (release, let_go) = channel::<&'static str>();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let Ok(text) = read_request(&mut sock) else {
                return;
            };
            let _ = seen.send(text);
            if let Ok(answer) = let_go.recv() {
                let _ = sock.write_all(answer.as_bytes());
            }
        });
        Ok(Self {
            addr,
            request,
            release,
        })
    }

    /// The request, once it arrived whole.
    fn request(&self, run: &Run) -> Result<String, TestError> {
        self.request
            .recv_timeout(run.left())
            .map_err(|_| format!("no request before the deadline; stderr:\n{}", run.log()).into())
    }
}

/// One HTTP request: the head, and the body `Content-Length` announces.
fn read_request(sock: &mut std::net::TcpStream) -> std::io::Result<String> {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        sock.read_exact(&mut byte)?;
        got.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&got).to_string();
    let length = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    sock.read_exact(&mut body)?;
    Ok(head + &String::from_utf8_lossy(&body))
}

const NO_CONTENT: &str =
    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

const UUID: &str = "0190a0b0-0000-7000-8000-000000000001";

fn container() -> String {
    format!(
        r#"{{"vcon":"0.4.0","uuid":"{UUID}","created_at":"2026-10-07T12:00:00+00:00","parties":[{{"tel":"+15550100001"}},{{"tel":"+15550100002"}}],"dialog":[{{"type":"recording","parties":[0,1],"start":"2026-10-07T12:00:00+00:00","mediatype":"audio/x-wav","encoding":"base64url","body":"UklGRg"}}],"attachments":[],"analysis":[]}}"#
    )
}

/// The key files of a center, each readable by root only, and the
/// arguments that name them with `store`.
fn center_args(scratch: &Scratch, store: &Path) -> Result<Vec<String>, TestError> {
    let store_key = scratch.path("store.key");
    let made = Command::new(BIN)
        .args(["fleet", "keygen", "--out", text(&store_key)?])
        .output()?;
    if !made.status.success() {
        return Err(format!("keygen: {}", String::from_utf8_lossy(&made.stderr)).into());
    }
    make_root_only(&store_key)?;
    let signing = scratch.root_only("signing.key", "early-exit-center-key-0123456789abcdef\n")?;
    Ok([
        "fleet",
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--store",
        text(store)?,
        "--store-key-file",
        text(&store_key)?,
        "--signing-key-file",
        text(&signing)?,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect())
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// A center started as root reads its two key files, which only root can
/// read, binds, and serves as `nobody`; the store it creates is `nobody`'s.
#[test]
fn a_center_started_as_root_serves_as_nobody() -> Result<(), TestError> {
    if !sudo_or_skip("a_center_started_as_root_serves_as_nobody") {
        return Ok(());
    }
    let scratch = Scratch::new("center")?;
    let data = scratch.dir_of("data", "nobody")?;
    let store = data.join("center.store");
    let args = center_args(&scratch, &store)?;
    let mut run = Run::start(&strs(&args), &store)?;
    run.line_with("fleet center serving")?;
    let nobody = uid_of("nobody")?;
    assert_eq!(
        run.uids()?,
        [nobody; 4],
        "every uid of the serving center is nobody's; stderr:\n{}",
        run.log()
    );
    assert_eq!(
        std::fs::metadata(&store)?.uid(),
        nobody,
        "the store was created after the drop, by nobody"
    );
    let (code, log) = run.stop()?;
    assert_eq!(code, Some(0), "a stopped center exits 0:\n{log}");
    Ok(())
}

/// `--user` names the account the center serves as.
#[test]
fn a_center_started_as_root_with_user_serves_as_that_user() -> Result<(), TestError> {
    if !sudo_or_skip("a_center_started_as_root_with_user_serves_as_that_user") {
        return Ok(());
    }
    let scratch = Scratch::new("center-user")?;
    let me = me()?;
    let data = scratch.dir_of("data", &me)?;
    let store = data.join("center.store");
    let mut args = center_args(&scratch, &store)?;
    args.extend(["--user".to_string(), me.clone()]);
    let mut run = Run::start(&strs(&args), &store)?;
    run.line_with("fleet center serving")?;
    let mine = uid_of(&me)?;
    assert_eq!(
        run.uids()?,
        [mine; 4],
        "every uid is the named user's; stderr:\n{}",
        run.log()
    );
    assert_eq!(
        std::fs::metadata(&store)?.uid(),
        mine,
        "the store is the named user's"
    );
    run.stop()?;
    Ok(())
}

/// `--no-priv-drop` keeps root, as before this rule, and says so once.
#[test]
fn a_center_with_no_priv_drop_stays_root_and_says_so() -> Result<(), TestError> {
    if !sudo_or_skip("a_center_with_no_priv_drop_stays_root_and_says_so") {
        return Ok(());
    }
    let scratch = Scratch::new("center-keep")?;
    let data = scratch.dir_of("data", "root")?;
    let store = data.join("center.store");
    let mut args = center_args(&scratch, &store)?;
    args.push("--no-priv-drop".to_string());
    let mut run = Run::start(&strs(&args), &store)?;
    run.line_with("fleet center serving")?;
    assert_eq!(run.uids()?, [0; 4], "root is kept; stderr:\n{}", run.log());
    let (_, log) = run.stop()?;
    let warnings = log
        .lines()
        .filter(|l| l.contains("running as root because --no-priv-drop"))
        .count();
    assert_eq!(warnings, 1, "one warning line says root was kept:\n{log}");
    Ok(())
}

/// A store directory `nobody` cannot write refuses the start: exit 2, the
/// three ways out, the caller offered by name because the directory is the
/// caller's, and nothing created.
#[test]
fn a_center_whose_store_nobody_cannot_write_refuses_and_creates_nothing() -> Result<(), TestError> {
    if !sudo_or_skip("a_center_whose_store_nobody_cannot_write_refuses_and_creates_nothing") {
        return Ok(());
    }
    let scratch = Scratch::new("center-refused")?;
    let me = me()?;
    let data = scratch.dir_of("data", &me)?;
    let store = data.join("center.store");
    let args = center_args(&scratch, &store)?;
    let before = names_under(scratch.dir.path())?;
    let (code, log) = Run::start(&strs(&args), &store)?.finish()?;
    assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
    for part in [
        "runs as user 'nobody'",
        "cannot write in",
        "the directory of --store",
        "Nothing was created",
        "chown nobody",
        &format!("--user {me}"),
        "--no-priv-drop",
    ] {
        assert!(log.contains(part), "the refusal lacks {part:?}:\n{log}");
    }
    assert_eq!(
        names_under(scratch.dir.path())?,
        before,
        "a refused start leaves no file or directory behind"
    );
    Ok(())
}

/// A store file a root-run center left, in a directory `nobody` can write,
/// refuses the start too: the file is named, and it is left as it was.
#[test]
fn a_center_whose_store_file_is_roots_refuses() -> Result<(), TestError> {
    if !sudo_or_skip("a_center_whose_store_file_is_roots_refuses") {
        return Ok(());
    }
    let scratch = Scratch::new("center-old-store")?;
    let data = scratch.dir_of("data", "nobody")?;
    let store = data.join("center.store");
    as_root("touch", &[text(&store)?])?;
    as_root("chmod", &["600", text(&store)?])?;
    let args = center_args(&scratch, &store)?;
    let before = names_under(scratch.dir.path())?;
    let (code, log) = Run::start(&strs(&args), &store)?.finish()?;
    assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
    assert!(
        log.contains("cannot read and write") && log.contains("(--store)"),
        "the refusal names the store file:\n{log}"
    );
    assert!(
        log.contains("--user USER"),
        "nobody but root can use the file, so no user is offered by name:\n{log}"
    );
    assert_eq!(
        names_under(scratch.dir.path())?,
        before,
        "nothing was created"
    );
    assert_eq!(
        std::fs::metadata(&store)?.uid(),
        0,
        "the old store is still root's"
    );
    Ok(())
}

/// The spool of a forwarder: `owner`'s, holding one container.
fn spool(scratch: &Scratch, owner: &str) -> Result<PathBuf, TestError> {
    let spool = scratch.path("spool");
    std::fs::create_dir(&spool)?;
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755))?;
    let file = spool.join(format!("{UUID}.vcon.json"));
    std::fs::write(&file, container())?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))?;
    as_root("chown", &["-R", owner, text(&spool)?])?;
    Ok(spool)
}

fn forward_args(
    spool: &Path,
    auth: &Path,
    addr: std::net::SocketAddr,
) -> Result<Vec<String>, TestError> {
    Ok([
        "--no-config",
        "--vcon-forward",
        text(spool)?,
        "--vcon-forward-url",
        &format!("http://{addr}/vcon"),
        "--vcon-forward-auth-file",
        text(auth)?,
        "--vcon-forward-once",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect())
}

/// A forwarder started as root reads its auth file, which only root can
/// read, and delivers as `nobody`: the request carries the credential, the
/// process holding the connection is `nobody`, and the directory it makes
/// for delivered containers is `nobody`'s.
#[test]
fn a_forwarder_started_as_root_delivers_as_nobody() -> Result<(), TestError> {
    if !sudo_or_skip("a_forwarder_started_as_root_delivers_as_nobody") {
        return Ok(());
    }
    let scratch = Scratch::new("forward")?;
    let spool = spool(&scratch, "nobody")?;
    let auth = scratch.root_only("auth", "x-conserver-api-token: early-exit-secret\n")?;
    let store = Held::listen()?;
    let run = Run::start(&strs(&forward_args(&spool, &auth, store.addr)?), &spool)?;
    let request = store.request(&run)?;
    assert!(
        request.contains("early-exit-secret"),
        "the credential only root can read was read before the drop and sent"
    );
    let nobody = uid_of("nobody")?;
    assert_eq!(
        run.uids()?,
        [nobody; 4],
        "the process that holds the connection is nobody"
    );
    store.release.send(NO_CONTENT)?;
    let (code, log) = run.finish()?;
    assert_eq!(code, Some(0), "the container was delivered:\n{log}");
    // Not `names_under`: the directories are 0700 and nobody's, so this
    // runner can name them and read their owner, and cannot list them.
    let mut made = Vec::new();
    for entry in std::fs::read_dir(&spool)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            made.push(entry.path());
        }
    }
    assert!(!made.is_empty(), "the forwarder made its directories");
    for dir in made {
        assert_eq!(
            std::fs::metadata(&dir)?.uid(),
            nobody,
            "{} was created after the drop",
            dir.display()
        );
    }
    Ok(())
}

/// A spool `nobody` cannot write refuses the start before a directory is
/// made or a connection opened.
#[test]
fn a_forwarder_whose_spool_nobody_cannot_write_refuses() -> Result<(), TestError> {
    if !sudo_or_skip("a_forwarder_whose_spool_nobody_cannot_write_refuses") {
        return Ok(());
    }
    let scratch = Scratch::new("forward-refused")?;
    let me = me()?;
    let spool = spool(&scratch, &me)?;
    let auth = scratch.root_only("auth", "x-conserver-api-token: early-exit-secret\n")?;
    let store = Held::listen()?;
    let before = names_under(scratch.dir.path())?;
    let (code, log) =
        Run::start(&strs(&forward_args(&spool, &auth, store.addr)?), &spool)?.finish()?;
    assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
    for part in [
        "--vcon-forward: started as root",
        "cannot write in",
        &format!("--user {me}"),
        "--no-priv-drop",
    ] {
        assert!(log.contains(part), "the refusal lacks {part:?}:\n{log}");
    }
    assert_eq!(
        names_under(scratch.dir.path())?,
        before,
        "nothing was created"
    );
    assert!(
        store.request.try_recv().is_err(),
        "nothing was sent to the store"
    );
    Ok(())
}

fn fetch_args(
    out: &Path,
    auth: &Path,
    addr: std::net::SocketAddr,
) -> Result<Vec<String>, TestError> {
    Ok([
        "--no-config",
        "--vcon-fetch-kind",
        "conserver",
        "--vcon-fetch-url",
        &format!("http://{addr}/vcon/{{uuid}}"),
        "--vcon-fetch-auth-file",
        text(auth)?,
        "--vcon-fetch-out",
        text(out)?,
        "--vcon-fetch",
        UUID,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect())
}

/// A fetcher started as root reads its auth file, which only root can read,
/// and fetches as `nobody`: the output directory and the file in it are
/// created after the drop.
#[test]
fn a_fetcher_started_as_root_writes_as_nobody() -> Result<(), TestError> {
    if !sudo_or_skip("a_fetcher_started_as_root_writes_as_nobody") {
        return Ok(());
    }
    let scratch = Scratch::new("fetch")?;
    let parent = scratch.dir_of("parent", "nobody")?;
    let out = parent.join("out");
    let auth = scratch.root_only("auth", "x-conserver-api-token: early-exit-secret\n")?;
    let store = Held::listen()?;
    let run = Run::start(&strs(&fetch_args(&out, &auth, store.addr)?), &out)?;
    let request = store.request(&run)?;
    assert!(
        request.contains("early-exit-secret"),
        "the credential only root can read was read before the drop and sent"
    );
    let nobody = uid_of("nobody")?;
    assert_eq!(
        run.uids()?,
        [nobody; 4],
        "the process that holds the connection is nobody"
    );
    assert_eq!(
        std::fs::metadata(&out)?.uid(),
        nobody,
        "the output directory was created after the drop"
    );
    let body = container();
    let answer: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    );
    store.release.send(answer)?;
    let (code, log) = run.finish()?;
    assert_eq!(code, Some(0), "the container was fetched:\n{log}");
    // The directory is 0700 and nobody's, so root reads the owner for us.
    let listed = root_run::sudo()?
        .args(["stat", "-c", "%u", "--"])
        .arg(out.join(format!("{UUID}.vcon.json")))
        .output()?;
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        nobody.to_string(),
        "the fetched file is nobody's: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    Ok(())
}

/// An output directory that would be made where `nobody` cannot write
/// refuses the start, offers the caller by name, and makes nothing.
#[test]
fn a_fetcher_whose_output_nobody_cannot_make_refuses() -> Result<(), TestError> {
    if !sudo_or_skip("a_fetcher_whose_output_nobody_cannot_make_refuses") {
        return Ok(());
    }
    let scratch = Scratch::new("fetch-refused")?;
    let me = me()?;
    let parent = scratch.dir_of("parent", &me)?;
    let out = parent.join("out");
    let auth = scratch.root_only("auth", "x-conserver-api-token: early-exit-secret\n")?;
    let store = Held::listen()?;
    let before = names_under(scratch.dir.path())?;
    let (code, log) = Run::start(&strs(&fetch_args(&out, &auth, store.addr)?), &out)?.finish()?;
    assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
    for part in [
        "--vcon-fetch: started as root",
        "(--vcon-fetch-out)",
        &format!("--user {me}"),
        "--no-priv-drop",
    ] {
        assert!(log.contains(part), "the refusal lacks {part:?}:\n{log}");
    }
    assert_eq!(
        names_under(scratch.dir.path())?,
        before,
        "nothing was created"
    );
    assert!(
        store.request.try_recv().is_err(),
        "nothing was asked of the store"
    );
    Ok(())
}

/// `sipnab fleet inventory` started as root reads its token file, which
/// only root can read, and asks the instance as `nobody`.
#[test]
fn an_inventory_started_as_root_asks_as_nobody() -> Result<(), TestError> {
    if !sudo_or_skip("an_inventory_started_as_root_asks_as_nobody") {
        return Ok(());
    }
    let scratch = Scratch::new("inventory")?;
    let token = scratch.root_only("token", "early-exit-token\n")?;
    let instance = Held::listen()?;
    let hosts = scratch.path("hosts.toml");
    std::fs::write(
        &hosts,
        format!(
            "[[host]]\nname = \"edge-a\"\nurl = \"http://{}\"\ntoken_file = {:?}\n",
            instance.addr,
            text(&token)?
        ),
    )?;
    make_root_only(&hosts)?;
    let run = Run::start(&["fleet", "inventory", "--hosts", text(&hosts)?], &hosts)?;
    let request = instance.request(&run)?;
    assert!(
        request.contains("Bearer early-exit-token"),
        "the token only root can read was read before the drop and sent"
    );
    assert_eq!(
        run.uids()?,
        [uid_of("nobody")?; 4],
        "the process that asks the instance is nobody"
    );
    instance.release.send(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\
         Connection: close\r\n\r\n{}",
    )?;
    run.finish()?;
    Ok(())
}

/// The commands that parse a file the caller named, started as root
/// (COMMANDS-PARSE-AS-ROOT): `--show-frame`, `--write-annotated`,
/// `--strip-secrets`, `--find-in-files`, `--compare-captures`,
/// `--vcon-validate` and `--vcon-resign` open and read their inputs as
/// root, drop, and only then judge and parse them.
///
/// Two facts are read from the kernel for the five that read captures. A
/// gzip capture is inflated into the temporary directory when it is judged:
/// with `TMPDIR` a directory only root can write the run must fail, and
/// with one only `nobody` can write it must succeed, so the step that
/// inflates and parses ran as `nobody` and not as root. And the input is a
/// file only root can read, so it was opened before the drop.
#[cfg(feature = "native")]
mod file_commands {
    use super::*;

    /// The Call-ID of the one call in `sip-rtp-g711.pcap`.
    const CALL: &str = "1-1966@10.0.2.20";

    fn sample(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples")
            .join(name)
    }

    fn gzip(data: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data)?;
        Ok(enc.finish()?)
    }

    /// The sample `name` copied to `scratch` as `to`, readable by root only,
    /// compressed when `to` ends in `.gz`.
    fn root_only_sample(scratch: &Scratch, name: &str, to: &str) -> Result<PathBuf, TestError> {
        let mut bytes = std::fs::read(sample(name))?;
        if to.ends_with(".gz") {
            bytes = gzip(&bytes)?;
        }
        let path = scratch.path(to);
        std::fs::write(&path, bytes)?;
        make_root_only(&path)?;
        Ok(path)
    }

    /// A directory only `owner` can enter or write.
    fn private_dir(scratch: &Scratch, name: &str, owner: &str) -> Result<PathBuf, TestError> {
        let path = scratch.dir_of(name, owner)?;
        as_root("chmod", &["700", text(&path)?])?;
        Ok(path)
    }

    /// Run sipnab as root with `TMPDIR` set to `tmp`, to its end.
    fn run_in(tmp: &Path, args: &[&str]) -> Result<(Option<i32>, String), TestError> {
        let mut command = root_run::sudo()?;
        command
            .arg("env")
            .arg(format!("TMPDIR={}", text(tmp)?))
            .arg(BIN)
            .args(args);
        Run::spawn(command, tmp, TEST_DEADLINE)?.finish()
    }

    /// Run sipnab as root to its end.
    fn run(args: &[&str]) -> Result<(Option<i32>, String), TestError> {
        Run::start(args, Path::new(BIN))?.finish()
    }

    /// The pointer to frame 0 of `capture`, with the digest of that frame
    /// as the sample `name` holds it.
    fn first_frame(name: &str, capture: &Path) -> Result<String, TestError> {
        use sipnab::capture::resolve::{parse_pointer, resolve};
        let source = sample(name);
        let pointer = parse_pointer(&format!("{}#0", text(&source)?))
            .map_err(|e| format!("pointer: {e:?}"))?;
        let frame = resolve(&pointer).map_err(|e| format!("frame 0: {e:?}"))?;
        let digest = sipnab::capture::packet::frame_digest(frame.bytes());
        Ok(format!("{}#0@{digest:016x}", text(capture)?))
    }

    /// A notes file holding one note on frame 0 of `capture`.
    fn notes_on(scratch: &Scratch, name: &str, capture: &Path) -> Result<PathBuf, TestError> {
        let line = serde_json::json!({"frame": first_frame(name, capture)?, "note": "seen"});
        scratch.root_only("notes.jsonl", &format!("{line}\n"))
    }

    /// The arguments of each capture command over `input` (and `other`, for
    /// the comparison), writing into `out_dir` when it writes.
    fn capture_command(
        scratch: &Scratch,
        flag: &str,
        sample_name: &str,
        input: &Path,
        other: &Path,
        out_dir: &Path,
    ) -> Result<Vec<String>, TestError> {
        let input_text = text(input)?.to_string();
        let out = text(&out_dir.join("out.pcapng"))?.to_string();
        Ok(match flag {
            "--show-frame" => vec![flag.into(), format!("{input_text}#0")],
            "--strip-secrets" => vec![flag.into(), out, "-I".into(), input_text],
            "--write-annotated" => vec![
                "-N".into(),
                "--notes".into(),
                text(&notes_on(scratch, sample_name, input)?)?.to_string(),
                flag.into(),
                out,
                "-I".into(),
                input_text,
            ],
            "--find-in-files" => vec![
                flag.into(),
                input_text,
                "--filter".into(),
                format!("call_id == \"{CALL}\""),
            ],
            "--compare-captures" => vec![flag.into(), input_text, text(other)?.to_string()],
            other => return Err(format!("no capture command {other}").into()),
        })
    }

    /// The sample each capture command reads in these tests.
    fn sample_for(flag: &str) -> &'static str {
        if flag == "--strip-secrets" {
            "b2bua-asterisk.pcapng"
        } else {
            "sip-rtp-g711.pcap"
        }
    }

    /// `flag` over a gzip capture only root can read: refused where only
    /// root can write the temporary directory, done where only `nobody`
    /// can. The step that inflates and judges the capture ran as `nobody`.
    fn judged_as_nobody(test: &str, flag: &str) -> Result<(), TestError> {
        if !sudo_or_skip(test) {
            return Ok(());
        }
        let scratch = Scratch::new("judge")?;
        let name = sample_for(flag);
        let to = format!("in-{name}.gz");
        let input = root_only_sample(&scratch, name, &to)?;
        let other = root_only_sample(&scratch, "sip-problem-call.pcap", "other.pcap.gz")?;
        let out_dir = scratch.dir_of("out", "nobody")?;
        let roots_tmp = private_dir(&scratch, "tmp-root", "root")?;
        let nobodys_tmp = private_dir(&scratch, "tmp-nobody", "nobody")?;
        let args = capture_command(&scratch, flag, name, &input, &other, &out_dir)?;

        let (code, log) = run_in(&roots_tmp, &strs(&args))?;
        assert_ne!(
            code,
            Some(0),
            "{flag} inflated its input where only root can write, so it judged it as root:\n{log}"
        );
        let (code, log) = run_in(&nobodys_tmp, &strs(&args))?;
        assert_eq!(
            code,
            Some(0),
            "{flag} could not inflate its input where only nobody can write:\n{log}"
        );
        Ok(())
    }

    /// `flag` over a capture only root can read, mode 0600: it is read.
    fn root_only_input_reads(test: &str, flag: &str) -> Result<Option<PathBuf>, TestError> {
        if !sudo_or_skip(test) {
            return Ok(None);
        }
        let scratch = Scratch::new("reads")?;
        let name = sample_for(flag);
        let input = root_only_sample(&scratch, name, &format!("in-{name}"))?;
        let other = root_only_sample(&scratch, "sip-problem-call.pcap", "other.pcap")?;
        assert_eq!(
            std::fs::metadata(&input)?.mode() & 0o777,
            0o600,
            "the input is private to root"
        );
        assert!(
            std::fs::read(&input).is_err(),
            "this test's own user cannot read the input"
        );
        let out_dir = scratch.dir_of("out", "nobody")?;
        let args = capture_command(&scratch, flag, name, &input, &other, &out_dir)?;
        let (code, log) = run(&strs(&args))?;
        assert_eq!(code, Some(0), "{flag} did not read root's capture:\n{log}");
        let out = out_dir.join("out.pcapng");
        if out.exists() {
            assert_eq!(
                std::fs::metadata(&out)?.uid(),
                uid_of("nobody")?,
                "{flag} wrote its output after the drop"
            );
            // Kept past the scratch directory only as a fact: the caller
            // asserts that a writing command did write.
            return Ok(Some(out));
        }
        Ok(None)
    }

    #[test]
    fn show_frame_judges_its_input_as_nobody() -> Result<(), TestError> {
        judged_as_nobody("show_frame_judges_its_input_as_nobody", "--show-frame")
    }

    #[test]
    fn strip_secrets_judges_its_input_as_nobody() -> Result<(), TestError> {
        judged_as_nobody(
            "strip_secrets_judges_its_input_as_nobody",
            "--strip-secrets",
        )
    }

    #[test]
    fn write_annotated_judges_its_input_as_nobody() -> Result<(), TestError> {
        judged_as_nobody(
            "write_annotated_judges_its_input_as_nobody",
            "--write-annotated",
        )
    }

    #[test]
    fn find_in_files_judges_its_input_as_nobody() -> Result<(), TestError> {
        judged_as_nobody(
            "find_in_files_judges_its_input_as_nobody",
            "--find-in-files",
        )
    }

    #[test]
    fn compare_captures_judges_its_inputs_as_nobody() -> Result<(), TestError> {
        judged_as_nobody(
            "compare_captures_judges_its_inputs_as_nobody",
            "--compare-captures",
        )
    }

    #[test]
    fn show_frame_reads_a_capture_only_root_can_read() -> Result<(), TestError> {
        root_only_input_reads(
            "show_frame_reads_a_capture_only_root_can_read",
            "--show-frame",
        )
        .map(|_| ())
    }

    #[test]
    fn strip_secrets_reads_a_capture_only_root_can_read() -> Result<(), TestError> {
        let test = "strip_secrets_reads_a_capture_only_root_can_read";
        if !sudo_or_skip(test) {
            return Ok(());
        }
        let wrote = root_only_input_reads(test, "--strip-secrets")?;
        assert!(wrote.is_some(), "the sanitized copy was written");
        Ok(())
    }

    #[test]
    fn write_annotated_reads_a_capture_and_notes_only_root_can_read() -> Result<(), TestError> {
        let test = "write_annotated_reads_a_capture_and_notes_only_root_can_read";
        if !sudo_or_skip(test) {
            return Ok(());
        }
        let wrote = root_only_input_reads(test, "--write-annotated")?;
        assert!(wrote.is_some(), "the annotated copy was written");
        Ok(())
    }

    #[test]
    fn find_in_files_reads_a_capture_only_root_can_read() -> Result<(), TestError> {
        root_only_input_reads(
            "find_in_files_reads_a_capture_only_root_can_read",
            "--find-in-files",
        )
        .map(|_| ())
    }

    #[test]
    fn compare_captures_reads_two_captures_only_root_can_read() -> Result<(), TestError> {
        root_only_input_reads(
            "compare_captures_reads_two_captures_only_root_can_read",
            "--compare-captures",
        )
        .map(|_| ())
    }

    /// A directory only root can list: its files are named and opened
    /// before the drop, and read after it.
    #[test]
    fn find_in_files_sweeps_a_directory_only_root_can_list() -> Result<(), TestError> {
        if !sudo_or_skip("find_in_files_sweeps_a_directory_only_root_can_list") {
            return Ok(());
        }
        let scratch = Scratch::new("sweep-dir")?;
        let dir = scratch.path("captures");
        std::fs::create_dir(&dir)?;
        std::fs::copy(sample("sip-rtp-g711.pcap"), dir.join("a.pcap"))?;
        as_root("chown", &["-R", "root:root", text(&dir)?])?;
        as_root("chmod", &["700", text(&dir)?])?;
        let filter = format!("call_id == \"{CALL}\"");
        let (code, log) = run(&["--find-in-files", text(&dir)?, "--filter", &filter])?;
        assert_eq!(code, Some(0), "the sweep read root's directory:\n{log}");
        Ok(())
    }

    /// A pointer into an archive only root can read: the archive is opened
    /// before the drop and the member is written out after it.
    #[test]
    fn show_frame_follows_a_pointer_into_an_archive_only_root_can_read() -> Result<(), TestError> {
        if !sudo_or_skip("show_frame_follows_a_pointer_into_an_archive_only_root_can_read") {
            return Ok(());
        }
        let scratch = Scratch::new("member")?;
        let dir = scratch.path("set");
        std::fs::create_dir(&dir)?;
        std::fs::copy(sample("sip-rtp-g711.pcap"), dir.join("a.pcap"))?;
        let archive = scratch.path("set.tar");
        let made = Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&dir)
            .arg("a.pcap")
            .status()?;
        assert!(made.success(), "tar wrote the archive");
        make_root_only(&archive)?;
        let pointer = format!("{}/a.pcap#0", text(&archive)?);
        let (code, log) = run(&["--show-frame", &pointer])?;
        assert_eq!(code, Some(0), "the member's frame was found:\n{log}");
        Ok(())
    }

    /// An output directory `nobody` cannot write refuses the run before it
    /// creates anything, and offers the user `sudo` was called by.
    fn refused_for_its_output(test: &str, flag: &str) -> Result<(), TestError> {
        if !sudo_or_skip(test) {
            return Ok(());
        }
        let scratch = Scratch::new("refused")?;
        let me = me()?;
        let name = sample_for(flag);
        let input = root_only_sample(&scratch, name, &format!("in-{name}"))?;
        let out_dir = scratch.dir_of("out", &me)?;
        let args = capture_command(&scratch, flag, name, &input, &input, &out_dir)?;
        let before = names_under(scratch.dir.path())?;
        let (code, log) = run(&strs(&args))?;
        assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
        for part in [
            format!("{flag}: started as root"),
            format!("({flag})"),
            format!("--user {me}"),
            "--no-priv-drop".to_string(),
        ] {
            assert!(log.contains(&part), "the refusal lacks {part:?}:\n{log}");
        }
        assert_eq!(
            names_under(scratch.dir.path())?,
            before,
            "nothing was created"
        );
        Ok(())
    }

    #[test]
    fn strip_secrets_refuses_an_output_directory_nobody_cannot_write() -> Result<(), TestError> {
        refused_for_its_output(
            "strip_secrets_refuses_an_output_directory_nobody_cannot_write",
            "--strip-secrets",
        )
    }

    #[test]
    fn write_annotated_refuses_an_output_directory_nobody_cannot_write() -> Result<(), TestError> {
        refused_for_its_output(
            "write_annotated_refuses_an_output_directory_nobody_cannot_write",
            "--write-annotated",
        )
    }

    /// The output may not name the input: refused before the drop, while
    /// both paths still resolve, and the input is left as it was.
    #[test]
    fn strip_secrets_refuses_to_write_over_its_input() -> Result<(), TestError> {
        if !sudo_or_skip("strip_secrets_refuses_to_write_over_its_input") {
            return Ok(());
        }
        let scratch = Scratch::new("strip-over")?;
        let dir = scratch.dir_of("captures", "nobody")?;
        let input = dir.join("in.pcapng");
        let bytes = std::fs::read(sample("b2bua-asterisk.pcapng"))?;
        as_root(
            "cp",
            &[text(&sample("b2bua-asterisk.pcapng"))?, text(&input)?],
        )?;
        make_root_only(&input)?;
        let (code, log) = run(&["--strip-secrets", text(&input)?, "-I", text(&input)?])?;
        assert_eq!(
            code,
            Some(2),
            "an output that names its input is refused:\n{log}"
        );
        as_root("chmod", &["644", text(&input)?])?;
        assert!(
            std::fs::read(&input)? == bytes,
            "the input is byte for byte what it was"
        );
        Ok(())
    }

    /// `--user` names the user the run drops to: the output is that user's.
    #[test]
    fn strip_secrets_with_user_writes_as_that_user() -> Result<(), TestError> {
        if !sudo_or_skip("strip_secrets_with_user_writes_as_that_user") {
            return Ok(());
        }
        let scratch = Scratch::new("strip-user")?;
        let me = me()?;
        let input = root_only_sample(&scratch, "b2bua-asterisk.pcapng", "in.pcapng")?;
        let out = scratch.dir_of("out", &me)?.join("out.pcapng");
        let (code, log) = run(&[
            "--strip-secrets",
            text(&out)?,
            "-I",
            text(&input)?,
            "--user",
            &me,
        ])?;
        assert_eq!(code, Some(0), "the copy was written:\n{log}");
        assert_eq!(
            std::fs::metadata(&out)?.uid(),
            uid_of(&me)?,
            "the output belongs to the user --user names"
        );
        Ok(())
    }

    /// `--no-priv-drop` keeps root: the output is root's and one line says
    /// the run kept root.
    #[test]
    fn strip_secrets_with_no_priv_drop_stays_root_and_says_so() -> Result<(), TestError> {
        if !sudo_or_skip("strip_secrets_with_no_priv_drop_stays_root_and_says_so") {
            return Ok(());
        }
        let scratch = Scratch::new("strip-keep")?;
        let input = root_only_sample(&scratch, "b2bua-asterisk.pcapng", "in.pcapng")?;
        let out = scratch.dir_of("out", "root")?.join("out.pcapng");
        let (code, log) = run(&[
            "--strip-secrets",
            text(&out)?,
            "-I",
            text(&input)?,
            "--no-priv-drop",
        ])?;
        assert_eq!(code, Some(0), "the copy was written:\n{log}");
        assert_eq!(std::fs::metadata(&out)?.uid(), 0, "the output is root's");
        assert!(
            log.contains("--strip-secrets: running as root because --no-priv-drop was given"),
            "the run says it kept root:\n{log}"
        );
        Ok(())
    }

    /// A capture that does not exist fails as it does for any user, after
    /// the drop: nothing about the refusal changed.
    #[test]
    fn show_frame_of_a_missing_capture_fails_as_before() -> Result<(), TestError> {
        if !sudo_or_skip("show_frame_of_a_missing_capture_fails_as_before") {
            return Ok(());
        }
        let scratch = Scratch::new("missing")?;
        let pointer = format!("{}#0", text(&scratch.path("absent.pcap"))?);
        let (code, log) = run(&["--show-frame", &pointer])?;
        assert_eq!(
            code,
            Some(1),
            "a pointer that cannot be honored exits 1:\n{log}"
        );
        Ok(())
    }

    /// A drop user that does not exist ends the run before it parses.
    #[test]
    fn a_file_command_with_an_unknown_user_does_not_run() -> Result<(), TestError> {
        if !sudo_or_skip("a_file_command_with_an_unknown_user_does_not_run") {
            return Ok(());
        }
        let scratch = Scratch::new("no-user")?;
        let input = root_only_sample(&scratch, "sip-rtp-g711.pcap", "in.pcap")?;
        let pointer = format!("{}#0", text(&input)?);
        let (code, log) = run(&[
            "--show-frame",
            &pointer,
            "--user",
            "no-such-user-sipnab-test",
        ])?;
        assert_eq!(code, Some(2), "the run is refused:\n{log}");
        assert!(
            log.contains("--show-frame: failed to drop privileges"),
            "the refusal names the command and the cause:\n{log}"
        );
        Ok(())
    }

    // ---- the two that parse a vCon they read whole ----

    /// `--no-priv-drop` keeps root for a command that reads no capture too,
    /// and the line that says so is printed once.
    #[test]
    fn vcon_validate_with_no_priv_drop_says_once_that_it_kept_root() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_validate_with_no_priv_drop_says_once_that_it_kept_root") {
            return Ok(());
        }
        let scratch = Scratch::new("validate-keep")?;
        let input = scratch.root_only("in.vcon.json", &container())?;
        let (code, log) = run(&["--vcon-validate", text(&input)?, "--no-priv-drop"])?;
        assert_eq!(code, Some(0), "root's container is valid:\n{log}");
        assert_eq!(
            log.matches("--vcon-validate: running as root because --no-priv-drop was given")
                .count(),
            1,
            "one line says the run kept root:\n{log}"
        );
        assert!(
            !log.contains("Dropped privileges"),
            "a run that keeps root drops nowhere:\n{log}"
        );
        Ok(())
    }

    /// A valid container only root can read is validated: its bytes were
    /// read before the drop.
    #[test]
    fn vcon_validate_reads_a_container_only_root_can_read() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_validate_reads_a_container_only_root_can_read") {
            return Ok(());
        }
        let scratch = Scratch::new("validate")?;
        let input = scratch.root_only("in.vcon.json", &container())?;
        let (code, log) = run(&["--vcon-validate", text(&input)?])?;
        assert_eq!(
            code,
            Some(0),
            "root's container was read and is valid:\n{log}"
        );
        Ok(())
    }

    /// The validation runs after the drop: the run says which user it
    /// dropped to before it says what the container lacks.
    #[test]
    fn vcon_validate_drops_before_it_reports() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_validate_drops_before_it_reports") {
            return Ok(());
        }
        let scratch = Scratch::new("validate-order")?;
        let input = scratch.root_only("in.vcon.json", "this is not JSON")?;
        let (code, log) = run(&["--vcon-validate", text(&input)?, "-v"])?;
        assert_eq!(
            code,
            Some(1),
            "a document that cannot be checked fails:\n{log}"
        );
        let dropped = log.find("Dropped privileges to user 'nobody'");
        let reported = log.find("--vcon-validate ");
        assert!(
            dropped.is_some() && reported.is_some() && dropped < reported,
            "the drop is logged before the document is reported:\n{log}"
        );
        Ok(())
    }

    /// A signer's key and certificate, the key readable by root only, and a
    /// vCon signed by another signer, readable by root only.
    fn resign_inputs(scratch: &Scratch) -> Result<(PathBuf, PathBuf, PathBuf), TestError> {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let identity = |name: &str| -> Result<(String, String), TestError> {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, format!("{name} archive signer"));
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2040, 1, 1);
            let cert = params.self_signed(&key)?;
            Ok((key.serialize_pem(), cert.pem()))
        };
        let (first_key, first_cert) = identity("first")?;
        let signer = sipnab::output::vcon_jose::Signer::from_pem(&first_key, &first_cert)?;
        let signed = sipnab::output::vcon_jose::sign(container().as_bytes(), UUID, &signer)?;
        let input = scratch.root_only("jws1.vcon.json", &String::from_utf8(signed)?)?;
        let (second_key, second_cert) = identity("second")?;
        let key = scratch.root_only("second.key", &second_key)?;
        let cert = scratch.path("second.crt");
        std::fs::write(&cert, second_cert)?;
        Ok((input, key, cert))
    }

    fn resign_args(
        input: &Path,
        key: &Path,
        cert: &Path,
        out: &Path,
    ) -> Result<Vec<String>, TestError> {
        Ok([
            "--vcon-resign",
            text(input)?,
            "--vcon-resign-key",
            text(key)?,
            "--vcon-resign-cert",
            text(cert)?,
            "--vcon-resign-out",
            text(out)?,
        ]
        .map(String::from)
        .to_vec())
    }

    /// A signed vCon and a key only root can read are read before the
    /// drop; the re-signed file is written after it, as `nobody`.
    #[test]
    fn vcon_resign_reads_as_root_and_writes_as_nobody() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_resign_reads_as_root_and_writes_as_nobody") {
            return Ok(());
        }
        let scratch = Scratch::new("resign")?;
        let (input, key, cert) = resign_inputs(&scratch)?;
        let out = scratch.dir_of("out", "nobody")?.join("jws2.vcon.json");
        let (code, log) = run(&strs(&resign_args(&input, &key, &cert, &out)?))?;
        assert_eq!(code, Some(0), "the vCon was re-signed:\n{log}");
        assert_eq!(
            std::fs::metadata(&out)?.uid(),
            uid_of("nobody")?,
            "the output was created after the drop"
        );
        Ok(())
    }

    #[test]
    fn vcon_resign_refuses_an_output_directory_nobody_cannot_write() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_resign_refuses_an_output_directory_nobody_cannot_write") {
            return Ok(());
        }
        let scratch = Scratch::new("resign-refused")?;
        let me = me()?;
        let (input, key, cert) = resign_inputs(&scratch)?;
        let out = scratch.dir_of("out", &me)?.join("jws2.vcon.json");
        let before = names_under(scratch.dir.path())?;
        let (code, log) = run(&strs(&resign_args(&input, &key, &cert, &out)?))?;
        assert_eq!(code, Some(2), "a refused start exits 2:\n{log}");
        for part in [
            "--vcon-resign: started as root",
            "(--vcon-resign-out)",
            &format!("--user {me}"),
        ] {
            assert!(log.contains(part), "the refusal lacks {part:?}:\n{log}");
        }
        assert_eq!(
            names_under(scratch.dir.path())?,
            before,
            "nothing was created"
        );
        Ok(())
    }

    /// An input that is not a vCon is refused after the drop: the run says
    /// which user it dropped to before it says what it refused.
    #[test]
    fn vcon_resign_drops_before_it_reports() -> Result<(), TestError> {
        if !sudo_or_skip("vcon_resign_drops_before_it_reports") {
            return Ok(());
        }
        let scratch = Scratch::new("resign-order")?;
        let (_signed, key, cert) = resign_inputs(&scratch)?;
        let input = scratch.root_only("junk.vcon.json", "this is not JSON")?;
        let out = scratch.dir_of("out", "nobody")?.join("jws2.vcon.json");
        let mut args = resign_args(&input, &key, &cert, &out)?;
        args.push("-v".to_string());
        let (code, log) = run(&strs(&args))?;
        assert_eq!(
            code,
            Some(1),
            "an input that is not a vCon is refused:\n{log}"
        );
        let dropped = log.find("Dropped privileges to user 'nobody'");
        let refused = log.find("not JSON");
        assert!(
            dropped.is_some() && refused.is_some() && dropped < refused,
            "the drop is logged before the input is refused:\n{log}"
        );
        assert!(!out.exists(), "nothing was written");
        Ok(())
    }
}
