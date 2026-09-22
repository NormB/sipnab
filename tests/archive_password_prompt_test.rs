// SPDX-License-Identifier: MIT OR Apache-2.0

//! The archive password prompt, driven through a pseudo-terminal.
//!
//! Each run gets a fresh session whose controlling terminal is the slave side
//! of a pty this test holds, so `/dev/tty` inside sipnab is that pty. The test
//! reads what sipnab writes to the terminal from the master side and types
//! into it. stdin is always `/dev/null`: the prompt must not depend on it.
//!
//! Every password is minted at runtime, and each one is a sentinel: it must
//! appear in no byte the terminal showed (the prompt echoes nothing) and no
//! byte of stdout or stderr.
#![cfg(all(target_os = "linux", feature = "native", feature = "archive"))]

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/pcap_build.rs"]
mod pcap_build;

fn mint(label: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut h);
    std::process::id().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    format!("pw{:016x}{label}", h.finish())
}

fn capture(call_id: &str) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("c.pcap");
    let frames: Vec<(Vec<u8>, u64)> = pcap_build::sip_call_frames(call_id, "b1", "alice", "bob")
        .into_iter()
        .enumerate()
        .map(|(i, f)| (f, 10_000_000 + i as u64 * 1_000))
        .collect();
    pcap_build::write_pcap_at(&p, &frames, 1);
    std::fs::read(&p).expect("read back")
}

/// An AES-256 ZIP holding one call under `calls/a.pcap`.
fn locked_zip(dir: &Path, call_id: &str, password: &str) -> PathBuf {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .with_aes_encryption(zip::AesMode::Aes256, password);
    w.start_file("calls/a.pcap", opts).expect("start");
    w.write_all(&capture(call_id)).expect("write");
    let bytes = w.finish().expect("finish").into_inner();
    let path = dir.join("evidence.zip");
    std::fs::write(&path, bytes).expect("write zip");
    path
}

/// A pty pair: the master this test reads and types into, the slave that
/// becomes sipnab's controlling terminal.
struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

fn pty() -> Pty {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty writes two descriptors into the two out-pointers, which
    // point at live locals; the name, termios and winsize pointers are null,
    // which openpty accepts.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just returned by openpty and are owned by
    // nothing else.
    unsafe {
        Pty {
            master: OwnedFd::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    }
}

/// The slave's local flags, to see whether echo and canonical mode are on.
fn lflag(fd: &OwnedFd) -> libc::tcflag_t {
    // SAFETY: tcgetattr fills a termios the zeroed local provides.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is an open terminal descriptor, and t is a valid termios.
    let rc = unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) };
    assert_eq!(rc, 0, "tcgetattr: {}", std::io::Error::last_os_error());
    t.c_lflag
}

/// A sipnab run in its own session, with the pty as its controlling
/// terminal when `with_tty`, and none at all otherwise.
struct Session {
    child: std::process::Child,
    pty: Pty,
    screen: String,
    /// stdout and stderr, drained as they arrive: a trace-level run writes
    /// more than a pipe holds, and an undrained pipe stops it mid-write.
    drains: Vec<std::thread::JoinHandle<Vec<u8>>>,
}

/// Read `src` to its end on a thread.
fn drain(mut src: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = src.read_to_end(&mut out);
        out
    })
}

fn start(args: &[&str], tmpdir: &Path, with_tty: bool) -> Session {
    let pty = pty();
    let slave = pty.slave.as_raw_fd();
    let master = pty.master.as_raw_fd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(args)
        .env("TMPDIR", tmpdir)
        .env("SIPNAB_LOG", "trace")
        .env("NO_COLOR", "1")
        .env_remove("SIPNAB_ARCHIVE_PASSWORD")
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: between fork and exec this calls only async-signal-safe
    // functions (close, setsid, ioctl) on descriptors the child inherited.
    unsafe {
        cmd.pre_exec(move || {
            libc::close(master);
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if with_tty && libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(slave);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn sipnab");
    let drains = vec![
        drain(child.stdout.take().expect("stdout")),
        drain(child.stderr.take().expect("stderr")),
    ];
    Session {
        child,
        pty,
        screen: String::new(),
        drains,
    }
}

impl Session {
    /// Read what the terminal shows until `needle` appears, or fail.
    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.screen.contains(needle) {
            assert!(
                Instant::now() < deadline,
                "'{needle}' never appeared on the terminal; it showed:\n{}",
                self.screen
            );
            self.pump(Duration::from_millis(100));
        }
    }

    /// Read whatever the terminal shows within `wait`.
    fn pump(&mut self, wait: Duration) {
        let mut pfd = libc::pollfd {
            fd: self.pty.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, wait.as_millis() as libc::c_int) };
        if n <= 0 {
            return;
        }
        let mut buf = [0u8; 4096];
        // SAFETY: buf is a valid writable buffer of the given length.
        let got = unsafe {
            libc::read(
                self.pty.master.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if got > 0 {
            self.screen
                .push_str(&String::from_utf8_lossy(&buf[..got as usize]));
        }
    }

    /// Type `bytes` at the terminal.
    fn type_in(&mut self, bytes: &[u8]) {
        // SAFETY: bytes is a valid readable buffer of the given length.
        let n = unsafe {
            libc::write(
                self.pty.master.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        };
        assert_eq!(n as usize, bytes.len());
    }

    /// Wait for sipnab to exit, reading the terminal meanwhile.
    fn finish(mut self) -> Finished {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(_status) = self.child.try_wait().expect("wait") {
                break;
            }
            assert!(Instant::now() < deadline, "sipnab hung:\n{}", self.screen);
            self.pump(Duration::from_millis(50));
        }
        self.pump(Duration::from_millis(50));
        let lflag = lflag(&self.pty.slave);
        let status = self.child.wait().expect("wait");
        let mut drained = self.drains.into_iter().map(|h| h.join().expect("drain"));
        let stdout = drained.next().unwrap_or_default();
        let stderr = drained.next().unwrap_or_default();
        Finished {
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            screen: self.screen,
            lflag,
        }
    }
}

struct Finished {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    screen: String,
    lflag: libc::tcflag_t,
}

impl Finished {
    fn assert_sealed(&self, password: &str) {
        for (what, text) in [
            ("the terminal", &self.screen),
            ("stdout", &self.stdout),
            ("stderr", &self.stderr),
        ] {
            assert!(!text.contains(password), "the password appeared on {what}");
        }
    }

    fn assert_terminal_restored(&self) {
        assert!(
            self.lflag & libc::ECHO != 0 && self.lflag & libc::ICANON != 0,
            "echo and line mode were not restored: lflag {:o}",
            self.lflag
        );
    }
}

fn args(spec: &str) -> Vec<String> {
    [
        "-N",
        "-I",
        spec,
        "--json-dialogs",
        "--no-cli-print",
        "--portrange",
        "1-65535",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

#[test]
fn the_prompt_asks_on_the_terminal_with_stdin_redirected_and_echoes_nothing() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("prompt");
    let zip = locked_zip(root.path(), "prompt@test", &password);
    let spec = zip.display().to_string();
    let a = args(&spec);
    let mut s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        true,
    );
    s.wait_for("(member calls/a.pcap, attempt 1 of 3): ");
    assert!(
        s.screen.contains(&format!("Password for {spec}")),
        "{}",
        s.screen
    );
    s.type_in(password.as_bytes());
    s.type_in(b"\r");
    let done = s.finish();
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert!(done.stdout.contains("prompt@test"), "{}", done.stderr);
    done.assert_sealed(&password);
    done.assert_terminal_restored();
}

#[test]
fn three_wrong_attempts_skip_the_member() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("three");
    let zip = locked_zip(root.path(), "three@test", &password);
    let a = args(&zip.display().to_string());
    let mut s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        true,
    );
    let wrong: Vec<String> = (0..3).map(|i| mint(&format!("wrong{i}"))).collect();
    for (i, w) in wrong.iter().enumerate() {
        s.wait_for(&format!("attempt {} of 3): ", i + 1));
        s.type_in(w.as_bytes());
        s.type_in(b"\r");
    }
    let done = s.finish();
    assert_eq!(done.code, Some(1), "{}", done.stderr);
    assert!(
        done.stderr.contains("encrypted_wrong_password"),
        "{}",
        done.stderr
    );
    assert_eq!(
        done.screen.matches("Wrong password.").count(),
        2,
        "{}",
        done.screen
    );
    assert!(!done.screen.contains("attempt 4"), "{}", done.screen);
    for w in &wrong {
        done.assert_sealed(w);
    }
    done.assert_sealed(&password);
    done.assert_terminal_restored();
}

#[test]
fn an_empty_entry_skips_the_archive() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("empty");
    let zip = locked_zip(root.path(), "empty@test", &password);
    let a = args(&zip.display().to_string());
    let mut s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        true,
    );
    s.wait_for("attempt 1 of 3): ");
    s.type_in(b"\r");
    let done = s.finish();
    assert_eq!(done.code, Some(1), "{}", done.stderr);
    assert!(
        done.stderr.contains("encrypted_no_password"),
        "{}",
        done.stderr
    );
    assert!(!done.screen.contains("attempt 2"), "{}", done.screen);
    done.assert_terminal_restored();
}

#[test]
fn ctrl_c_at_the_prompt_restores_the_terminal_and_stops() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("ctrlc");
    let zip = locked_zip(root.path(), "ctrlc@test", &password);
    let a = args(&zip.display().to_string());
    let mut s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        true,
    );
    s.wait_for("attempt 1 of 3): ");
    s.type_in(b"half");
    s.type_in(&[0x03]);
    let done = s.finish();
    assert_ne!(done.code, Some(0), "{}", done.stderr);
    assert!(!done.stdout.contains("ctrlc@test"));
    done.assert_terminal_restored();
}

#[test]
fn no_password_prompt_never_asks_even_with_a_terminal() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("noprompt");
    let zip = locked_zip(root.path(), "noprompt@test", &password);
    let mut a = args(&zip.display().to_string());
    a.push("--no-password-prompt".into());
    let s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        true,
    );
    let done = s.finish();
    assert_eq!(done.code, Some(1), "{}", done.stderr);
    assert!(!done.screen.contains("Password for"), "{}", done.screen);
    assert!(
        done.stderr.contains("encrypted_no_password"),
        "{}",
        done.stderr
    );
}

#[test]
fn without_a_terminal_there_is_no_prompt_and_no_hang() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("notty");
    let zip = locked_zip(root.path(), "notty@test", &password);
    let a = args(&zip.display().to_string());
    let started = Instant::now();
    let s = start(
        &a.iter().map(String::as_str).collect::<Vec<_>>(),
        tmp.path(),
        false,
    );
    let done = s.finish();
    assert_eq!(done.code, Some(1), "{}", done.stderr);
    assert!(!done.screen.contains("Password for"), "{}", done.screen);
    assert!(
        done.stderr.contains("encrypted_no_password"),
        "{}",
        done.stderr
    );
    assert!(started.elapsed() < Duration::from_secs(20));
}

#[test]
fn a_decrypted_export_warns_that_it_is_written_unencrypted() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("export");
    let zip = locked_zip(root.path(), "export@test", &password);
    let pw_file = root.path().join("pw");
    std::fs::write(&pw_file, format!("{password}\n")).expect("write");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pw_file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let out = root.path().join("out.pcap");
    let s = start(
        &[
            "-N",
            "-I",
            &zip.display().to_string(),
            "--archive-password-file",
            &pw_file.display().to_string(),
            "-O",
            &out.display().to_string(),
            "--no-cli-print",
        ],
        tmp.path(),
        false,
    );
    let done = s.finish();
    assert_eq!(done.code, Some(0), "{}", done.stderr);
    assert_eq!(
        done.stderr
            .matches("decrypted from a password-protected archive")
            .count(),
        1,
        "{}",
        done.stderr
    );
    done.assert_sealed(&password);
}
