// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A real `sipnab fleet serve` for the tests, and the one HTTP exchange they
//! drive it with.
#![allow(dead_code)]

use std::io::{BufRead as _, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub type TestError = Box<dyn std::error::Error>;

/// A running `sipnab fleet serve`, stopped when dropped.
pub struct Center {
    child: std::process::Child,
    /// `host:port` it serves on.
    pub addr: String,
    /// Its log lines, as they come.
    pub log: std::sync::mpsc::Receiver<String>,
    /// The lines it logged before it said where it serves.
    pub early: Vec<String>,
}

impl Center {
    /// The center's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `sipnab fleet serve` with `args`, once it says where it serves.
    pub fn start(args: &[&str]) -> Result<Self, TestError> {
        Self::start_within(args, Duration::from_secs(30))
    }

    /// [`Self::start`], waiting up to `within` for the center to say where
    /// it serves: a start that rebuilds a large member list takes longer.
    pub fn start_within(args: &[&str], within: Duration) -> Result<Self, TestError> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["fleet", "serve"])
            .args(args)
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, log) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        let deadline = Instant::now() + within;
        let mut early = Vec::new();
        while Instant::now() < deadline {
            match log.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if line.contains("fleet center serving")
                        && let Some(rest) = line.split(" on ").nth(1)
                    {
                        let addr = rest.trim().to_string();
                        return Ok(Self {
                            child,
                            addr,
                            log,
                            early,
                        });
                    }
                    early.push(line);
                }
                Err(_) => {
                    if let Ok(Some(status)) = child.try_wait() {
                        return Err(format!("the center exited early: {status}").into());
                    }
                }
            }
        }
        let _ = child.kill();
        Err("the center did not say where it serves".into())
    }
}

impl Drop for Center {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A `sipnab fleet serve` that is started and not waited for, stopped when
/// dropped. Each log line comes as it arrives, so a test can see what the
/// center did before it said where it serves.
pub struct Starting {
    child: std::process::Child,
    /// Its log lines, as they come.
    pub log: std::sync::mpsc::Receiver<String>,
}

impl Starting {
    /// `sipnab fleet serve` with `args`, as soon as it is spawned.
    pub fn spawn(args: &[String]) -> Result<Self, TestError> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["fleet", "serve"])
            .args(args)
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, log) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        Ok(Self { child, log })
    }

    /// The center's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether the center has exited, with its status.
    pub fn exited(&mut self) -> Result<Option<std::process::ExitStatus>, TestError> {
        Ok(self.child.try_wait()?)
    }

    /// Send the center SIGTERM.
    pub fn terminate(&self) -> Result<(), TestError> {
        let pid = i32::try_from(self.child.id())?;
        // SAFETY: kill(2) with the PID of a child this value spawned and has
        // not reaped; it touches no memory.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    /// The center's exit status, once it exits within `within`; at the
    /// deadline it is killed, and that is an error.
    pub fn wait_within(&mut self, within: Duration) -> Result<std::process::ExitStatus, TestError> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(format!("the center did not exit within {within:?}").into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Starting {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The TCP port process `pid` listens on, or `None` while it holds no
/// listening socket.
///
/// Read from `/proc`: the socket inodes the process holds open, matched
/// against the sockets in the LISTEN state (`0A`) of `/proc/net/tcp` and
/// `/proc/net/tcp6`. This finds the port a center bound with port 0
/// before it logs where it serves, without a port the test reserves.
#[cfg(target_os = "linux")]
pub fn listening_port(pid: u32) -> Result<Option<u16>, TestError> {
    let mut inodes = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let Ok(target) = std::fs::read_link(entry?.path()) else {
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_string());
        }
    }
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(state), Some(inode)) =
                (fields.get(1), fields.get(3), fields.get(9))
            else {
                continue;
            };
            if *state == "0A" && inodes.contains(*inode) {
                let port = local.rsplit(':').next().ok_or("a local port")?;
                return Ok(Some(u16::from_str_radix(port, 16)?));
            }
        }
    }
    Ok(None)
}

/// One HTTP exchange on `addr`: status and body.
pub fn http(
    addr: &str,
    method: &str,
    path: &str,
    token: &str,
    body: &[u8],
) -> Result<(u16, String), TestError> {
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    s.write_all(body)?;
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let (head, rest) = raw.split_once("\r\n\r\n").ok_or("an HTTP answer")?;
    let status = head.split_whitespace().nth(1).ok_or("a status")?.parse()?;
    Ok((status, rest.to_string()))
}

/// One GET-like exchange on `addr` with no body: status, the head and the
/// body, read within 30 seconds.
pub fn http_full(
    addr: &str,
    method: &str,
    path: &str,
    token: &str,
) -> Result<(u16, String, String), TestError> {
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let (head, rest) = raw.split_once("\r\n\r\n").ok_or("an HTTP answer")?;
    let status = head.split_whitespace().nth(1).ok_or("a status")?.parse()?;
    Ok((status, head.to_string(), rest.to_string()))
}

/// A store key file in `dir` for a test center: mode 0600, a fixed key.
pub fn store_key_file(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("center.storekey");
    std::fs::write(&path, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// `sipnab` with `args`, run to its end or ended at `within`: exit code,
/// stdout and stderr.
///
/// A run that is still there at the deadline is killed, and that is an
/// error that carries what the run wrote: a command that waits (on a FIFO
/// under a file's name, on a lock) fails its test and is not left behind.
pub fn sipnab_within(
    args: &[&str],
    within: Duration,
) -> Result<(Option<i32>, String, String), TestError> {
    let scratch = tempfile::tempdir()?;
    let (out, err) = (scratch.path().join("stdout"), scratch.path().join("stderr"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("SIPNAB_LOG")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&out)?)
        .stderr(std::fs::File::create(&err)?)
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + within;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "`sipnab {}` did not end within {within:?} and was ended; stdout:\n{}\nstderr:\n{}",
                args.join(" "),
                std::fs::read_to_string(&out)?,
                std::fs::read_to_string(&err)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok((
        status.code(),
        std::fs::read_to_string(&out)?,
        std::fs::read_to_string(&err)?,
    ))
}

include!("child_lifetime.rs");
