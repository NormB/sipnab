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
}

impl Center {
    /// The center's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `sipnab fleet serve` with `args`, once it says where it serves.
    pub fn start(args: &[&str]) -> Result<Self, TestError> {
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
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match log.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if line.contains("fleet center serving")
                        && let Some(rest) = line.split(" on ").nth(1)
                    {
                        let addr = rest.trim().to_string();
                        return Ok(Self { child, addr, log });
                    }
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

/// A store key file in `dir` for a test center: mode 0600, a fixed key.
pub fn store_key_file(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("center.storekey");
    std::fs::write(&path, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

include!("child_lifetime.rs");
