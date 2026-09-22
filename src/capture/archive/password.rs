// SPDX-License-Identifier: MIT OR Apache-2.0

//! Passwords for encrypted capture archives.
//!
//! Real captures carry subscriber identities, numbers and credentials, so they
//! travel as password-protected ZIP files. Unpacking one by hand leaves a
//! decrypted copy on disk, which defeats the password. sipnab opens the archive
//! itself, and this module is where the password lives while it does.
//!
//! # The password is toxic waste
//!
//! [`ArchivePassword`] is bytes in a [`zeroize::Zeroizing`] buffer, sealed the
//! way [`crate::annotate::NoteText`] is: no `Display`, no `Serialize`, no
//! `Deref`, and a `Debug` that prints `[REDACTED]` without even a length. The
//! only way to read it is a crate-private accessor used at the one moment a
//! decryptor needs the bytes. Every buffer a password is read into is sized
//! before the read, because the copy a reallocation leaves behind is one
//! `zeroize` never sees.
//!
//! # Where a password comes from
//!
//! [`SourceConfig`] lists every place an operator can put one, most preferred
//! first: a file (`--archive-password-file`), a command
//! (`--archive-password-command`), the first line of stdin
//! (`--archive-password-stdin`), a systemd credential named `archive-password`,
//! the `SIPNAB_ARCHIVE_PASSWORD` environment variable, and last the command
//! line itself (`--archive-password`), which warns on every use because `ps`
//! and shell history can read it. Each source that is configured contributes
//! its candidates, in that order.
//!
//! # One typed password is one attempt
//!
//! A decryptor has to reproduce the bytes the archive's creator used, and ZIP
//! never recorded which encoding that was. So a non-ASCII password is also
//! tried in NFC and NFD, and re-encoded into the three single-byte code pages
//! `unzip` and 7-Zip fall back to. All of those spellings are one
//! [`Keyring::unlock`] attempt: three tries at a prompt means three things the
//! operator typed, not three spellings of the first.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use super::codepage::CodePage;

/// The longest password accepted, in bytes. Anything longer is refused whole,
/// never truncated: a truncated password is a different password.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// The largest password file read. One candidate per line; a file this size
/// holds sixteen passwords of the longest length.
pub const MAX_PASSWORD_FILE_BYTES: usize = 64 * 1024;

/// How long `--archive-password-command` may run. Long enough for a secret
/// manager to prompt for its own unlock, short enough that a wedged command
/// does not hang a scripted run for good.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// Tries a prompt gets per archive. Each try covers every encoding variant of
/// what was typed.
pub const PROMPT_ATTEMPTS: u32 = 3;

/// The systemd credential name sipnab reads from `$CREDENTIALS_DIRECTORY`.
pub const CREDENTIAL_NAME: &str = "archive-password";

/// The environment variable a password may be passed in.
pub const ENV_VAR: &str = "SIPNAB_ARCHIVE_PASSWORD";

/// The warning `--archive-password` prints on every use, in the form Docker
/// prints for `docker login -p`.
pub const INLINE_WARNING: &str = "WARNING! Using --archive-password on the command line is \
     insecure: other local users can read it in `ps`, and it is saved in shell history. Use \
     --archive-password-stdin, --archive-password-file or --archive-password-command.";

/// A password for an encrypted archive.
///
/// Bytes, not a `String`: real archives carry passwords that are not UTF-8,
/// and the ZIP format hashes bytes. Cleared from memory when dropped.
///
/// It prints as `[REDACTED]`:
///
/// ```
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// assert_eq!(format!("{pw:?}"), "[REDACTED]");
/// ```
///
/// No `Display`, so no `to_string` and no `format!("{}")`:
///
/// ```compile_fail
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// let _text = pw.to_string();
/// ```
///
/// No `Serialize`, so it cannot be put into any JSON projection:
///
/// ```compile_fail
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// let _json = serde_json::to_string(&pw);
/// ```
///
/// No `Deref` to its bytes and no `as_str`:
///
/// ```compile_fail
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// let _len = pw.len();
/// ```
///
/// ```compile_fail
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// let _text = pw.as_str();
/// ```
///
/// And the bytes are reachable only inside the crate:
///
/// ```compile_fail
/// let pw = sipnab::capture::archive::password::ArchivePassword::from_bytes(b"sealed")
///     .expect("valid");
/// let _bytes: &[u8] = pw.expose();
/// ```
#[derive(Clone)]
pub struct ArchivePassword(Zeroizing<Vec<u8>>);

impl ArchivePassword {
    /// Copy `bytes` into a sealed password.
    ///
    /// The copy is allocated at exactly its length, so it is never moved by a
    /// reallocation. Clearing `bytes` stays the caller's job.
    ///
    /// # Errors
    ///
    /// [`PasswordRefusal`] when `bytes` is empty or longer than
    /// [`MAX_PASSWORD_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasswordRefusal> {
        if bytes.is_empty() {
            return Err(PasswordRefusal::Empty);
        }
        if bytes.len() > MAX_PASSWORD_BYTES {
            return Err(PasswordRefusal::TooLong { bytes: bytes.len() });
        }
        let mut owned = Zeroizing::new(Vec::with_capacity(bytes.len()));
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    /// The bytes, for the decryptor and nothing else.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ArchivePassword {
    /// `[REDACTED]`, with no length: the `secrecy` crate's convention, so a
    /// `{:?}` in a log line or a test failure carries nothing about it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Why bytes were refused as a password. Names the problem, never the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordRefusal {
    /// Nothing at all.
    Empty,
    /// More than [`MAX_PASSWORD_BYTES`].
    TooLong {
        /// How many bytes there were.
        bytes: usize,
    },
}

impl std::fmt::Display for PasswordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the password is empty"),
            Self::TooLong { bytes } => write!(
                f,
                "the password is {bytes} bytes, over the {MAX_PASSWORD_BYTES}-byte limit; it \
                 was refused whole rather than cut short, since a shortened password is a \
                 different one"
            ),
        }
    }
}

/// `line` without its terminator: one trailing `\n`, or `\r\n`.
///
/// Nothing else is removed. Leading and trailing spaces are part of a password
/// (NIST SP 800-63B-4 says to accept them), and OpenSSL, gpg and borg strip
/// only the newline too. This is deliberately NOT the trim
/// [`crate::cli::resolve_file_or_inline_secret`] applies to tokens.
#[must_use]
pub fn strip_terminator(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Split a password file's bytes into candidates, one per line.
///
/// Blank lines are passed over: an empty password opens nothing.
///
/// # Errors
///
/// When a line is longer than [`MAX_PASSWORD_BYTES`], naming its line number.
pub fn split_candidates(buf: &[u8]) -> Result<Vec<ArchivePassword>, String> {
    let mut out = Vec::new();
    for (n, raw) in buf.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = strip_terminator(raw);
        if line.is_empty() {
            continue;
        }
        match ArchivePassword::from_bytes(line) {
            Ok(pw) => out.push(pw),
            Err(e) => return Err(format!("line {}: {e}", n + 1)),
        }
    }
    Ok(out)
}

/// Whether a password file may be read, by OpenSSH's rule for private keys.
///
/// Refused only when the file is a regular file owned by the user running
/// sipnab AND any group or other permission bit is set. So:
///
/// - `chmod 644` on your own file is refused. Anyone on the box can read it.
/// - A file another user owns is accepted whatever its mode: a Kubernetes
///   secret mount is `root 0644`, and a systemd credential is `0400` with an
///   ACL. Its owner decided who reads it.
/// - A pipe, a FIFO or a device is accepted: `<(pass show pcaps)` and
///   `/dev/stdin` stat as a pipe, and a pipe's mode says nothing about who
///   can read what passes through it.
///
/// Returns the refusal's text, naming the mode, or `None` to proceed.
#[must_use]
pub fn permission_refusal(owner: u32, me: u32, mode: u32, regular: bool) -> Option<String> {
    if regular && owner == me && mode & 0o077 != 0 {
        return Some(format!(
            "can be read or written by other users (mode {:04o}); chmod 600 it",
            mode & 0o7777
        ));
    }
    None
}

/// Read at most `max` bytes of `src` into a buffer sized before the read.
///
/// # Errors
///
/// When the read fails, or `src` holds more than `max` bytes.
fn read_bounded(src: &mut dyn Read, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; max + 1]);
    let mut got = 0;
    loop {
        match src.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => {
                got += n;
                if got > max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("more than {max} bytes"),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    // Shrinking the length never moves the buffer.
    buf.truncate(got);
    Ok(buf)
}

/// The user running this process.
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::getuid() }
}

/// Read every candidate from a password file, after the permission check.
///
/// The check is made on the descriptor that is then read, not on the path, so
/// nothing can swap the file between the two.
///
/// # Errors
///
/// When the file cannot be opened or read, fails [`permission_refusal`], is
/// larger than [`MAX_PASSWORD_FILE_BYTES`], holds a line that is too long, or
/// holds no password at all. `what` names the source in every message.
pub fn read_password_file(path: &Path, what: &str) -> Result<Vec<ArchivePassword>, String> {
    let shown = path.display();
    let mut file = std::fs::File::open(path).map_err(|e| format!("{what} '{shown}': {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|e| format!("{what} '{shown}': {e}"))?;
        if let Some(why) = permission_refusal(
            meta.uid(),
            current_uid(),
            meta.mode(),
            meta.file_type().is_file(),
        ) {
            return Err(format!("{what} '{shown}' {why}"));
        }
    }
    let buf = read_bounded(&mut file, MAX_PASSWORD_FILE_BYTES).map_err(|e| {
        format!("{what} '{shown}': {e}; a password file holds one password per line")
    })?;
    let found = split_candidates(&buf).map_err(|e| format!("{what} '{shown}', {e}"))?;
    if found.is_empty() {
        return Err(format!("{what} '{shown}' holds no password"));
    }
    Ok(found)
}

/// Read one password: the first line of `src`.
///
/// Reads a byte at a time and stops at the first newline, so nothing past the
/// password is consumed, into a buffer sized before the read.
///
/// # Errors
///
/// When the read fails, the line is longer than [`MAX_PASSWORD_BYTES`], or it
/// is empty.
pub fn read_first_line(src: &mut dyn Read, what: &str) -> Result<ArchivePassword, String> {
    // The password, an optional `\r`, and one byte to notice a line too long.
    let cap = MAX_PASSWORD_BYTES + 2;
    let mut line = Zeroizing::new(Vec::with_capacity(cap));
    // Cleared on drop like the line: it held each byte of the password.
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match src.read(&mut *byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() == cap {
                    return Err(format!(
                        "{what}: {}",
                        PasswordRefusal::TooLong {
                            bytes: line.len() + 1
                        }
                    ));
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("{what}: {e}")),
        }
    }
    ArchivePassword::from_bytes(strip_terminator(&line)).map_err(|e| format!("{what}: {e}"))
}

/// Split a command line into words the way a POSIX shell would, without
/// running one: whitespace separates, single quotes are literal, double quotes
/// allow `\"`, `\\`, `` \` `` and `\$`, and a backslash outside quotes escapes
/// the next character. borg splits `BORG_PASSCOMMAND` the same way.
///
/// # Errors
///
/// When a quote is left open, a backslash ends the line, or there is no word.
pub fn split_command(cmd: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Err("a single quote is not closed".to_string()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\' | '`' | '$')) => cur.push(e),
                            Some(other) => {
                                cur.push('\\');
                                cur.push(other);
                            }
                            None => return Err("a double quote is not closed".to_string()),
                        },
                        Some(c) => cur.push(c),
                        None => return Err("a double quote is not closed".to_string()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(c) => cur.push(c),
                    None => return Err("the command ends in a backslash".to_string()),
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    if words.is_empty() {
        return Err("the command is empty".to_string());
    }
    Ok(words)
}

/// The most `--archive-password-command` may print. The first line is the
/// password, so anything this long is not a password command.
pub const MAX_COMMAND_OUTPUT: usize = 64 * 1024;

/// Run `--archive-password-command` and take the first line it prints.
///
/// Run without a shell (restic's `--password-command`, borg's
/// `BORG_PASSCOMMAND`). Its stderr passes through, so a secret manager can
/// prompt; its stdin is the terminal's unless `stdin_taken`, when stdin is
/// already carrying `--archive-password-stdin`.
///
/// # Errors
///
/// When the command cannot be split or started, does not finish within
/// `timeout`, exits non-zero, prints more than [`MAX_COMMAND_OUTPUT`] bytes,
/// or prints an empty first line. Every message names the program and never
/// its output, which may hold the password.
pub fn run_password_command(
    cmd: &str,
    timeout: Duration,
    stdin_taken: bool,
) -> Result<ArchivePassword, String> {
    let what = "--archive-password-command";
    let argv = split_command(cmd).map_err(|e| format!("{what}: {e}"))?;
    let program = argv[0].clone();
    let mut child = std::process::Command::new(&program)
        .args(&argv[1..])
        .stdin(if stdin_taken {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::inherit()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{what}: could not run '{program}': {e}"))?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("{what}: '{program}' has no stdout to read"));
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let out = read_bounded(&mut stdout, MAX_COMMAND_OUTPUT);
        let _ = tx.send(out);
    });
    let started = std::time::Instant::now();
    let mut early: Option<io::Result<Zeroizing<Vec<u8>>>> = None;
    let status = loop {
        // Output past the bound ends the wait at once: a command that prints
        // forever would otherwise hold the run until the timeout.
        if early.is_none()
            && let Ok(out) = rx.try_recv()
        {
            if let Err(e) = out {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!("{what}: '{program}' printed {e}"));
            }
            early = Some(out);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!(
                    "{what}: '{program}' did not finish within {}s and was stopped",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}: waiting for '{program}': {e}"));
            }
        }
    };
    // The command has exited; its stdout closes with it unless a grandchild
    // kept it open, which the output bound and this wait cover.
    let out = match early.map_or_else(
        || rx.recv_timeout(timeout.saturating_sub(started.elapsed())),
        Ok,
    ) {
        Ok(out) => out,
        Err(_) => {
            return Err(format!(
                "{what}: '{program}' exited, but something it started kept its output open"
            ));
        }
    };
    let _ = reader.join();
    let out = out.map_err(|e| format!("{what}: '{program}' printed {e}"))?;
    if !status.success() {
        return Err(format!(
            "{what}: '{program}' failed ({status}); its output is not shown, since it may \
             hold the password"
        ));
    }
    let first = out.split(|b| *b == b'\n').next().unwrap_or(&[]);
    ArchivePassword::from_bytes(strip_terminator(first))
        .map_err(|e| format!("{what}: '{program}' printed no usable first line: {e}"))
}

/// Where a candidate came from, for messages that must name the source and
/// never the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--archive-password-file`.
    File,
    /// `--archive-password-command`.
    Command,
    /// `--archive-password-stdin`.
    Stdin,
    /// The systemd credential `archive-password`.
    Credential,
    /// `SIPNAB_ARCHIVE_PASSWORD`.
    Environment,
    /// `--archive-password`.
    CommandLine,
    /// A REST request's `Sipnab-Archive-Password` header.
    Request,
    /// Typed at a prompt.
    Prompt,
}

impl Source {
    /// How the source is named in output.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::File => "--archive-password-file",
            Self::Command => "--archive-password-command",
            Self::Stdin => "--archive-password-stdin",
            Self::Credential => "the systemd credential archive-password",
            Self::Environment => ENV_VAR,
            Self::CommandLine => "--archive-password",
            Self::Request => "the Sipnab-Archive-Password header",
            Self::Prompt => "the prompt",
        }
    }
}

/// One password to try, and where it came from.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The password.
    pub password: ArchivePassword,
    /// Its source.
    pub source: Source,
}

/// Every place a run may take archive passwords from, as configured.
///
/// Plain data, so [`collect`] can be driven by a test without a process
/// environment: the caller reads `$CREDENTIALS_DIRECTORY` and
/// `SIPNAB_ARCHIVE_PASSWORD` and passes them in.
#[derive(Debug, Default)]
pub struct SourceConfig {
    /// `--archive-password-file`.
    pub file: Option<PathBuf>,
    /// `--archive-password-command`.
    pub command: Option<String>,
    /// `--archive-password-stdin`.
    pub stdin: bool,
    /// `$CREDENTIALS_DIRECTORY`, which systemd sets for a unit that loads
    /// credentials.
    pub credentials_directory: Option<PathBuf>,
    /// `SIPNAB_ARCHIVE_PASSWORD`, as bytes.
    pub environment: Option<OsString>,
    /// `--archive-password`, as bytes.
    pub inline: Option<OsString>,
    /// How long the command may run; [`COMMAND_TIMEOUT`] outside tests.
    pub command_timeout: Option<Duration>,
}

impl SourceConfig {
    /// Whether any source is configured. A credentials directory alone is not
    /// one: systemd sets it for every credential a unit loads, and only a file
    /// named [`CREDENTIAL_NAME`] in it is a password.
    #[must_use]
    pub fn any(&self) -> bool {
        self.file.is_some()
            || self.command.is_some()
            || self.stdin
            || self
                .credentials_directory
                .as_ref()
                .is_some_and(|d| d.join(CREDENTIAL_NAME).exists())
            || self.environment.is_some()
            || self.inline.is_some()
    }
}

/// The bytes of an OS string, as the process received them.
fn os_bytes(value: &OsString) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

/// Gather every configured candidate, most preferred source first.
///
/// `stdin` is read only when `cfg.stdin` asks for it. The inline flag warns on
/// every use.
///
/// # Errors
///
/// When a configured source cannot supply a password: an unreadable or
/// over-permissive file, a failing command, an empty stdin, an empty
/// environment variable. A source the operator configured and that yields
/// nothing is a mistake to report, not a candidate to leave out quietly.
pub fn collect(cfg: &SourceConfig, stdin: &mut dyn Read) -> Result<Vec<Candidate>, String> {
    let mut out = Vec::new();
    let mut push = |password: ArchivePassword, source: Source| {
        out.push(Candidate { password, source });
    };
    if let Some(path) = &cfg.file {
        for pw in read_password_file(path, "--archive-password-file")? {
            push(pw, Source::File);
        }
    }
    if let Some(cmd) = &cfg.command {
        let timeout = cfg.command_timeout.unwrap_or(COMMAND_TIMEOUT);
        push(
            run_password_command(cmd, timeout, cfg.stdin)?,
            Source::Command,
        );
    }
    if cfg.stdin {
        push(
            read_first_line(stdin, "--archive-password-stdin")?,
            Source::Stdin,
        );
    }
    if let Some(dir) = &cfg.credentials_directory {
        let path = dir.join(CREDENTIAL_NAME);
        if path.exists() {
            for pw in read_password_file(&path, "systemd credential")? {
                push(pw, Source::Credential);
            }
        }
    }
    if let Some(value) = &cfg.environment {
        let bytes = Zeroizing::new(os_bytes(value));
        let pw = ArchivePassword::from_bytes(&bytes).map_err(|e| format!("{ENV_VAR}: {e}"))?;
        push(pw, Source::Environment);
    }
    if let Some(value) = &cfg.inline {
        tracing::warn!("{INLINE_WARNING}");
        let bytes = Zeroizing::new(os_bytes(value));
        let pw =
            ArchivePassword::from_bytes(&bytes).map_err(|e| format!("--archive-password: {e}"))?;
        push(pw, Source::CommandLine);
    }
    Ok(out)
}

/// The container a password is for, which decides the encoding variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// ZIP: the password's bytes are hashed as they are, in whatever encoding
    /// the creator's tool used.
    Zip,
}

/// An encoding `--archive-password-encoding` pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The bytes exactly as supplied.
    Utf8,
    /// Re-encoded into a single-byte code page.
    Page(CodePage),
}

impl std::str::FromStr for Encoding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "utf-8" | "utf8" => Ok(Self::Utf8),
            "cp437" | "ibm437" => Ok(Self::Page(CodePage::Cp437)),
            "cp850" | "ibm850" => Ok(Self::Page(CodePage::Cp850)),
            "cp1252" | "windows-1252" => Ok(Self::Page(CodePage::Cp1252)),
            other => Err(format!(
                "unknown password encoding '{other}'; use utf-8, cp437, cp850 or cp1252"
            )),
        }
    }
}

/// `text` normalized, in a buffer sized before it is filled, or `None` when
/// the normalized form would not fit: a password is never grown by
/// reallocation.
fn normalized(text: &str, compose: bool) -> Option<Zeroizing<Vec<u8>>> {
    use unicode_normalization::UnicodeNormalization;
    // NFD at most triples a character's UTF-8 length; the margin covers the
    // rest.
    let cap = text.len() * 3 + 16;
    let mut out = Zeroizing::new(String::with_capacity(cap));
    let mut push = |c: char| -> Option<()> {
        if out.len() + c.len_utf8() > cap {
            return None;
        }
        out.push(c);
        Some(())
    };
    if compose {
        for c in text.nfc() {
            push(c)?;
        }
    } else {
        for c in text.nfd() {
            push(c)?;
        }
    }
    let s: String = std::mem::take(&mut *out);
    Some(Zeroizing::new(s.into_bytes()))
}

/// Every spelling of `pw` a decryptor should try, most likely first.
///
/// 1. the exact bytes supplied;
/// 2. if non-ASCII UTF-8, its NFC and then NFD forms;
/// 3. for ZIP, if non-ASCII, the CP437, CP850 and CP1252 re-encodings, which
///    is what `unzip` and 7-Zip fall back to.
///
/// Duplicates are dropped. A pinned encoding yields exactly one spelling.
#[must_use]
pub fn variants(
    pw: &ArchivePassword,
    container: Container,
    pinned: Option<Encoding>,
) -> Vec<Zeroizing<Vec<u8>>> {
    let exact = pw.expose();
    let text = std::str::from_utf8(exact).ok();
    let to_page = |page: CodePage, text: &str| -> Option<Zeroizing<Vec<u8>>> {
        let source = normalized(text, true)?;
        let composed = std::str::from_utf8(&source).ok()?;
        let mut out = Zeroizing::new(Vec::with_capacity(composed.chars().count()));
        page.encode_into(composed, &mut out)?;
        Some(out)
    };
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    match pinned {
        Some(Encoding::Utf8) | None => out.push(Zeroizing::new(exact.to_vec())),
        Some(Encoding::Page(page)) => {
            match text.and_then(|t| to_page(page, t)) {
                Some(v) => out.push(v),
                // Not text, or a character the page lacks: the bytes as given
                // are the only spelling left.
                None => out.push(Zeroizing::new(exact.to_vec())),
            }
            return out;
        }
    }
    if pinned.is_some() || exact.is_ascii() {
        return out;
    }
    let Some(text) = text else {
        return out;
    };
    let add = |v: Option<Zeroizing<Vec<u8>>>, out: &mut Vec<Zeroizing<Vec<u8>>>| {
        if let Some(v) = v
            && !out.iter().any(|o| o.as_slice() == v.as_slice())
        {
            out.push(v);
        }
    };
    add(normalized(text, true), &mut out);
    add(normalized(text, false), &mut out);
    match container {
        Container::Zip => {
            for page in CodePage::ALL {
                add(to_page(page, text), &mut out);
            }
        }
    }
    out
}

/// What a prompt is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRequest {
    /// The archive's label.
    pub archive: String,
    /// The member's label, relative to the archive.
    pub member: String,
    /// This attempt, from 1.
    pub attempt: u32,
    /// Attempts allowed, [`PROMPT_ATTEMPTS`].
    pub of: u32,
    /// Whether the previous attempt was wrong.
    pub after_wrong: bool,
}

/// What a prompt answers.
#[derive(Debug)]
pub enum PromptAnswer {
    /// A password to try.
    Password(ArchivePassword),
    /// Skip this archive's locked members: an empty entry, Esc, or no
    /// terminal to ask on.
    Skip,
}

/// Something that can ask the operator for a password: the CLI's `/dev/tty`
/// prompt, or the TUI's popup.
pub trait Prompter: Send {
    /// Ask once.
    fn ask(&mut self, request: &PromptRequest) -> PromptAnswer;
}

/// The result of one try of one spelling.
#[derive(Debug)]
pub enum Trial<T> {
    /// It opened; here is what reading it produced.
    Opened(T),
    /// The format's own check said this is not the password.
    Wrong,
    /// The member cannot be decrypted by sipnab whatever the password.
    Unsupported(String),
}

/// The outcome of [`Keyring::unlock`].
#[derive(Debug)]
pub enum Unlock<T> {
    /// A password opened it.
    Opened(T),
    /// No password was available to try.
    NoPassword,
    /// Every password tried was wrong.
    WrongPassword,
    /// The member's encryption is one sipnab cannot decrypt.
    Unsupported(String),
}

/// Every password a run or a request can offer an archive, and what it has
/// learned about which opens what.
#[derive(Default)]
pub struct Keyring {
    /// Configured candidates, in source order.
    candidates: Vec<Candidate>,
    /// Archive label -> the password that opened a member of it. Tried first
    /// for that archive's other members, and offered to no other archive.
    remembered: HashMap<String, ArchivePassword>,
    /// The encoding `--archive-password-encoding` pinned, if any.
    pinned: Option<Encoding>,
    /// Asks the operator when no candidate opens a member.
    prompter: Option<Box<dyn Prompter>>,
    /// Archive label -> prompts already spent on it.
    prompted: HashMap<String, u32>,
    /// Archives the operator skipped at a prompt, or whose prompts ran out.
    given_up: HashSet<String>,
    /// Archives a prompted password was actually tried on, which is what
    /// makes a later locked member "wrong password" rather than "no password".
    prompt_tried: HashSet<String>,
    /// Typed passwords tried, counting every spelling of one as one.
    attempts: u64,
    /// Of those, how many opened nothing.
    wrong: u64,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("candidates", &self.candidates.len())
            .field("remembered", &self.remembered.len())
            .field("pinned", &self.pinned)
            .field("prompter", &self.prompter.is_some())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// A keyring offering `candidates`, spelled per `pinned`.
    #[must_use]
    pub fn new(candidates: Vec<Candidate>, pinned: Option<Encoding>) -> Self {
        Self {
            candidates,
            pinned,
            ..Self::default()
        }
    }

    /// Ask `prompter` when no configured candidate opens a member.
    pub fn set_prompter(&mut self, prompter: Option<Box<dyn Prompter>>) {
        self.prompter = prompter;
    }

    /// Take the prompter back out.
    pub fn take_prompter(&mut self) -> Option<Box<dyn Prompter>> {
        self.prompter.take()
    }

    /// Whether any password or prompt is available at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty() && self.prompter.is_none() && self.remembered.is_empty()
    }

    /// Configured candidates.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Typed passwords tried so far, every spelling of one counted once.
    #[must_use]
    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Typed passwords tried that opened nothing.
    #[must_use]
    pub fn wrong_attempts(&self) -> u64 {
        self.wrong
    }

    /// Archives this keyring remembers a password for.
    #[must_use]
    pub fn remembered_count(&self) -> usize {
        self.remembered.len()
    }

    /// Forget every password this keyring remembered, clearing each.
    pub fn forget_remembered(&mut self) {
        self.remembered.clear();
        self.prompted.clear();
        self.given_up.clear();
        self.prompt_tried.clear();
    }

    /// Try every spelling of `pw` with `try_one`, counting one attempt.
    fn attempt<T>(
        &mut self,
        pw: &ArchivePassword,
        container: Container,
        try_one: &mut dyn FnMut(&[u8]) -> Trial<T>,
    ) -> Trial<T> {
        self.attempts += 1;
        for spelling in variants(pw, container, self.pinned) {
            match try_one(&spelling) {
                Trial::Wrong => {}
                other => return other,
            }
        }
        self.wrong += 1;
        Trial::Wrong
    }

    /// Open one encrypted member of `archive`.
    ///
    /// Tries, in order: the password that opened this archive before, every
    /// configured candidate, then the prompt, up to [`PROMPT_ATTEMPTS`] per
    /// archive. Every spelling of one password is one attempt. The first that
    /// opens is remembered for `archive` alone.
    pub fn unlock<T>(
        &mut self,
        archive: &str,
        member: &str,
        container: Container,
        try_one: &mut dyn FnMut(&[u8]) -> Trial<T>,
    ) -> Unlock<T> {
        let mut tried = false;
        if let Some(pw) = self.remembered.get(archive).cloned() {
            tried = true;
            match self.attempt(&pw, container, try_one) {
                Trial::Opened(t) => return Unlock::Opened(t),
                Trial::Unsupported(why) => return Unlock::Unsupported(why),
                Trial::Wrong => {}
            }
        }
        for i in 0..self.candidates.len() {
            let pw = self.candidates[i].password.clone();
            tried = true;
            match self.attempt(&pw, container, try_one) {
                Trial::Opened(t) => {
                    self.remembered.insert(archive.to_string(), pw);
                    return Unlock::Opened(t);
                }
                Trial::Unsupported(why) => return Unlock::Unsupported(why),
                Trial::Wrong => {}
            }
        }
        let give_up = |tried: bool| {
            if tried {
                Unlock::WrongPassword
            } else {
                Unlock::NoPassword
            }
        };
        if self.given_up.contains(archive) {
            return give_up(tried || self.prompt_tried.contains(archive));
        }
        let Some(mut prompter) = self.prompter.take() else {
            return give_up(tried);
        };
        let mut after_wrong = false;
        let result = loop {
            let used = self.prompted.get(archive).copied().unwrap_or(0);
            if used >= PROMPT_ATTEMPTS {
                self.given_up.insert(archive.to_string());
                break give_up(true);
            }
            self.prompted.insert(archive.to_string(), used + 1);
            let request = PromptRequest {
                archive: archive.to_string(),
                member: member.to_string(),
                attempt: used + 1,
                of: PROMPT_ATTEMPTS,
                after_wrong,
            };
            let pw = match prompter.ask(&request) {
                PromptAnswer::Password(pw) => pw,
                PromptAnswer::Skip => {
                    self.given_up.insert(archive.to_string());
                    break give_up(tried || self.prompt_tried.contains(archive));
                }
            };
            self.prompt_tried.insert(archive.to_string());
            match self.attempt(&pw, container, try_one) {
                Trial::Opened(t) => {
                    self.remembered.insert(archive.to_string(), pw);
                    break Unlock::Opened(t);
                }
                Trial::Unsupported(why) => break Unlock::Unsupported(why),
                Trial::Wrong => after_wrong = true,
            }
        };
        self.prompter = Some(prompter);
        result
    }
}

/// Archives already warned about for ZipCrypto, so each is warned once.
static ZIPCRYPTO_WARNED: parking_lot::Mutex<Option<HashSet<String>>> =
    parking_lot::Mutex::new(None);

/// The ZipCrypto warning for `archive`.
#[must_use]
pub fn zipcrypto_warning(archive: &str) -> String {
    format!(
        "'{archive}' uses ZipCrypto, which does not protect its contents: 12 known bytes \
         recover the keys (bkcrack), and a capture's first bytes are predictable. \
         Re-encrypt with AES-256."
    )
}

/// Warn that `archive` uses ZipCrypto, once per archive per process. Returns
/// whether this call warned.
pub fn warn_zipcrypto_once(archive: &str) -> bool {
    let mut guard = ZIPCRYPTO_WARNED.lock();
    let set = guard.get_or_insert_with(HashSet::new);
    if !set.insert(archive.to_string()) {
        return false;
    }
    tracing::warn!("{}", zipcrypto_warning(archive));
    true
}

/// The run's keyring: the operator's configured passwords, and what they have
/// opened. Installed once at start-up by the CLI.
static RUN_KEYRING: parking_lot::Mutex<Option<Keyring>> = parking_lot::Mutex::new(None);

/// Install the run's keyring, replacing any earlier one (whose passwords are
/// cleared as it drops).
pub fn install_run_keyring(keyring: Keyring) {
    *RUN_KEYRING.lock() = Some(keyring);
}

/// Drop the run's keyring, clearing every password it held.
///
/// Never waits: an exit can be taken from inside a walk that holds the
/// keyring, such as Ctrl-C at the prompt, and waiting there would never end.
/// The process is leaving in that case, and its memory with it.
pub fn clear_run_keyring() {
    if let Some(mut guard) = RUN_KEYRING.try_lock() {
        drop(guard.take());
    }
}

/// Run `f` with the run's keyring, installing an empty one first when there
/// is none: for a surface that brings its own prompter, such as the TUI.
pub fn with_run_keyring_or_default<R>(f: impl FnOnce(&mut Keyring) -> R) -> R {
    let mut guard = RUN_KEYRING.lock();
    f(guard.get_or_insert_with(Keyring::default))
}

/// Run `f` with the run's keyring, if one is installed.
pub fn with_run_keyring<R>(f: impl FnOnce(Option<&mut Keyring>) -> R) -> R {
    let mut guard = RUN_KEYRING.lock();
    f(guard.as_mut())
}

/// A copy of the run's configured candidates, for a request that adds its own
/// and must not share what another request's password opened.
#[must_use]
pub fn run_candidates() -> (Vec<Candidate>, Option<Encoding>) {
    let guard = RUN_KEYRING.lock();
    match guard.as_ref() {
        Some(k) => (k.candidates.clone(), k.pinned),
        None => (Vec::new(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password for a test: runtime material, never a literal, so no
    /// scanner reads a hard-coded key into these tests.
    fn pw(label: &str) -> ArchivePassword {
        ArchivePassword::from_bytes(crate::test_material::key_str(label).as_bytes()).expect("valid")
    }

    #[test]
    fn debug_prints_redacted_and_nothing_else() {
        let p = pw("debug");
        let shown = format!("{p:?} {:?}", vec![p.clone()]);
        assert_eq!(shown, "[REDACTED] [[REDACTED]]");
        assert!(!shown.contains(crate::test_material::key_str("debug")));
    }

    #[test]
    fn only_the_line_terminator_is_stripped() {
        assert_eq!(strip_terminator(b"  a b  \n"), b"  a b  ");
        assert_eq!(strip_terminator(b"\tpw\r\n"), b"\tpw");
        assert_eq!(strip_terminator(b"pw"), b"pw");
        // One terminator, not every trailing newline: a password can end in
        // a carriage return typed on purpose only if nothing eats it twice.
        assert_eq!(strip_terminator(b"pw\n\n"), b"pw\n");
    }

    #[test]
    fn a_file_holds_one_candidate_per_line_spaces_kept() {
        let got = split_candidates(b" lead\ntrail \r\n\nthird").expect("split");
        let bytes: Vec<&[u8]> = got.iter().map(ArchivePassword::expose).collect();
        assert_eq!(bytes, vec![&b" lead"[..], b"trail ", b"third"]);
    }

    #[test]
    fn a_password_over_the_limit_is_refused_whole() {
        let long = vec![b'x'; MAX_PASSWORD_BYTES + 1];
        let err = ArchivePassword::from_bytes(&long).expect_err("too long");
        assert_eq!(
            err,
            PasswordRefusal::TooLong {
                bytes: MAX_PASSWORD_BYTES + 1
            }
        );
        assert!(ArchivePassword::from_bytes(&long[..MAX_PASSWORD_BYTES]).is_ok());
        let mut file = b"short\n".to_vec();
        file.extend_from_slice(&long);
        let err = split_candidates(&file).expect_err("line 2 too long");
        assert!(err.starts_with("line 2:"), "{err}");
        let err = read_first_line(&mut &long[..], "stdin").expect_err("too long");
        assert!(err.contains("4096-byte limit"), "{err}");
    }

    #[test]
    fn the_permission_rule_is_openssh_s() {
        let me = 1000;
        // Own file, any group or other bit: refused, naming the mode.
        let why = permission_refusal(me, me, 0o100_644, true).expect("own 0644 refused");
        assert!(
            why.contains("mode 0644") && why.contains("chmod 600"),
            "{why}"
        );
        assert!(permission_refusal(me, me, 0o100_640, true).is_some());
        assert!(permission_refusal(me, me, 0o100_604, true).is_some());
        // Own file, owner-only: accepted.
        assert_eq!(permission_refusal(me, me, 0o100_600, true), None);
        assert_eq!(permission_refusal(me, me, 0o100_400, true), None);
        // Another owner (a root 0644 Kubernetes mount): accepted.
        assert_eq!(permission_refusal(0, me, 0o100_644, true), None);
        // A pipe or FIFO: accepted whatever its mode.
        assert_eq!(permission_refusal(me, me, 0o010_644, false), None);
    }

    #[cfg(unix)]
    #[test]
    fn an_own_world_readable_file_is_refused_and_a_private_one_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("pw");
        std::fs::write(
            &path,
            format!("{}\n", crate::test_material::key_str("file")),
        )
        .expect("w");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = read_password_file(&path, "--archive-password-file").expect_err("0644");
        assert!(err.contains("mode 0644"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let got = read_password_file(&path, "--archive-password-file").expect("0600");
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].expose(),
            crate::test_material::key_str("file").as_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_read_whatever_its_mode() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("fifo");
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("cstr");
        // SAFETY: `c` is a valid NUL-terminated path; mkfifo reads nothing else.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo");
        let writer_path = path.clone();
        let secret = crate::test_material::key_str("fifo");
        let writer = std::thread::spawn(move || {
            std::fs::write(&writer_path, format!("{secret}\n")).expect("write fifo");
        });
        let got = read_password_file(&path, "--archive-password-file").expect("fifo read");
        writer.join().expect("writer");
        assert_eq!(got[0].expose(), secret.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_another_user_owns_is_not_refused_for_its_mode() {
        use std::os::unix::fs::MetadataExt;
        // A root-owned world-readable file stands in for a Kubernetes secret
        // mount; it is present on every Unix this runs on.
        let path = Path::new("/etc/passwd");
        let meta = std::fs::metadata(path).expect("stat");
        if meta.uid() == current_uid() {
            return; // Running as root: the case cannot be built here.
        }
        assert!(
            meta.mode() & 0o044 != 0,
            "fixture must be readable by others"
        );
        // It is refused for its size or its lines, never for its mode.
        if let Err(e) = read_password_file(path, "--archive-password-file") {
            assert!(!e.contains("chmod 600"), "{e}");
        }
    }

    #[test]
    fn a_command_line_splits_like_a_shell_without_one() {
        assert_eq!(
            split_command(r#"pass show 'pcaps/lab one' "x\"y" a\ b"#).expect("split"),
            vec!["pass", "show", "pcaps/lab one", "x\"y", "a b"]
        );
        assert!(split_command("  ").is_err());
        assert!(split_command("echo 'open").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_command_supplies_its_first_line() {
        let secret = crate::test_material::key_str("command");
        let cmd = format!("printf '%s\\nsecond\\n' '{secret}'");
        let got = run_password_command(&cmd, Duration::from_secs(10), true).expect("runs");
        assert_eq!(got.expose(), secret.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_command_is_an_error_without_its_output() {
        let secret = crate::test_material::key_str("failing");
        let cmd = format!("sh -c 'echo {secret}; exit 3'");
        let err = run_password_command(&cmd, Duration::from_secs(10), true).expect_err("fails");
        assert!(err.contains("'sh' failed"), "{err}");
        assert!(
            !err.contains(secret),
            "the output must not be in the message: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_is_bounded_in_time_and_in_output() {
        let started = std::time::Instant::now();
        let err = run_password_command("sleep 30", Duration::from_millis(300), true)
            .expect_err("times out");
        assert!(err.contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let err = run_password_command("yes", Duration::from_secs(10), true).expect_err("too much");
        assert!(err.contains("more than"), "{err}");
    }

    #[test]
    fn sources_are_gathered_in_preference_order() {
        let dir = tempfile::tempdir().expect("tmp");
        let file = dir.path().join("pw");
        std::fs::write(
            &file,
            format!("{}\n", crate::test_material::key_str("s-file")),
        )
        .expect("w");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("m");
        }
        let creds = dir.path().join("creds");
        std::fs::create_dir(&creds).expect("mkdir");
        let cred = creds.join(CREDENTIAL_NAME);
        std::fs::write(&cred, crate::test_material::key_str("s-cred")).expect("w");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o400)).expect("m");
        }
        let cfg = SourceConfig {
            file: Some(file),
            command: Some(format!(
                "printf %s {}",
                crate::test_material::key_str("s-cmd")
            )),
            stdin: true,
            credentials_directory: Some(creds),
            environment: Some(crate::test_material::key_str("s-env").into()),
            inline: Some(crate::test_material::key_str("s-inline").into()),
            command_timeout: Some(Duration::from_secs(10)),
        };
        let stdin = format!("{}\nnot this\n", crate::test_material::key_str("s-stdin"));
        let got = collect(&cfg, &mut stdin.as_bytes()).expect("collect");
        let sources: Vec<Source> = got.iter().map(|c| c.source).collect();
        assert_eq!(
            sources,
            vec![
                Source::File,
                Source::Command,
                Source::Stdin,
                Source::Credential,
                Source::Environment,
                Source::CommandLine
            ]
        );
        for (c, label) in got
            .iter()
            .zip(["s-file", "s-cmd", "s-stdin", "s-cred", "s-env", "s-inline"])
        {
            assert_eq!(
                c.password.expose(),
                crate::test_material::key_str(label).as_bytes()
            );
        }
    }

    #[test]
    fn a_credentials_directory_without_the_credential_is_no_source() {
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = SourceConfig {
            credentials_directory: Some(dir.path().to_path_buf()),
            ..SourceConfig::default()
        };
        assert!(!cfg.any());
        assert!(collect(&cfg, &mut io::empty()).expect("collect").is_empty());
    }

    #[test]
    fn an_empty_environment_value_is_an_error() {
        let cfg = SourceConfig {
            environment: Some(OsString::new()),
            ..SourceConfig::default()
        };
        let err = collect(&cfg, &mut io::empty()).expect_err("empty");
        assert!(err.contains(ENV_VAR), "{err}");
    }

    /// `ü`, composed and decomposed, built from code points so no password
    /// literal appears here.
    fn umlaut_word(composed: bool) -> String {
        let base = crate::test_material::key_str("umlaut");
        let u = if composed { "\u{00fc}" } else { "u\u{0308}" };
        format!("{}{u}{}", &base[..6], &base[6..12])
    }

    #[test]
    fn non_ascii_passwords_get_every_spelling_and_ascii_one() {
        let ascii = pw("ascii");
        assert_eq!(variants(&ascii, Container::Zip, None).len(), 1);

        let nfd = ArchivePassword::from_bytes(umlaut_word(false).as_bytes()).expect("valid");
        let got = variants(&nfd, Container::Zip, None);
        let composed = umlaut_word(true);
        let mut cp437 = Vec::new();
        CodePage::Cp437
            .encode_into(&composed, &mut cp437)
            .expect("encodable");
        let mut cp1252 = Vec::new();
        CodePage::Cp1252
            .encode_into(&composed, &mut cp1252)
            .expect("encodable");
        let spellings: Vec<&[u8]> = got.iter().map(|v| v.as_slice()).collect();
        // Exact (NFD), NFC, then CP437 (which CP850 duplicates here), CP1252.
        assert_eq!(
            spellings,
            vec![
                umlaut_word(false).as_bytes(),
                composed.as_bytes(),
                &cp437[..],
                &cp1252[..]
            ]
        );
    }

    #[test]
    fn a_pinned_encoding_yields_exactly_one_spelling() {
        let p = ArchivePassword::from_bytes(umlaut_word(true).as_bytes()).expect("valid");
        let got = variants(&p, Container::Zip, Some(Encoding::Page(CodePage::Cp1252)));
        assert_eq!(got.len(), 1);
        assert!(got[0].contains(&0xfc));
        let got = variants(&p, Container::Zip, Some(Encoding::Utf8));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_slice(), umlaut_word(true).as_bytes());
    }

    /// A lock that opens only for `want`.
    fn lock_for(
        want: Vec<u8>,
        tries: std::rc::Rc<std::cell::Cell<u32>>,
    ) -> impl FnMut(&[u8]) -> Trial<()> {
        move |p: &[u8]| {
            tries.set(tries.get() + 1);
            if p == want.as_slice() {
                Trial::Opened(())
            } else {
                Trial::Wrong
            }
        }
    }

    fn candidate(label: &str) -> Candidate {
        Candidate {
            password: pw(label),
            source: Source::File,
        }
    }

    #[test]
    fn every_spelling_of_one_password_is_one_attempt() {
        let composed = umlaut_word(true);
        let mut cp437 = Vec::new();
        CodePage::Cp437
            .encode_into(&composed, &mut cp437)
            .expect("enc");
        let tries = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut lock = lock_for(cp437, tries.clone());
        let typed = ArchivePassword::from_bytes(composed.as_bytes()).expect("valid");
        let mut ring = Keyring::new(
            vec![Candidate {
                password: typed,
                source: Source::Prompt,
            }],
            None,
        );
        assert!(matches!(
            ring.unlock("a.zip", "m", Container::Zip, &mut lock),
            Unlock::Opened(())
        ));
        assert!(tries.get() > 1, "several spellings were tried");
        assert_eq!(ring.attempts(), 1, "but they were one attempt");
        assert_eq!(ring.wrong_attempts(), 0);
    }

    #[test]
    fn the_second_candidate_opens_and_is_remembered_for_that_archive_only() {
        let right = pw("right");
        let tries = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut lock = lock_for(right.expose().to_vec(), tries.clone());
        let mut ring = Keyring::new(vec![candidate("wrong"), candidate("right")], None);
        assert!(matches!(
            ring.unlock("a.zip", "m1", Container::Zip, &mut lock),
            Unlock::Opened(())
        ));
        assert_eq!(ring.attempts(), 2);
        // The next member of the same archive: the remembered one, first.
        let before = ring.attempts();
        assert!(matches!(
            ring.unlock("a.zip", "m2", Container::Zip, &mut lock),
            Unlock::Opened(())
        ));
        assert_eq!(
            ring.attempts() - before,
            1,
            "remembered password tried first"
        );
        // Another archive is not offered a.zip's remembered password first.
        let mut ring2 = Keyring::new(vec![candidate("wrong")], None);
        ring2.remembered.insert("a.zip".into(), right.clone());
        assert!(matches!(
            ring2.unlock("b.zip", "m", Container::Zip, &mut lock),
            Unlock::WrongPassword
        ));
    }

    #[test]
    fn no_password_and_wrong_password_are_told_apart() {
        let tries = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut lock = lock_for(b"x".to_vec(), tries);
        let mut none = Keyring::default();
        assert!(matches!(
            none.unlock("a.zip", "m", Container::Zip, &mut lock),
            Unlock::NoPassword
        ));
        let mut wrong = Keyring::new(vec![candidate("nope")], None);
        assert!(matches!(
            wrong.unlock("a.zip", "m", Container::Zip, &mut lock),
            Unlock::WrongPassword
        ));
        assert_eq!(wrong.wrong_attempts(), 1);
    }

    /// Answers from a script, and records what it was asked.
    struct Scripted {
        answers: std::collections::VecDeque<Option<ArchivePassword>>,
        asked: std::sync::Arc<parking_lot::Mutex<Vec<PromptRequest>>>,
    }

    impl Prompter for Scripted {
        fn ask(&mut self, request: &PromptRequest) -> PromptAnswer {
            self.asked.lock().push(request.clone());
            match self.answers.pop_front().flatten() {
                Some(pw) => PromptAnswer::Password(pw),
                None => PromptAnswer::Skip,
            }
        }
    }

    #[test]
    fn a_prompt_gets_three_attempts_per_archive_then_gives_up() {
        let tries = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut lock = lock_for(pw("never").expose().to_vec(), tries);
        let asked = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut ring = Keyring::default();
        ring.set_prompter(Some(Box::new(Scripted {
            answers: (0..5).map(|i| Some(pw(&format!("guess{i}")))).collect(),
            asked: asked.clone(),
        })));
        assert!(matches!(
            ring.unlock("a.zip", "m1", Container::Zip, &mut lock),
            Unlock::WrongPassword
        ));
        // The archive's prompts are spent: its next member is not asked about.
        assert!(matches!(
            ring.unlock("a.zip", "m2", Container::Zip, &mut lock),
            Unlock::WrongPassword
        ));
        let asked = asked.lock();
        assert_eq!(asked.len(), 3);
        assert_eq!(
            asked
                .iter()
                .map(|r| (r.attempt, r.after_wrong))
                .collect::<Vec<_>>(),
            vec![(1, false), (2, true), (3, true)]
        );
        assert!(asked.iter().all(|r| r.of == PROMPT_ATTEMPTS));
    }

    #[test]
    fn an_empty_entry_skips_the_archive() {
        let tries = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut lock = lock_for(b"x".to_vec(), tries.clone());
        let asked = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut ring = Keyring::default();
        ring.set_prompter(Some(Box::new(Scripted {
            answers: vec![None].into(),
            asked: asked.clone(),
        })));
        assert!(matches!(
            ring.unlock("a.zip", "m1", Container::Zip, &mut lock),
            Unlock::NoPassword
        ));
        assert!(matches!(
            ring.unlock("a.zip", "m2", Container::Zip, &mut lock),
            Unlock::NoPassword
        ));
        assert_eq!(
            asked.lock().len(),
            1,
            "skipping asks no more about that archive"
        );
        assert_eq!(tries.get(), 0);
    }

    #[test]
    fn the_zipcrypto_warning_prints_once_per_archive() {
        let name = format!("once-{}.zip", crate::test_material::key_str("zc-once"));
        assert!(warn_zipcrypto_once(&name));
        assert!(!warn_zipcrypto_once(&name));
        let text = zipcrypto_warning(&name);
        assert!(
            text.contains("bkcrack") && text.contains("AES-256"),
            "{text}"
        );
    }
}
