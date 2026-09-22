// SPDX-License-Identifier: MIT OR Apache-2.0

//! The archive password prompt on `/dev/tty`.
//!
//! The prompt reads and writes the controlling terminal, never stdin and
//! stdout: stdin may be a pipe carrying something else, and stdout may be the
//! JSON a script is reading. That is how `getpass`, ssh and sudo behave. With
//! no controlling terminal (cron, CI, a detached agent) [`TtyPrompter::open`]
//! returns `None`, and there is no prompt and no hang.
//!
//! # The terminal always comes back
//!
//! While the operator types, the terminal is in raw mode: no echo, no line
//! editing by the kernel, and no signals from the keyboard. [`RawMode`]
//! restores what it found when it drops, on Enter, on an error, and on
//! Ctrl-C, which arrives as a byte this module handles rather than as a
//! signal that could kill the process with echo still off. A SIGTERM from
//! outside sets sipnab's shutdown flag, which the read loop checks between
//! keystrokes, so that way out restores the terminal too.

use std::io::Write;
use std::os::fd::AsRawFd;

use zeroize::Zeroizing;

use super::password::{ArchivePassword, MAX_PASSWORD_BYTES, PromptAnswer, PromptRequest, Prompter};

/// What one keystroke did to the line being typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Keep reading.
    More,
    /// Enter: the line is complete.
    Done,
    /// Ctrl-D on an empty line: end of input, the same as an empty entry.
    Eof,
    /// Ctrl-C: stop.
    Interrupt,
}

/// Apply one byte typed at the prompt to `line`.
///
/// Enter ends the line, Backspace removes the last byte, Ctrl-U clears the
/// line, Ctrl-C interrupts, and Ctrl-D ends input on an empty line. Anything
/// else is part of the password. `line` never grows past its capacity, which
/// the caller sets before the first byte: a byte past it is dropped and the
/// line marked too long, rather than the buffer reallocated.
pub fn feed(line: &mut Zeroizing<Vec<u8>>, too_long: &mut bool, byte: u8) -> Key {
    match byte {
        b'\r' | b'\n' => Key::Done,
        0x03 => Key::Interrupt,
        0x04 if line.is_empty() => Key::Eof,
        0x7f | 0x08 => {
            line.pop();
            Key::More
        }
        0x15 => {
            line.clear();
            *too_long = false;
            Key::More
        }
        b => {
            if line.len() < line.capacity() {
                line.push(b);
            } else {
                *too_long = true;
            }
            Key::More
        }
    }
}

/// The text of one prompt: archive, member and attempt, and a word about the
/// last attempt when it was wrong.
#[must_use]
pub fn prompt_text(request: &PromptRequest) -> String {
    let again = if request.after_wrong {
        "Wrong password. "
    } else {
        ""
    };
    format!(
        "{again}Password for {} (member {}, attempt {} of {}): ",
        request.archive, request.member, request.attempt, request.of
    )
}

/// `t` with echo, line editing and keyboard signals off, reading a byte at a
/// time. Output processing stays as it was, so the prompt's newline still
/// returns the cursor.
#[must_use]
pub fn raw(mut t: libc::termios) -> libc::termios {
    t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
    t.c_iflag &= !(libc::ICRNL | libc::IXON);
    t.c_cc[libc::VMIN] = 1;
    t.c_cc[libc::VTIME] = 0;
    t
}

/// Raw mode on a terminal, undone when dropped.
struct RawMode {
    /// The terminal.
    fd: libc::c_int,
    /// What it was set to before.
    saved: libc::termios,
}

impl RawMode {
    /// Put `fd` in raw mode.
    fn enter(fd: libc::c_int) -> std::io::Result<Self> {
        // SAFETY: a zeroed termios is a valid value for tcgetattr to fill.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an open descriptor, saved a valid termios.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let wanted = raw(saved);
        // SAFETY: fd is an open terminal, wanted a termios built from its own.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &wanted) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: fd is the terminal `enter` read `saved` from.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
    }
}

/// Asks for archive passwords on the controlling terminal.
#[derive(Debug)]
pub struct TtyPrompter {
    /// `/dev/tty`, open for reading and writing.
    tty: std::fs::File,
    /// Whether the operator allowed core dumps; a password typed then earns
    /// the warning a configured one does.
    allow_coredump: bool,
    /// Whether core dumps have been dealt with for a typed password yet.
    guarded: bool,
}

impl TtyPrompter {
    /// Open the controlling terminal, or `None` when there is none.
    #[must_use]
    pub fn open(allow_coredump: bool) -> Option<Self> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        Some(Self {
            tty,
            allow_coredump,
            guarded: false,
        })
    }

    /// Show `prompt` and read one line with echo off: the line, the key that
    /// ended it, and whether it overflowed.
    ///
    /// Raw mode goes on BEFORE the prompt is shown. Entering it discards
    /// typeahead, as `getpass` does, and anything typed once the prompt is
    /// visible must survive that.
    fn read_line(&mut self, prompt: &str) -> std::io::Result<(Zeroizing<Vec<u8>>, Key, bool)> {
        let fd = self.tty.as_raw_fd();
        let _raw = RawMode::enter(fd)?;
        self.tty.write_all(prompt.as_bytes())?;
        self.tty.flush()?;
        let mut line = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES));
        let mut too_long = false;
        let mut byte = Zeroizing::new([0u8; 1]);
        loop {
            if crate::signals::shutdown_requested() {
                return Ok((line, Key::Interrupt, too_long));
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd is one valid pollfd for an open descriptor.
            let ready = unsafe { libc::poll(&mut pfd, 1, 200) };
            if ready < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if ready == 0 {
                continue;
            }
            // SAFETY: byte is one writable byte.
            let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Ok((line, Key::Eof, too_long));
            }
            match feed(&mut line, &mut too_long, byte[0]) {
                Key::More => {}
                other => return Ok((line, other, too_long)),
            }
        }
    }

    /// Deal with core dumps before the first typed password is held.
    fn guard_core_dumps(&mut self) {
        if self.guarded {
            return;
        }
        self.guarded = true;
        if self.allow_coredump {
            tracing::warn!(
                "--allow-coredump: a core dump would contain the archive password this run \
                 holds"
            );
        } else if let Err(e) = crate::privilege::disable_core_dumps() {
            tracing::warn!("Could not keep the typed archive password out of a core dump: {e}");
        }
    }
}

impl Prompter for TtyPrompter {
    fn ask(&mut self, request: &PromptRequest) -> PromptAnswer {
        let read = self.read_line(&prompt_text(request));
        // The terminal is back in its own mode here: `read_line` dropped its
        // guard on the way out, however it left.
        let _ = writeln!(self.tty);
        let (line, key, too_long) = match read {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Could not read a password from the terminal: {e}");
                return PromptAnswer::Skip;
            }
        };
        match key {
            Key::Interrupt => {
                drop(line);
                tracing::warn!("Interrupted at the archive password prompt");
                super::release_run_and_exit(130);
            }
            Key::Eof | Key::More => PromptAnswer::Skip,
            Key::Done if too_long => {
                let _ = writeln!(
                    self.tty,
                    "That password is over {MAX_PASSWORD_BYTES} bytes; it was refused whole."
                );
                PromptAnswer::Skip
            }
            Key::Done => match ArchivePassword::from_bytes(&line) {
                Ok(pw) => {
                    self.guard_core_dumps();
                    PromptAnswer::Password(pw)
                }
                Err(_) => PromptAnswer::Skip,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(bytes: &[u8]) -> (Vec<u8>, Key, bool) {
        let mut line = Zeroizing::new(Vec::with_capacity(8));
        let mut too_long = false;
        let mut last = Key::More;
        for b in bytes {
            last = feed(&mut line, &mut too_long, *b);
            if last != Key::More {
                break;
            }
        }
        (line.to_vec(), last, too_long)
    }

    #[test]
    fn line_editing_keys_do_what_they_say() {
        assert_eq!(typed(b"ab\r"), (b"ab".to_vec(), Key::Done, false));
        assert_eq!(typed(b"xyz\x7fw\r"), (b"xyw".to_vec(), Key::Done, false));
        assert_eq!(typed(b"abc\x15xy\n"), (b"xy".to_vec(), Key::Done, false));
        assert_eq!(typed(b"ab\x03"), (b"ab".to_vec(), Key::Interrupt, false));
        assert_eq!(typed(b"\x04"), (Vec::new(), Key::Eof, false));
        // Ctrl-D mid-line is part of nothing special: it is a byte.
        assert_eq!(typed(b"a\x04\r"), (b"a\x04".to_vec(), Key::Done, false));
    }

    #[test]
    fn a_line_never_grows_past_its_buffer() {
        let (line, key, too_long) = typed(b"0123456789\r");
        assert_eq!(line, b"01234567");
        assert_eq!(key, Key::Done);
        assert!(too_long, "the overflow is reported, not silently cut");
    }

    #[test]
    fn raw_mode_turns_off_echo_line_mode_and_keyboard_signals() {
        // SAFETY: a zeroed termios is a valid value to build from.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        t.c_lflag = libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN | libc::ECHOE;
        let r = raw(t);
        assert_eq!(r.c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG), 0);
        assert_ne!(r.c_lflag & libc::ECHOE, 0, "unrelated flags are kept");
        assert_eq!(r.c_cc[libc::VMIN], 1);
    }

    #[test]
    fn the_prompt_names_archive_member_and_attempt() {
        let mut req = PromptRequest {
            archive: "evidence.zip".into(),
            member: "voip/call3.pcap".into(),
            attempt: 1,
            of: 3,
            after_wrong: false,
        };
        assert_eq!(
            prompt_text(&req),
            "Password for evidence.zip (member voip/call3.pcap, attempt 1 of 3): "
        );
        req.attempt = 2;
        req.after_wrong = true;
        assert!(prompt_text(&req).starts_with("Wrong password. Password for"));
    }
}
