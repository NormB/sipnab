//! Where TLS keylog bytes come from, and nothing about what they mean.
//!
//! A file, a FIFO, or a descriptor inherited from a supervisor.
//!
//! [`TlsDecryptor`](crate::capture::decrypt::TlsDecryptor) used to reach for the keylog
//! file itself, with a stat-size-and-seek that could not survive a producer
//! which truncates or replaces the file, and could not read a FIFO at all. That
//! logic lives here now, behind one type, so a live secrets producer — an eBPF
//! tool extracting master secrets from a running SIP daemon — is an ordinary
//! input rather than a special case.

use anyhow::Result;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Why a source restarted from byte zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCause {
    /// Same inode, fewer bytes: the producer truncated in place.
    Truncated,
    /// Different inode: the producer renamed or recreated the file.
    Replaced,
}

/// The result of one poll. `lines` holds whole lines only.
#[derive(Debug, Default)]
pub struct PollOutcome {
    /// Complete keylog lines, each still carrying its trailing newline.
    pub lines: String,
    /// Set when this poll restarted from the beginning of the file.
    pub reset: Option<ResetCause>,
}

/// A file identity that survives rotation, so a new file is never read at the
/// previous file's offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    /// Device number, so two files with the same inode on different mounts
    /// are not confused for one.
    dev: u64,
    /// Inode number, which changes when a producer rotates by rename-and-create.
    ino: u64,
}

/// How this source reads, chosen once at open time.
enum Mode {
    /// A regular file, resumed by identity and offset rather than by size.
    File {
        /// Stat'ed on every poll and compared against the held handle, so a
        /// replaced path is noticed.
        path: PathBuf,
        /// The handle actually read from, held open across polls.
        ///
        /// Holding it open is what makes identity trustworthy: an open
        /// descriptor pins the inode, so the filesystem cannot hand the same
        /// inode number to the producer's replacement file. Without this, a
        /// delete-and-recreate that reuses the inode is indistinguishable from
        /// an append, and the replacement gets read at the old file's offset.
        handle: Option<std::fs::File>,
        /// Identity of `handle`, or `None` before the first successful open.
        id: Option<FileId>,
        /// Bytes already handed to the framer from the current file.
        consumed: u64,
    },
    /// A FIFO or an inherited descriptor. Never stat'd: a pipe's length is
    /// always zero, which is what made a size comparison unable to see queued
    /// bytes at all.
    #[cfg(unix)]
    Stream {
        /// Held open for the life of the source, in non-blocking mode.
        fd: std::os::fd::OwnedFd,
        /// Set once every writer has closed, so a dead producer is not polled.
        exhausted: bool,
    },
}

/// A source of NSS `SSLKEYLOGFILE` lines.
pub struct KeylogSource {
    /// File or stream, decided at open time and never changed.
    mode: Mode,
    /// A trailing line the producer has not finished writing. Holds key
    /// material, so it is zeroized on drop.
    partial: String,
}

impl Drop for KeylogSource {
    fn drop(&mut self) {
        self.partial.zeroize();
    }
}

impl KeylogSource {
    /// Open a keylog path in file mode.
    pub fn open_file(path: &Path) -> Result<Self> {
        Ok(Self {
            mode: Mode::File {
                path: path.to_path_buf(),
                handle: None,
                id: None,
                consumed: 0,
            },
            partial: String::new(),
        })
    }

    /// Open a regular file positioned at its current end.
    ///
    /// For callers that have just read the existing contents themselves and
    /// want only what arrives next, without re-parsing what they already hold.
    pub fn open_file_at_end(path: &Path) -> Result<Self> {
        let (id, consumed) = match std::fs::metadata(path) {
            Ok(meta) => (Some(file_id(&meta)), meta.len()),
            Err(_) => (None, 0),
        };
        Ok(Self {
            mode: Mode::File {
                path: path.to_path_buf(),
                handle: None,
                id,
                consumed,
            },
            partial: String::new(),
        })
    }

    /// Whether a path is a FIFO, and so must never be read with a blocking
    /// whole-file read.
    ///
    /// Callers need this *before* they touch the path: opening a FIFO
    /// `O_RDONLY` blocks until a writer appears, so an eager "load the existing
    /// contents" pass would hang the process rather than return empty.
    pub fn is_fifo(path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            std::fs::metadata(path).is_ok_and(|m| m.file_type().is_fifo())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }

    /// Open a path, streaming it when it is a FIFO and reading it as a file
    /// otherwise. This is what lets `--keylog /run/sip.keys` accept a pipe from
    /// a privileged producer with no change in spelling.
    pub fn open_auto(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        if Self::is_fifo(path) {
            return Self::open_fifo(path);
        }
        Self::open_file(path)
    }

    /// `O_RDONLY | O_NONBLOCK`.
    ///
    /// The non-blocking flag is the whole fix: on a FIFO it makes `open` return
    /// immediately with no writer present, where a plain `O_RDONLY` open blocks
    /// until one appears — inside the sweep loop that also drives dialog expiry
    /// and output flushing.
    #[cfg(unix)]
    fn open_fifo(path: &Path) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `raw` is a fresh descriptor this function exclusively owns.
        let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        Ok(Self {
            mode: Mode::Stream {
                fd,
                exhausted: false,
            },
            partial: String::new(),
        })
    }

    /// Take an already-open descriptor, as inherited from a supervisor that
    /// started the privileged producer.
    ///
    /// # The caller's descriptor is left exactly as it was
    ///
    /// It is duplicated, and **the duplicate's status flags are not touched**.
    /// An earlier version set `O_NONBLOCK` on the duplicate and claimed that
    /// left the original alone; it did not. `dup` returns a distinct descriptor
    /// NUMBER, but both refer to one open-file description, and `O_NONBLOCK`
    /// belongs to that description — so a supervisor still reading the
    /// descriptor it lent sipnab began getting `EAGAIN` from a borrow. Proven
    /// by comparing `F_GETFL` before and after, which is the only way to see
    /// it: the two descriptors are unequal, so nothing about the call looks
    /// wrong.
    ///
    /// sipnab therefore reads whatever mode the caller chose. A blocking
    /// descriptor blocks, which is correct for the supervisor-fed pipe this
    /// exists for: the producer writes keys as sessions start, and a read that
    /// waits for them is the intended behavior rather than a busy loop.
    #[cfg(unix)]
    pub fn from_fd(fd: std::os::fd::RawFd) -> Result<Self> {
        // SAFETY: `dup` either returns a fresh owned descriptor or -1.
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Deliberately NOT `F_SETFL`. See the contract above: the flag would
        // land on the caller's descriptor too.
        let set = 0;
        if set < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: closing the descriptor this function just created.
            unsafe { libc::close(dup) };
            return Err(err.into());
        }
        // SAFETY: `dup` is owned here and not closed above on the success path.
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(dup) };
        Ok(Self {
            mode: Mode::Stream {
                fd: owned,
                exhausted: false,
            },
            partial: String::new(),
        })
    }

    /// True once a stream reached EOF and can never yield again.
    pub fn is_exhausted(&self) -> bool {
        match &self.mode {
            #[cfg(unix)]
            Mode::Stream { exhausted, .. } => *exhausted,
            Mode::File { .. } => false,
        }
    }

    /// Read whatever is new. Returns complete lines only; an unfinished
    /// trailing line is retained for the next call. Never blocks.
    pub fn poll(&mut self) -> Result<PollOutcome> {
        match &mut self.mode {
            Mode::File { .. } => self.poll_file(),
            #[cfg(unix)]
            Mode::Stream { .. } => self.poll_stream(),
        }
    }

    /// File mode: resume by identity and offset, resetting on rotation.
    fn poll_file(&mut self) -> Result<PollOutcome> {
        let Mode::File {
            path,
            handle,
            id,
            consumed,
        } = &mut self.mode
        else {
            return Ok(PollOutcome::default());
        };

        // What the path points at NOW. The handle below still pins whatever it
        // pointed at last time, so these two disagreeing is exactly the
        // rotation signal — and because the old inode is pinned, the producer's
        // replacement cannot be handed the same inode number and masquerade as
        // an append.
        let path_id = std::fs::metadata(&*path).ok().map(|m| file_id(&m));

        let replaced = match (*id, path_id) {
            (Some(held), Some(now)) => held != now,
            // The path is gone for the moment. Keep reading the handle we hold:
            // a producer that renames before recreating has not lost us data.
            (Some(_), None) => false,
            _ => false,
        };

        if handle.is_none() || replaced {
            match std::fs::File::open(&*path) {
                Ok(f) => {
                    *id = f.metadata().ok().map(|m| file_id(&m));
                    *handle = Some(f);
                    if replaced {
                        *consumed = 0;
                    }
                }
                Err(e) => {
                    tracing::debug!("keylog source: cannot open {}: {e}", path.display());
                    return Ok(PollOutcome::default());
                }
            }
        }

        let Some(file) = handle.as_mut() else {
            return Ok(PollOutcome::default());
        };

        let len = file.metadata()?.len();

        // Truncation is judged on the handle we are actually reading, so an
        // in-place truncate is seen even though the path never changed.
        let truncated = !replaced && len < *consumed;
        if truncated {
            *consumed = 0;
        }

        let reset = if replaced {
            Some(ResetCause::Replaced)
        } else if truncated {
            Some(ResetCause::Truncated)
        } else {
            None
        };

        if reset.is_some() {
            self.partial.zeroize();
            self.partial.clear();
        }

        let Mode::File {
            handle, consumed, ..
        } = &mut self.mode
        else {
            return Ok(PollOutcome::default());
        };
        let Some(file) = handle.as_mut() else {
            return Ok(PollOutcome::default());
        };

        if len <= *consumed {
            return Ok(PollOutcome {
                lines: String::new(),
                reset,
            });
        }

        // Bounded read: exactly the bytes observed at stat time. Reading to EOF
        // would consume bytes written during the read and then re-read them on
        // the next poll, which is where unbounded duplicate growth came from.
        let want = usize::try_from(len - *consumed).unwrap_or(usize::MAX);
        file.seek(SeekFrom::Start(*consumed))?;
        let mut buf = vec![0u8; want];
        let got = read_full(file, &mut buf)?;
        buf.truncate(got);
        *consumed += got as u64;

        let lines = self.frame(&buf);
        buf.zeroize();
        Ok(PollOutcome { lines, reset })
    }

    /// Stream mode: drain the descriptor until it would block or ends.
    #[cfg(unix)]
    fn poll_stream(&mut self) -> Result<PollOutcome> {
        use std::os::fd::AsRawFd;

        let Mode::Stream { fd, exhausted } = &mut self.mode else {
            return Ok(PollOutcome::default());
        };
        if *exhausted {
            return Ok(PollOutcome::default());
        }

        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            // SAFETY: `fd` is owned and open; `chunk` is a valid writable buffer.
            let n = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    chunk.as_mut_ptr().cast::<libc::c_void>(),
                    chunk.len(),
                )
            };
            if n > 0 {
                raw.extend_from_slice(&chunk[..n as usize]);
                continue;
            }
            if n == 0 {
                // Every writer closed. Not an error: the producer exited.
                *exhausted = true;
                break;
            }
            let err = std::io::Error::last_os_error();
            match err.kind() {
                // No writer yet, or nothing queued. Both are ordinary.
                std::io::ErrorKind::WouldBlock => break,
                std::io::ErrorKind::Interrupted => continue,
                _ => return Err(err.into()),
            }
        }
        chunk.zeroize();

        let lines = self.frame(&raw);
        raw.zeroize();
        Ok(PollOutcome { lines, reset: None })
    }

    /// Split raw bytes into whole lines, carrying an unfinished tail forward.
    fn frame(&mut self, buf: &[u8]) -> String {
        if buf.is_empty() && self.partial.is_empty() {
            return String::new();
        }
        let text = String::from_utf8_lossy(buf);
        let mut pending = std::mem::take(&mut self.partial);
        pending.push_str(&text);
        match pending.rfind('\n') {
            Some(cut) => {
                self.partial = pending[cut + 1..].to_string();
                pending.truncate(cut + 1);
                pending
            }
            None => {
                self.partial = pending;
                String::new()
            }
        }
    }
}

/// Read the device and inode that identify a file across rotation.
#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt;
    FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

/// Platforms without a stable inode identity detect rotation by shrink alone.
#[cfg(not(unix))]
fn file_id(_meta: &std::fs::Metadata) -> FileId {
    // No stable inode identity, so rotation is detected by shrink alone.
    FileId { dev: 0, ino: 0 }
}

/// Read until the buffer is full or the file ends.
///
/// A single `read` may return short without an error, which would otherwise
/// desynchronise the consumed offset from what was actually parsed.
fn read_full(f: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            got => n += got,
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// There is no `hex` crate in this tree, so encode by hand.
    fn hex32(b: u8) -> String {
        (0..32).map(|_| format!("{b:02x}")).collect()
    }

    /// A keylog line the real parser accepts, so the tests assert the effect —
    /// a usable secret arrived — rather than "some bytes moved".
    fn line(tag: u8) -> String {
        format!("CLIENT_TRAFFIC_SECRET_0 {} {}\n", hex32(tag), hex32(0x11))
    }

    #[cfg(unix)]
    fn mkfifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path living across the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn growing_file_yields_only_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl");
        std::fs::write(&path, line(1)).unwrap();

        let mut src = KeylogSource::open_file(&path).unwrap();
        let first = src.poll().unwrap();
        assert_eq!(first.lines.lines().count(), 1, "first poll reads the file");
        assert!(first.reset.is_none());

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(line(2).as_bytes()).unwrap();

        let second = src.poll().unwrap();
        assert_eq!(
            second.lines.lines().count(),
            1,
            "second poll reads ONLY the appended line, not the whole file"
        );
    }

    #[test]
    fn quiet_file_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl");
        std::fs::write(&path, line(1)).unwrap();
        let mut src = KeylogSource::open_file(&path).unwrap();
        src.poll().unwrap();
        assert!(
            src.poll().unwrap().lines.is_empty(),
            "no new bytes, no lines"
        );
    }

    #[test]
    fn truncation_resets_and_reloads_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl");
        std::fs::write(&path, format!("{}{}", line(1), line(2))).unwrap();

        let mut src = KeylogSource::open_file(&path).unwrap();
        assert_eq!(src.poll().unwrap().lines.lines().count(), 2);

        // The producer rotates by truncating in place and writing one new key.
        std::fs::write(&path, line(3)).unwrap();

        let out = src.poll().unwrap();
        assert!(
            matches!(out.reset, Some(ResetCause::Truncated)),
            "a shrink with the same inode is a truncation"
        );
        assert_eq!(
            out.lines.lines().count(),
            1,
            "the post-truncation key is DELIVERED, not skipped for the rest of the run"
        );
    }

    #[test]
    fn replacement_resets_and_reloads_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl");
        std::fs::write(&path, format!("{}{}", line(1), line(2))).unwrap();

        let mut src = KeylogSource::open_file(&path).unwrap();
        assert_eq!(src.poll().unwrap().lines.lines().count(), 2);

        // The producer rotates by rename-and-create: new inode, and longer than
        // the old file, so a size comparison alone reads it at a stale offset.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, format!("{}{}{}", line(3), line(4), line(5))).unwrap();

        let out = src.poll().unwrap();
        assert!(
            matches!(out.reset, Some(ResetCause::Replaced)),
            "a different inode is a replacement, not a growth"
        );
        assert_eq!(
            out.lines.lines().count(),
            3,
            "all three keys from the NEW file arrive, none read at a stale offset"
        );
    }

    #[test]
    fn a_line_split_across_polls_is_delivered_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl");
        let whole = line(1);
        let (head, tail) = whole.split_at(20);

        std::fs::write(&path, head).unwrap();
        let mut src = KeylogSource::open_file(&path).unwrap();
        assert!(
            src.poll().unwrap().lines.is_empty(),
            "a partial line is retained, never emitted half-formed"
        );

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(tail.as_bytes()).unwrap();

        let out = src.poll().unwrap();
        assert_eq!(
            out.lines, whole,
            "the completed line arrives intact, exactly once"
        );
        assert!(
            src.poll().unwrap().lines.is_empty(),
            "and is not delivered again"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_fifo_with_no_writer_returns_immediately() {
        // THE REGRESSION: `File::open` on a FIFO O_RDONLY blocks until a writer
        // appears, and this runs inside the packet sweep loop. Measured before
        // the fix: `timeout 2 cat kl.fifo` exits 124.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl.fifo");
        mkfifo(&path);

        let started = std::time::Instant::now();
        let mut src = KeylogSource::open_auto(&path).unwrap();
        let out = src.poll().unwrap();
        assert!(out.lines.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "opening and polling a writerless FIFO must not block the packet loop"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_fifo_delivers_keys_a_size_check_could_never_see() {
        // THE REGRESSION: a FIFO stats as length 0 however much is queued, so
        // `current_size <= last_keylog_size` held forever and returned Ok(0).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl.fifo");
        mkfifo(&path);

        let mut src = KeylogSource::open_auto(&path).unwrap();

        let mut w = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        w.write_all(line(7).as_bytes()).unwrap();
        w.flush().unwrap();

        let mut got = String::new();
        for _ in 0..50 {
            got.push_str(&src.poll().unwrap().lines);
            if !got.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            got.lines().count(),
            1,
            "the key written to the FIFO arrived"
        );
    }

    /// The whole point of `--keylog-fd`: a producer writes secrets into a pipe
    /// and the DECRYPTOR ends up holding them, with nothing on disk.
    ///
    /// Asserts the effect — `keylog_entry_count` rises — rather than that some
    /// bytes were read.
    #[test]
    #[cfg(unix)]
    fn secrets_sent_down_a_pipe_reach_the_decryptor() {
        use crate::capture::decrypt::TlsDecryptor;
        use std::os::fd::AsRawFd;

        let (read_fd, write_fd) = {
            let mut fds = [0i32; 2];
            // SAFETY: `fds` is a valid two-element array for `pipe` to fill.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            (fds[0], fds[1])
        };

        let mut decryptor =
            TlsDecryptor::new(None, crate::crypto::default_backend()).expect("decryptor");
        decryptor.set_keylog_source(KeylogSource::from_fd(read_fd).expect("adopt the read end"));
        assert_eq!(decryptor.keylog_entry_count(), 0, "nothing yet");

        // SAFETY: `read_fd` was duplicated by `from_fd`, so closing ours is safe.
        unsafe { libc::close(read_fd) };

        {
            // SAFETY: `write_fd` is a fresh descriptor this scope owns.
            let mut w = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(write_fd) };
            w.write_all(line(3).as_bytes()).unwrap();
            w.flush().unwrap();
            let _ = w.as_raw_fd();
        } // the writer closes here

        let mut loaded = 0;
        for _ in 0..50 {
            loaded += decryptor.poll_keylog_file().expect("poll");
            if loaded > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        assert_eq!(loaded, 1, "the secret written to the pipe was loaded");
        assert_eq!(
            decryptor.keylog_entry_count(),
            1,
            "and the decryptor holds it, with nothing written to disk"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_stream_reports_exhaustion_when_the_producer_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kl.fifo");
        mkfifo(&path);
        let mut src = KeylogSource::open_auto(&path).unwrap();

        {
            let mut w = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            w.write_all(line(8).as_bytes()).unwrap();
        } // the writer closes, so the next read sees EOF

        let mut got = String::new();
        for _ in 0..50 {
            got.push_str(&src.poll().unwrap().lines);
            if src.is_exhausted() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            got.lines().count(),
            1,
            "the last key is not lost to the EOF"
        );
        assert!(
            src.is_exhausted(),
            "a closed producer is reported, not polled forever"
        );
    }
}

#[cfg(all(test, unix, feature = "tls"))]
mod fd_contract_tests {
    use super::*;

    /// **The caller's descriptor must come back exactly as it went in.**
    ///
    /// `dup` returns a distinct descriptor NUMBER but both refer to the same
    /// open-file description, and `O_NONBLOCK` is a property of that
    /// description rather than of the number. So setting it on the duplicate
    /// sets it on the caller's too, and a supervisor that handed sipnab a
    /// descriptor it still reads starts getting `EAGAIN` from a borrow.
    ///
    /// Compares `F_GETFL` before and after, which is the only way to see it:
    /// the two descriptors are not equal, so nothing about the call LOOKS
    /// wrong.
    #[test]
    fn from_fd_does_not_change_the_callers_descriptor_flags() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.log");
        std::fs::write(&path, b"").expect("create");
        let file = std::fs::File::open(&path).expect("open");
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);

        // SAFETY: `fd` is open and owned by `file` for the whole test.
        let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(
            before >= 0,
            "F_GETFL failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            before & libc::O_NONBLOCK,
            0,
            "the fixture must start BLOCKING or this test proves nothing"
        );

        let source = KeylogSource::from_fd(fd).expect("from_fd");

        // SAFETY: as above.
        let after = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        drop(source);
        assert_eq!(
            after & libc::O_NONBLOCK,
            0,
            "from_fd set O_NONBLOCK on the CALLER's descriptor. `dup` shares the \
             open-file description, so F_SETFL on the duplicate changes both — \
             the doc comment promises the opposite"
        );
    }
}
