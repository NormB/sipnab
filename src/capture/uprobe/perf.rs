//! Reading uprobe records through `perf_event_open` rather than `trace_pipe`.
//!
//! `trace_pipe` is a **text** interface: the kernel formats every field into
//! ASCII and userspace parses it back. That is fine for a measurement by hand
//! and unfit for a host under load, which is where this feature is meant to
//! run. Perf hands over the record's own bytes instead, and the layout to read
//! them with comes from the kernel itself (see [`crate::capture::uprobe::record`]).
//!
//! `libc` does not declare `perf_event_attr`, so it is declared here. That is
//! hand-written kernel ABI, which is worth being nervous about — but the kernel
//! validates `attr.size` against the layouts it knows and returns `E2BIG` when
//! the caller claims a size it does not understand, so a mismatch is loud
//! rather than a silent misread. [`crate::capture::uprobe::perf::PerfRing::open`] uses that: it offers the
//! sizes the ABI has actually had, newest first, and takes the first the
//! running kernel accepts.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

/// `PERF_TYPE_TRACEPOINT`.
const PERF_TYPE_TRACEPOINT: u32 = 2;
/// `PERF_SAMPLE_RAW` — the tracepoint record's own bytes.
const PERF_SAMPLE_RAW: u64 = 1 << 10;
/// `PERF_RECORD_SAMPLE`.
const PERF_RECORD_SAMPLE: u32 = 9;
/// `PERF_RECORD_LOST` — the kernel dropped records because we read too slowly.
const PERF_RECORD_LOST: u32 = 2;

/// Published `perf_event_attr` sizes, newest first.
///
/// The kernel accepts a size it knows and rejects a larger one with `E2BIG`, so
/// offering these in order finds what the running kernel speaks without asking
/// its version.
const ATTR_SIZES: [u32; 5] = [136, 128, 112, 96, 64];

/// `perf_event_attr`, as much of it as sipnab sets.
///
/// Field order is kernel ABI and must not be reordered. `flags` is the
/// bitfield word. sipnab sets none of it: see [`crate::capture::uprobe::perf::PerfRing::open`] for why
/// `exclude_kernel` in particular must stay clear for a tracepoint.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    /// `PERF_TYPE_*`.
    type_: u32,
    /// Size of this struct, which is how the kernel detects a version skew.
    size: u32,
    /// For a tracepoint, the event id from `events/<group>/<name>/id`.
    config: u64,
    /// Sample every event.
    sample_period: u64,
    /// Which sample fields to include.
    sample_type: u64,
    /// Unused.
    read_format: u64,
    /// Bitfield word; see the struct docs.
    flags: u64,
    /// Wake a reader after this many events.
    wakeup_events: u32,
    /// Unused.
    bp_type: u32,
    /// Unused.
    config1: u64,
    /// Unused.
    config2: u64,
    /// Unused.
    branch_sample_type: u64,
    /// Unused.
    sample_regs_user: u64,
    /// Unused.
    sample_stack_user: u32,
    /// Unused.
    clockid: i32,
    /// Unused.
    sample_regs_intr: u64,
    /// Unused.
    aux_watermark: u32,
    /// Unused.
    sample_max_stack: u16,
    /// Unused.
    reserved_2: u16,
    /// Unused.
    aux_sample_size: u32,
    /// Unused.
    reserved_3: u32,
    /// Unused.
    sig_data: u64,
    /// Unused.
    config3: u64,
}

/// `perf_event_mmap_page`, first two fields plus the head and tail this reads.
///
/// Only the offsets sipnab touches are named; the page is far larger.
const MMAP_DATA_HEAD: usize = 1024;
/// Byte offset of `data_tail` within `perf_event_mmap_page`.
const MMAP_DATA_TAIL: usize = 1032;

/// One CPU's perf ring for a tracepoint.
pub struct PerfRing {
    /// The perf event, closed on drop.
    fd: OwnedFd,
    /// Base of the mapping: one metadata page followed by the data pages.
    base: *mut u8,
    /// Total mapped length, metadata page included.
    map_len: usize,
    /// Size of the data area, always a power of two.
    data_size: usize,
    /// Records the kernel dropped because this reader was too slow.
    lost: u64,
}

// SAFETY: the mapping is owned solely by this value; nothing else aliases it.
unsafe impl Send for PerfRing {}

impl PerfRing {
    /// Open and map one CPU's ring for tracepoint `event_id`.
    ///
    /// # Errors
    ///
    /// The syscall's own error, after trying each published `attr` size. A
    /// failure here is reported rather than downgraded: a capture that
    /// silently attached to nothing reads exactly like quiet traffic.
    pub fn open(event_id: u64, cpu: i32, data_pages: usize) -> io::Result<Self> {
        let mut last = io::Error::other("no attr size was attempted");
        for size in ATTR_SIZES {
            let mut attr = PerfEventAttr {
                type_: PERF_TYPE_TRACEPOINT,
                size,
                config: event_id,
                sample_period: 1,
                sample_type: PERF_SAMPLE_RAW,
                // Wake on every event: these are rare compared with packets,
                // and batching them would delay a dialog rather than save work.
                wakeup_events: 1,
                ..Default::default()
            };
            // No exclusion flags, and that is not an oversight. A uprobe is
            // placed on userspace code but the tracepoint FIRES IN KERNEL
            // CONTEXT, so `exclude_kernel` excludes the very event being asked
            // for. Setting it failed every open with EINTR, which reads as a
            // spurious interruption and is really the kernel refusing a request
            // for something that can never be sampled. An equivalent C program
            // setting no flags succeeded against the same tracepoint, which is
            // how the difference was found.
            attr.flags = 0;

            // Every argument is widened to `c_long` on purpose. `syscall` is
            // variadic and its wrapper reads each argument as a `long`; handing
            // it an `i32` leaves the upper half of that slot undefined, so the
            // kernel sees a garbage pid and cpu. Measured: passing `-1i32` here
            // failed with EINTR on every cpu, which reads as a spurious
            // interruption and is really a mis-marshalled argument.
            //
            // SAFETY: `attr` outlives the call; pid -1 with a cpu means
            // "every process on this cpu", which is what a library-wide uprobe
            // needs.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    std::ptr::addr_of!(attr) as libc::c_long,
                    -1 as libc::c_long,
                    libc::c_long::from(cpu),
                    -1 as libc::c_long,
                    0 as libc::c_long,
                )
            };
            if fd >= 0 {
                // SAFETY: the syscall returned a fresh descriptor we now own.
                let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
                return Self::map(fd, data_pages);
            }
            last = io::Error::last_os_error();
            // Anything but a size complaint will not be fixed by a smaller one.
            if last.raw_os_error() != Some(libc::E2BIG) {
                break;
            }
        }
        Err(last)
    }

    /// Map the ring: one metadata page plus `data_pages` (a power of two).
    fn map(fd: OwnedFd, data_pages: usize) -> io::Result<Self> {
        assert!(
            data_pages.is_power_of_two(),
            "the kernel requires a power-of-two data area"
        );
        // SAFETY: `sysconf` is always safe to call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let map_len = page * (data_pages + 1);
        // SAFETY: a fresh anonymous-shared mapping of the perf fd.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            base: base.cast::<u8>(),
            map_len,
            data_size: page * data_pages,
            lost: 0,
        })
    }

    /// The perf descriptor, for waiting on several rings at once.
    ///
    /// A caller with one ring per cpu polls these rather than spinning: the
    /// probe fires only when the application writes, which on a quiet trunk is
    /// rarely.
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Records the kernel dropped because this reader fell behind.
    ///
    /// Surfaced rather than counted silently: a capture that lost evidence must
    /// be able to say so.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Read the metadata page's head pointer.
    fn head(&self) -> u64 {
        // SAFETY: the metadata page is mapped and at least one page long.
        unsafe { std::ptr::read_volatile(self.base.add(MMAP_DATA_HEAD).cast::<u64>()) }
    }

    /// Read the tail pointer.
    fn tail(&self) -> u64 {
        // SAFETY: as `head`.
        unsafe { std::ptr::read_volatile(self.base.add(MMAP_DATA_TAIL).cast::<u64>()) }
    }

    /// Publish a new tail, telling the kernel the space is reusable.
    fn set_tail(&self, v: u64) {
        // SAFETY: as `head`. The fence orders our reads of the data area
        // before the kernel sees the space as free.
        unsafe {
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            std::ptr::write_volatile(self.base.add(MMAP_DATA_TAIL).cast::<u64>(), v);
        }
    }

    /// Copy `len` bytes out of the ring at `pos`, wrapping at the end.
    fn copy_out(&self, pos: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let start = (pos as usize) & (self.data_size - 1);
        let first = len.min(self.data_size - start);
        // SAFETY: the data area begins one page in and is `data_size` long;
        // both copies stay inside it by construction.
        unsafe {
            let data = self.base.add(self.map_len - self.data_size);
            std::ptr::copy_nonoverlapping(data.add(start), out.as_mut_ptr(), first);
            if first < len {
                std::ptr::copy_nonoverlapping(data, out.as_mut_ptr().add(first), len - first);
            }
        }
        out
    }

    /// Drain every record currently in the ring, handing each raw tracepoint
    /// payload to `on_record`.
    ///
    /// Returns how many records were delivered.
    pub fn drain<F: FnMut(&[u8])>(&mut self, mut on_record: F) -> usize {
        let head = self.head();
        let mut tail = self.tail();
        let mut seen = 0;

        while tail < head {
            let hdr = self.copy_out(tail, 8);
            let ev_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap_or_default());
            let size = u16::from_le_bytes(hdr[6..8].try_into().unwrap_or_default()) as usize;
            if size < 8 {
                // A zero-length record would spin this loop forever.
                break;
            }

            match ev_type {
                PERF_RECORD_SAMPLE => {
                    // PERF_SAMPLE_RAW: a u32 length, then that many bytes.
                    let body = self.copy_out(tail + 8, size - 8);
                    if body.len() >= 4 {
                        let raw_len =
                            u32::from_le_bytes(body[0..4].try_into().unwrap_or_default()) as usize;
                        if let Some(raw) = body.get(4..4 + raw_len) {
                            on_record(raw);
                            seen += 1;
                        }
                    }
                }
                PERF_RECORD_LOST => {
                    // Body is { u64 id, u64 lost }.
                    let body = self.copy_out(tail + 8, size - 8);
                    if body.len() >= 16 {
                        self.lost = self.lost.saturating_add(u64::from_le_bytes(
                            body[8..16].try_into().unwrap_or_default(),
                        ));
                    }
                }
                _ => {}
            }
            tail += size as u64;
        }

        self.set_tail(tail);
        seen
    }
}

impl Drop for PerfRing {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly what this value mapped.
        unsafe { libc::munmap(self.base.cast::<libc::c_void>(), self.map_len) };
    }
}

/// Read a probe's tracepoint id, which `perf_event_open` needs as its config.
///
/// # Errors
///
/// Propagates the read, and reports an unparsable id rather than defaulting to
/// zero — event id 0 is a real, different tracepoint.
pub fn event_id(tracefs: &std::path::Path, name: &str) -> io::Result<u64> {
    let path = tracefs.join(format!("events/uprobes/{name}/id"));
    let text = std::fs::read_to_string(path)?;
    text.trim()
        .parse::<u64>()
        .map_err(|e| io::Error::other(format!("tracepoint id for {name} is not a number: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel rejects an `attr.size` it does not know, so the list must be
    /// ordered newest first for the newest accepted size to win.
    #[test]
    fn attr_sizes_are_offered_newest_first() {
        let mut sorted = ATTR_SIZES;
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(
            ATTR_SIZES, sorted,
            "a smaller size would win first otherwise"
        );
    }

    /// The struct is kernel ABI; a Rust-side layout change would misread every
    /// field after it.
    #[test]
    fn the_attr_struct_is_at_least_as_large_as_the_sizes_offered() {
        assert!(
            std::mem::size_of::<PerfEventAttr>() >= ATTR_SIZES[0] as usize,
            "claiming a size larger than the struct would hand the kernel a \
             pointer to memory this does not own"
        );
    }

    #[test]
    fn an_unreadable_or_unparsable_id_is_an_error_not_a_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            event_id(dir.path(), "absent").is_err(),
            "missing id is an error"
        );

        let d = dir.path().join("events/uprobes/bad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("id"), "not-a-number").unwrap();
        assert!(
            event_id(dir.path(), "bad").is_err(),
            "event id 0 is a real, different tracepoint; defaulting to it would \
             read someone else's events"
        );
    }

    #[test]
    fn a_valid_id_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("events/uprobes/good");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("id"), "1815\n").unwrap();
        assert_eq!(event_id(dir.path(), "good").unwrap(), 1815);
    }
}
