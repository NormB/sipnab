//! Reading uprobe records through `perf_event_open` rather than `trace_pipe`.
//!
//! It needs `libc`, and so is gated on `native` rather than the whole module
//! being gated: `elf` and `record` are pure byte arithmetic and stay testable
//! in feature combinations that carry no `libc` at all.
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
            // interruption and is really a mis-marshaled argument.
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

    // ── The ring walk, over a file standing in for the kernel ────────────
    //
    // Opening a real ring needs CAP_PERFMON (or perf_event_paranoid <= -1) and
    // a live tracepoint, and neither exists where CI measures coverage. The
    // walk does not care: it reads `data_head`/`data_tail` at their ABI
    // offsets and records out of a power-of-two data area one page in, and a
    // regular file mapped the same way presents exactly that. Only the
    // kernel's half -- the producer -- is replaced; see `fake`.

    use super::fake;

    /// The one thing the reader is for: the tracepoint's own bytes, and no
    /// more of the record than the kernel said they occupy.
    #[test]
    fn a_sample_delivers_exactly_its_raw_payload() {
        let records = fake::sample(b"INVITE sip:b@x SIP/2.0");
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        let n = ring.drain(|raw| got.push(raw.to_vec()));

        assert_eq!(n, 1, "one sample, one delivery");
        assert_eq!(got, vec![b"INVITE sip:b@x SIP/2.0".to_vec()]);
        assert!(
            records.len() > 8 + 4 + got[0].len(),
            "the fixture really does carry alignment padding past the payload, \
             so an equal length above proves the padding was cut"
        );
    }

    /// Consumed space is handed back: the kernel may not reuse what `data_tail`
    /// does not cover, so a reader that forgot to publish it would stall the
    /// ring once it filled.
    #[test]
    fn draining_publishes_the_tail_up_to_the_head() {
        let mut records = fake::sample(b"one");
        records.extend(fake::sample(b"two"));
        let (mut ring, _file) = fake::ring(1, 0, &records);
        assert_eq!(ring.tail(), 0);

        ring.drain(|_| {});

        assert_eq!(
            ring.tail(),
            records.len() as u64,
            "everything read must be released to the kernel"
        );
        assert_eq!(ring.tail(), ring.head());
    }

    #[test]
    fn records_are_delivered_in_ring_order() {
        let mut records = Vec::new();
        for m in [&b"first"[..], b"second", b"third"] {
            records.extend(fake::sample(m));
        }
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 3);
        assert_eq!(
            got,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    /// An empty ring is the common case on a quiet trunk. It must deliver
    /// nothing and must not move the tail.
    #[test]
    fn an_empty_ring_delivers_nothing() {
        let (mut ring, _file) = fake::ring(1, 64, &[]);
        assert_eq!(ring.drain(|_| panic!("nothing was written")), 0);
        assert_eq!(ring.tail(), 64, "no record, no movement");
    }

    /// `PERF_RECORD_LOST` is evidence that the capture has a hole in it. It is
    /// counted, summed across records, and never handed on as a payload.
    #[test]
    fn a_lost_record_is_counted_and_never_delivered() {
        let mut records = fake::lost(0xABCD, 7);
        records.extend(fake::sample(b"after the gap"));
        records.extend(fake::lost(0xABCD, 5));
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        let n = ring.drain(|raw| got.push(raw.to_vec()));

        assert_eq!(n, 1, "a lost record is not a record");
        assert_eq!(got, vec![b"after the gap".to_vec()]);
        assert_eq!(
            ring.lost(),
            12,
            "the COUNT field is summed, not the id and not the record count"
        );
    }

    /// Record types this reader has no use for (mmap, comm, throttle, ...) are
    /// stepped over by their own size, or everything after them is lost.
    #[test]
    fn an_unknown_record_type_is_stepped_over() {
        let mut records = fake::record(99, &[0xEE; 8]);
        records.extend(fake::sample(b"still read"));
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 1);
        assert_eq!(got, vec![b"still read".to_vec()]);
        assert_eq!(ring.tail(), records.len() as u64);
    }

    /// A header claiming fewer than its own eight bytes would never advance
    /// the walk, which would spin forever. It stops there instead, keeping
    /// everything before it and releasing nothing past it.
    #[test]
    fn a_record_too_short_to_advance_stops_the_walk_where_it_stands() {
        let mut records = fake::sample(b"kept");
        let stuck_at = records.len() as u64;
        records.extend(fake::header(PERF_RECORD_SAMPLE, 0));
        records.extend(fake::sample(b"unreachable"));
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        let n = ring.drain(|raw| got.push(raw.to_vec()));

        assert_eq!(n, 1);
        assert_eq!(got, vec![b"kept".to_vec()]);
        assert_eq!(
            ring.tail(),
            stuck_at,
            "the tail stops at the record it could not read"
        );
    }

    /// A raw length larger than the record that carries it is refused rather
    /// than read past: the bytes beyond belong to the next record.
    #[test]
    fn a_raw_length_larger_than_its_record_is_not_delivered() {
        let mut lying = fake::sample(b"abcd");
        lying[8..12].copy_from_slice(&1000u32.to_le_bytes());
        let mut records = lying;
        records.extend(fake::sample(b"next"));
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 1);
        assert_eq!(
            got,
            vec![b"next".to_vec()],
            "only the honest record arrives, and the walk carries on past the \
             lying one by its header size"
        );
    }

    /// The kernel writes a record across the end of the data area when that is
    /// where the head happens to be. Reading it must stitch the two halves, not
    /// return the bytes that happen to sit past the end of the mapping.
    #[test]
    fn a_record_that_wraps_the_end_of_the_ring_is_reassembled() {
        let data_size = fake::page() as u64;
        let payload = b"INVITE sip:wrapped@x SIP/2.0 -- long enough to straddle";
        let records = fake::sample(payload);
        // Start 16 bytes before the end, so the header and the length fit and
        // the payload is split between the last bytes and the first.
        let start = data_size - 16;
        assert!(start + (records.len() as u64) > data_size, "must straddle");
        let (mut ring, _file) = fake::ring(1, start, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 1);
        assert_eq!(got, vec![payload.to_vec()]);
    }

    /// Positions are absolute and grow forever; only their low bits address
    /// the data area. A reader that indexed with the raw position would read
    /// outside the mapping after the first lap.
    #[test]
    fn positions_past_the_first_lap_address_the_same_ring() {
        let data_size = fake::page() as u64;
        let records = fake::sample(b"third lap");
        let (mut ring, _file) = fake::ring(1, 3 * data_size + 40, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 1);
        assert_eq!(got, vec![b"third lap".to_vec()]);
        assert_eq!(ring.tail(), 3 * data_size + 40 + records.len() as u64);
    }

    /// The descriptor handed out for polling is the ring's own, not a copy or
    /// a stand-in: polling anything else would never wake.
    #[test]
    fn the_polling_descriptor_is_the_rings_own() {
        let (ring, _file) = fake::ring(2, 0, &[]);
        let dup = ring
            .as_fd()
            .try_clone_to_owned()
            .expect("a live descriptor duplicates");
        let len = std::fs::File::from(dup).metadata().expect("fstat").len();
        assert_eq!(
            len as usize,
            fake::page() * 3,
            "the file the ring was mapped from: one metadata page, two data"
        );
    }

    /// The kernel sizes the data area in pages and requires a power of two.
    /// Asked for anything else, mapping refuses rather than mapping a ring
    /// the index mask would read outside of.
    #[test]
    #[should_panic(expected = "power-of-two")]
    fn a_data_area_that_is_not_a_power_of_two_is_refused() {
        let file = tempfile::tempfile().unwrap();
        file.set_len((fake::page() * 4) as u64).unwrap();
        let _ = PerfRing::map(OwnedFd::from(file), 3);
    }

    /// A sample whose header claims no room for its own length field carries
    /// no payload. It is stepped over, not read as a zero-length payload.
    #[test]
    fn a_sample_too_short_to_carry_its_length_is_stepped_over() {
        let mut records = fake::header(PERF_RECORD_SAMPLE, 8);
        records.extend(fake::sample(b"after"));
        let (mut ring, _file) = fake::ring(1, 0, &records);

        let mut got = Vec::new();
        assert_eq!(ring.drain(|raw| got.push(raw.to_vec())), 1);
        assert_eq!(got, vec![b"after".to_vec()]);
    }

    /// A mapping the kernel refuses is reported with its errno rather than
    /// handed back as a ring over memory that is not there. A read-only file
    /// cannot be mapped shared and writable, so the kernel refuses with EACCES.
    #[test]
    fn a_mapping_the_kernel_refuses_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ring");
        std::fs::write(&path, vec![0u8; fake::page() * 2]).unwrap();
        let read_only = std::fs::File::open(&path).unwrap();
        let err = match PerfRing::map(OwnedFd::from(read_only), 1) {
            Ok(_) => panic!("a read-only descriptor cannot back a writable shared map"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EACCES), "{err}");
    }

    /// An open the kernel refuses is reported as the syscall's OWN error, not
    /// the placeholder the loop starts from and not a success.
    ///
    /// `u64::MAX` is an event id no tracepoint carries, so this refuses on
    /// every host and at every privilege level: unprivileged it is refused by
    /// `perf_event_paranoid` (EACCES) before the id is looked at, and with
    /// privileges `perf_trace_init` finds no tracepoint of that type
    /// (EINVAL/ENOENT). Nothing is opened, so nothing is captured. The
    /// SUCCESS arm of `open` is the part no unprivileged test can reach.
    #[test]
    fn an_event_id_no_tracepoint_carries_is_refused_with_the_kernels_own_error() {
        let err = match PerfRing::open(u64::MAX, 0, 1) {
            Ok(_) => panic!("no tracepoint has id u64::MAX"),
            Err(e) => e,
        };
        assert!(
            err.raw_os_error().is_some(),
            "the error must be the kernel's errno, not the loop's placeholder: {err}"
        );
        assert!(
            !err.to_string().contains("no attr size was attempted"),
            "{err}"
        );
    }
}

/// A file standing in for the kernel's side of a perf ring, for tests.
///
/// The layout is the ABI the reader walks: a metadata page whose `data_head`
/// and `data_tail` sit at [`MMAP_DATA_HEAD`] and [`MMAP_DATA_TAIL`], then a
/// power-of-two data area of whole pages. Records are written the way the
/// kernel writes them -- an eight-byte header whose size covers the record,
/// padded to eight bytes -- and wrap at the end of the data area.
///
/// Visible to the rest of `uprobe` so the reader's tests can drive a whole
/// drain without a perf descriptor.
#[cfg(test)]
pub(super) mod fake {
    use super::*;
    use std::os::unix::fs::FileExt;

    /// This host's page size, which is what the data area is measured in.
    pub(in crate::capture::uprobe) fn page() -> usize {
        crate::capture::mapped::page_size()
    }

    /// A header of `ev_type` claiming `size` bytes in total.
    pub(in crate::capture::uprobe) fn header(ev_type: u32, size: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(&ev_type.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // misc
        h.extend_from_slice(&size.to_le_bytes());
        h
    }

    /// A record of `ev_type` carrying `body`, padded to eight bytes.
    pub(in crate::capture::uprobe) fn record(ev_type: u32, body: &[u8]) -> Vec<u8> {
        let size = (8 + body.len()).next_multiple_of(8);
        let mut r = header(ev_type, u16::try_from(size).expect("fixture record fits"));
        r.extend_from_slice(body);
        r.resize(size, 0);
        r
    }

    /// A `PERF_RECORD_SAMPLE` whose `PERF_SAMPLE_RAW` body is `raw`.
    pub(in crate::capture::uprobe) fn sample(raw: &[u8]) -> Vec<u8> {
        let mut body = u32::try_from(raw.len())
            .expect("fixture payload fits")
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(raw);
        record(PERF_RECORD_SAMPLE, &body)
    }

    /// A `PERF_RECORD_LOST`: `{ u64 id, u64 lost }`.
    pub(in crate::capture::uprobe) fn lost(id: u64, count: u64) -> Vec<u8> {
        let mut body = id.to_le_bytes().to_vec();
        body.extend_from_slice(&count.to_le_bytes());
        record(PERF_RECORD_LOST, &body)
    }

    /// A ring of `data_pages` holding `records` from absolute position `start`.
    ///
    /// Returns the file as well, still open, so a test can append more records
    /// after a first drain with [`append`].
    pub(in crate::capture::uprobe) fn ring(
        data_pages: usize,
        start: u64,
        records: &[u8],
    ) -> (PerfRing, std::fs::File) {
        let file = tempfile::tempfile().expect("an anonymous file");
        file.set_len((page() * (data_pages + 1)) as u64)
            .expect("size the file");
        file.write_at(&start.to_le_bytes(), MMAP_DATA_TAIL as u64)
            .expect("write data_tail");
        file.write_at(&start.to_le_bytes(), MMAP_DATA_HEAD as u64)
            .expect("write data_head");
        let keep = file.try_clone().expect("a second handle");
        append(&keep, data_pages, records);
        let ring = PerfRing::map(OwnedFd::from(file), data_pages).expect("map the file");
        (ring, keep)
    }

    /// Write `records` at the current head, wrapping, then advance the head --
    /// the producer's side of the protocol, in the order the kernel does it.
    pub(in crate::capture::uprobe) fn append(
        file: &std::fs::File,
        data_pages: usize,
        records: &[u8],
    ) {
        let data_size = page() * data_pages;
        let mut head = [0u8; 8];
        file.read_exact_at(&mut head, MMAP_DATA_HEAD as u64)
            .expect("read data_head");
        let head = u64::from_le_bytes(head);
        let at = (head as usize) & (data_size - 1);
        let first = records.len().min(data_size - at);
        file.write_at(&records[..first], (page() + at) as u64)
            .expect("write before the end");
        file.write_at(&records[first..], page() as u64)
            .expect("write the wrapped rest");
        file.write_at(
            &(head + records.len() as u64).to_le_bytes(),
            MMAP_DATA_HEAD as u64,
        )
        .expect("advance data_head");
    }
}
