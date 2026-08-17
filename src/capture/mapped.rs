//! Reading a capture file through a mapping instead of through libpcap.
//!
//! # Why this exists
//!
//! The `--cores` reader is the one serial stage the whole design queues behind:
//! one thread reads, copies and host-pair-peeks every packet while N workers
//! wait. Reading through libpcap costs that thread a `read` into libpcap's
//! buffer AND a copy out of it, because `pcap::Capture::next_packet`
//! invalidates what it returns on the following call. Mapping the file removes
//! the first of those two: records are parsed in place out of page cache, and
//! only the frame itself is copied.
//!
//! Measured on the 535k-packet corpus (median-of-7, idle host), against the
//! same binary reading the same file through libpcap:
//!
//! | cores | mapped | libpcap |      |
//! |-------|--------|---------|------|
//! | 1     | 1.59M  | 1.60M   | —    |
//! | 2     | 2.19M  | 2.19M   | —    |
//! | 4     | 3.27M  | 2.38M   | +37% |
//! | 8     | 3.30M  | 2.18M   | +51% |
//!
//! Both columns come from one session on one binary. Repeated sessions put the
//! four-core libpcap figure between 2.30M and 2.38M, so read the four-core gain
//! as "high thirties to low forties percent" and the eight-core one as "about
//! half again"; the pair quoted is the least flattering measured.
//!
//! Read the one-core row as a CONTROL, not a result: `--cores 1` and a run with
//! no `--cores` at all use the single-threaded reader in
//! [`crate::capture::file`], which does not map, so that row is libpcap against
//! itself and its ~2% spread is the harness noise floor. Only `--cores 2` and
//! above reach this module. Two cores is within that floor; the gain arrives at
//! four, which is the point at which the serial reader is what the workers are
//! waiting on.
//!
//! It follows that the DEFAULT offline read does not benefit yet. Teaching
//! [`crate::capture::file`] to map as well is the obvious next step and is not
//! done here.
//!
//! Peak resident memory stays within ~10 MiB of the libpcap path, because
//! `release_behind` hands pages back as the read passes them; without it the
//! whole capture stays resident (213 MiB against 88 on this corpus).
//!
//! # What did NOT work, and why it is worth knowing
//!
//! The obvious form of this — hand each frame out as a refcounted slice of the
//! mapping, copying nothing at all — is SLOWER than libpcap: 1.88M against
//! 2.30M at four cores. One mapping means one atomic refcount, so 535k frames
//! cloned by the reader and dropped by the workers drive ~1M atomic updates
//! through a single cache line. It costs nothing on one core and 21% on four,
//! which is why an ablation that only removed the copy predicted a win that did
//! not exist. Copying into blocks spreads that refcounting across one counter
//! per ~270 frames and is what makes the mapping pay.
//!
//! `docs/internals/zero-copy-payloads.md` records the same lesson one stage
//! downstream: at these packet sizes the copy is not the cost, the cross-thread
//! refcount and allocator traffic is.
//!
//! # What it deliberately does not handle
//!
//! [`MappedPcap::open`] returns `Ok(None)` — not an error — for anything it
//! cannot read as a classic uncompressed pcap: pcapng, gzip, a named pipe, a
//! short or corrupt header. The caller falls back to libpcap and reads the
//! file the slow way, which is why declining is routine rather than a failure.
//! Growing this to cover every container libpcap reads would mean reimplementing
//! libpcap; the point is to be fast on the common case and absent otherwise.
//!
//! # Mapping hazard
//!
//! A mapping is a window onto a file, not a copy of it. If another process
//! *truncates* the file while it is mapped, touching a page past the new end
//! raises `SIGBUS` rather than returning short as a `read` would. Files that
//! only grow are safe: the mapping is a fixed length taken at open. This is the
//! standard trade every `mmap`-based reader makes, and it is why only regular
//! files are mapped — a pipe or character device is declined above.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use pcap_file::pcap::PcapParser;

/// One frame, read out of a mapped file.
#[derive(Debug, Clone)]
pub struct MappedFrame {
    /// Capture time, converted once here so callers need not know the file's
    /// timestamp resolution.
    pub timestamp: DateTime<Utc>,
    /// The frame, a refcounted slice of a shared block — NOT of the mapping.
    /// It outlives the mapped pages it was read from, which is what lets
    /// [`MappedPcap::release_behind`] give them back mid-read.
    pub data: Bytes,
    /// Bytes actually captured. Always equal to `data.len()`.
    pub caplen: usize,
    /// Bytes on the wire, which exceeds `caplen` for a snapped frame.
    pub origlen: usize,
}

/// A classic pcap file, mapped once and read front to back.
pub struct MappedPcap {
    /// The whole file, mapped. Records are parsed in place out of this and
    /// frames are copied from it; nothing borrows it past `next_frame`.
    whole: memmap2::Mmap,
    /// Holds the file header, which fixes the endianness every record is read
    /// with. It parses records out of a caller-supplied slice and keeps no
    /// position of its own, which is what `cursor` is for.
    parser: PcapParser,
    /// Offset of the next record. An offset rather than a `&[u8]` remainder
    /// because a struct holding a slice of its own field is self-referential.
    cursor: usize,
    /// libpcap's datalink number for this file, so callers stamp frames with
    /// the same link type the fallback reader would have reported.
    link_type: i32,
    /// Whether this file's fractional timestamps are microseconds or
    /// nanoseconds. Read from the magic once, applied per frame.
    ts_resolution: pcap_file::TsResolution,
    /// Frames are cut from this rather than allocated one at a time. See
    /// [`MappedPcap::cut_from_block`] for why the frames are copied here at all
    /// instead of borrowed straight from the mapping.
    block: bytes::BytesMut,
    /// How far the mapping has been handed back to the kernel. See
    /// [`MappedPcap::release_behind`].
    released: usize,
    /// Set when the file ended in the middle of a record: the bytes the last
    /// record claimed, and the bytes actually left. See
    /// [`MappedPcap::truncation`].
    truncated: Option<(u32, usize)>,
}

impl std::fmt::Debug for MappedPcap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedPcap")
            .field("len", &self.whole.len())
            .field("cursor", &self.cursor)
            .field("link_type", &self.link_type)
            .finish()
    }
}

impl MappedPcap {
    /// Block size frames are cut from. 64 KiB deliberately, not larger: a block
    /// stays alive until the last slice cut from it drops, so an oversized
    /// block keeps a whole span resident because one packet in it is still
    /// being processed.
    const BLOCK: usize = 64 * 1024;

    /// Map `path`, or return `Ok(None)` if it is not a classic pcap this can
    /// read. `Err` is reserved for the file being unreadable at all.
    pub fn open(path: &std::path::Path) -> std::io::Result<Option<Self>> {
        if mapping_disabled() {
            return Ok(None);
        }
        let file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        // Only regular files. A pipe or device has no stable length to map,
        // and mapping one either fails or invites the SIGBUS above.
        if !meta.is_file() || meta.len() == 0 {
            return Ok(None);
        }
        // A mapping of a file smaller than its own header cannot be a pcap.
        if meta.len() < 24 {
            return Ok(None);
        }

        // SAFETY: `mmap` is unsafe because the mapping aliases file contents
        // that another process could change underneath it. The hazard and the
        // reason it is accepted are documented at module level; `file` being a
        // regular file is checked above.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        // The read is strictly front-to-back, and the reader thread is the
        // stage the whole `--cores` design queues behind, so it must not stop
        // to fault a page in per 4 KiB of capture.
        let _ = mmap.advise(memmap2::Advice::Sequential);
        // The mapping is held directly rather than wrapped in a `Bytes`. No
        // frame outlives the read -- each is copied into a block -- so nothing
        // needs the mapping refcounted, and holding it plainly is what lets
        // `release_behind` hand consumed pages back.
        let whole = mmap;

        let Ok((rest, parser)) = PcapParser::new(&whole[..]) else {
            // pcapng, gzip, or not a capture at all. The caller falls back.
            return Ok(None);
        };
        let cursor = whole.len() - rest.len();
        let link_type = i32::try_from(u32::from(parser.header().datalink)).unwrap_or(-1);
        if link_type < 0 {
            return Ok(None);
        }

        let ts_resolution = parser.header().ts_resolution;
        Ok(Some(Self {
            whole,
            parser,
            cursor,
            link_type,
            ts_resolution,
            block: bytes::BytesMut::with_capacity(Self::BLOCK),
            released: 0,
            truncated: None,
        }))
    }

    /// libpcap's datalink number for this file.
    pub fn link_type(&self) -> i32 {
        self.link_type
    }

    /// The next frame, or `None` at end of file — including a file that ends
    /// mid-record, which is a clean stop rather than an error because captures
    /// are routinely cut off mid-write.
    pub fn next_frame(&mut self) -> Option<MappedFrame> {
        if self.cursor >= self.whole.len() {
            return None;
        }
        let rest = &self.whole[self.cursor..];
        // The RAW record deliberately, not `next_packet`.
        //
        // `next_packet` additionally rejects any record with
        // `orig_len > snaplen` -- but that inequality is the DEFINITION of a
        // snapped capture: record 96 bytes of a 1500-byte frame and the header
        // reads `incl_len 96, orig_len 1500`. libpcap reads such a file to the
        // end, so a reader that stops at the first snapped packet would
        // silently truncate the operator's capture while reporting success.
        // The raw form still bounds-checks the record against the buffer, which
        // is the only check that protects memory; the rest are opinions about
        // well-formedness that libpcap does not share.
        let Ok((remainder, raw)) = self.parser.next_raw_packet(rest) else {
            self.note_truncation();
            return None;
        };

        // Guard against a parser that hands back a remainder that did not
        // advance: without this a malformed record would spin forever.
        let consumed = rest.len().checked_sub(remainder.len())?;
        if consumed == 0 {
            return None;
        }
        self.cursor += consumed;

        // Copy the frame's position out before touching `self` mutably below:
        // `raw` borrows the mapping, which is a field of `self`.
        let (ts_sec, ts_frac, origlen) = (raw.ts_sec, raw.ts_frac, raw.orig_len as usize);
        let len = raw.data.len();
        let offset = self.offset_within_mapping(&raw.data);

        let data = match offset {
            Some(off) => self.cut_from_block(off, len),
            // An owned `Cow` from the parser: rare, but correctness first.
            None => Bytes::copy_from_slice(&raw.data),
        };
        self.release_behind();
        Some(MappedFrame {
            timestamp: self.frame_time(ts_sec, ts_frac),
            caplen: data.len(),
            origlen,
            data,
        })
    }

    /// Copy one frame out of the mapping into the shared block, returning the
    /// bytes just written.
    ///
    /// Why a copy, when the whole point of a mapping is to avoid one: handing
    /// out slices of the mapping itself makes every frame in the file share ONE
    /// atomic refcount. The reader clones it per frame and each worker drops it
    /// again, so a 535k-packet capture drives ~1M atomic updates through a
    /// single cache line, contended by every worker. Measured on the 535k
    /// corpus, that costs nothing on one core and 21% of four-core throughput
    /// (2.55M -> 1.88M pkts/s). Blocks spread the same refcounting across one
    /// counter per ~270 frames, and a block is untouched by any thread but the
    /// one still reading from it.
    ///
    /// The mapping still earns its place: this is ONE copy, out of page cache,
    /// where libpcap costs a `read` into its own buffer AND a copy out of it.
    fn cut_from_block(&mut self, offset: usize, len: usize) -> Bytes {
        // A frame larger than the block gets its own exact-sized one, so
        // `split_to` cannot outrun the capacity and one jumbo frame does not
        // force every later frame into a bigger block.
        if self.block.capacity() < len {
            self.block = bytes::BytesMut::with_capacity(Self::BLOCK.max(len));
        }
        // Disjoint fields: the block is written from the mapping, both borrowed
        // from `self` at once.
        self.block
            .extend_from_slice(&self.whole[offset..offset + len]);
        self.block.split_to(len).freeze()
    }

    /// Whether the file ended mid-record, and by how much: the byte count the
    /// final record claimed against the bytes actually present.
    ///
    /// A truncated capture is not an empty one — every whole record before the
    /// cut is real data — so the read stops rather than fails. But the operator
    /// has to be TOLD, because a capture cut off mid-write is missing the end
    /// of whatever it was recording, and "read in full" over a truncated file
    /// is a wrong answer dressed as a clean one. libpcap reports this, so a
    /// mapped read that stayed quiet would lose a diagnostic the fallback path
    /// gives for free.
    pub fn truncation(&self) -> Option<(u32, usize)> {
        self.truncated
    }

    /// Record that the file ran out mid-record, reading the length the last
    /// record header claimed so the report can name it.
    fn note_truncation(&mut self) {
        let rest = &self.whole[self.cursor..];
        if rest.is_empty() {
            return; // a clean end, not a truncation
        }
        if rest.len() < 16 {
            // Not even a whole record header left.
            self.truncated = Some((0, rest.len()));
            return;
        }
        // `incl_len` is the third u32 of the record header, in the file's byte
        // order -- the same field libpcap names in its own message.
        let raw = [rest[8], rest[9], rest[10], rest[11]];
        let incl_len = match self.parser.header().endianness {
            pcap_file::Endianness::Big => u32::from_be_bytes(raw),
            pcap_file::Endianness::Little => u32::from_le_bytes(raw),
        };
        self.truncated = Some((incl_len, rest.len() - 16));
    }

    /// Hand pages the read has passed back to the kernel, so resident memory
    /// stays flat instead of growing to the size of the capture.
    ///
    /// A mapping counts every page it has touched against the process, and a
    /// front-to-back read touches all of them, so reading a 123 MiB corpus left
    /// 123 MiB resident and a multi-gigabyte capture would leave all of it. The
    /// pages are clean and evictable, so this is not a leak — but "not a leak"
    /// is cold comfort on a box already under pressure, and an operator reading
    /// a large capture should not have to know that the number is harmless.
    ///
    /// Safe because frames are COPIED into blocks: once the cursor is past a
    /// byte, nothing in the program refers to that page. Dropping it costs
    /// nothing to re-read either, since the page cache still holds it.
    ///
    /// Released a chunk at a time rather than per frame: the call is a syscall,
    /// and one per packet would put it back on the serial reader that this
    /// whole change exists to unblock.
    fn release_behind(&mut self) {
        const CHUNK: usize = 8 * 1024 * 1024;
        // The REAL page size, not an assumed 4 KiB: `madvise` wants a
        // page-aligned offset, and aarch64 hosts run 16 KiB and 64 KiB pages
        // too. Guessing low would leave every call misaligned, and since the
        // result is deliberately ignored the hint would simply stop working
        // with nothing to show that it had.
        let page = page_size();
        // Round down, so a page still holding the current record is kept.
        let upto = (self.cursor / page) * page;
        if upto <= self.released || upto - self.released < CHUNK {
            return;
        }
        let len = upto - self.released;
        // SAFETY: `MADV_DONTNEED` is unsafe in general because a later read of
        // the freed range can observe different bytes than before. Here the
        // mapping is a READ-ONLY file mapping, so a re-faulted page is re-read
        // from the same file and cannot change; the range is strictly BEHIND
        // the cursor, which the read never revisits; and no borrow into it is
        // outstanding, because every frame was copied into a block before this
        // is reached. Best-effort: a kernel that refuses the hint costs only
        // memory.
        unsafe {
            let _ = self.whole.unchecked_advise_range(
                memmap2::UncheckedAdvice::DontNeed,
                self.released,
                len,
            );
        }
        self.released = upto;
    }

    /// Convert a record's seconds/fraction pair to an instant, honouring the
    /// file's timestamp resolution. A fraction too large for its unit is
    /// clamped rather than rejected: libpcap hands such a record to the caller,
    /// so dropping it here would lose a frame libpcap keeps.
    fn frame_time(&self, ts_sec: u32, ts_frac: u32) -> DateTime<Utc> {
        let nanos = match self.ts_resolution {
            pcap_file::TsResolution::MicroSecond => ts_frac.saturating_mul(1_000),
            pcap_file::TsResolution::NanoSecond => ts_frac,
        };
        DateTime::from_timestamp(i64::from(ts_sec), nanos.min(999_999_999)).unwrap_or_else(Utc::now)
    }

    /// Where a slice the parser handed back sits within the mapping, or `None`
    /// if it does not point into the mapping at all.
    ///
    /// The parser is free to return an owned `Cow`, and a caller must never
    /// turn that into an out-of-range index, so containment is checked rather
    /// than assumed.
    fn offset_within_mapping(&self, data: &[u8]) -> Option<usize> {
        let base = self.whole.as_ptr() as usize;
        let end = base + self.whole.len();
        let sub = data.as_ptr() as usize;
        if sub >= base && sub.saturating_add(data.len()) <= end {
            Some(sub - base)
        } else {
            None
        }
    }
}

/// This host's page size, read once.
///
/// Falls back to 4 KiB only if the query fails, which it does not on any
/// supported platform; a wrong value here costs the page-release hint, not
/// correctness.
fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `sysconf` takes an int and returns a long, touches no memory
        // the caller owns, and is documented thread-safe.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n > 0 { n as usize } else { 4096 }
    })
}

/// Whether `SIPNAB_NO_MMAP` is set, so every read falls back to libpcap.
///
/// An off switch for a new I/O path, and the reason it is an environment
/// variable rather than a flag: the failure it exists for is a filesystem where
/// mapping misbehaves (a network mount, a FUSE layer), which an operator hits
/// on every invocation and wants to disable once for a shell, not remember to
/// type. It also makes the copy and no-copy readers A/B-comparable in a single
/// binary, which is how the throughput claim in the module docs was measured.
///
/// Read once: this is consulted per file, and a `getenv` per file of a large
/// set is a syscall for an answer that cannot change.
fn mapping_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| std::env::var_os("SIPNAB_NO_MMAP").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No frame may alias the mapping.
    ///
    /// This is the invariant [`MappedPcap::release_behind`] rests on: it hands
    /// consumed pages back to the kernel, so a frame still pointing into them
    /// would be a use-after-free that no amount of testing the BYTES would
    /// catch — the page usually still holds the same data. So this asserts the
    /// ADDRESS is outside the mapping, which is the only form of the claim that
    /// can fail when the invariant breaks.
    #[test]
    fn no_frame_aliases_the_mapping_it_was_read_from() {
        let mut mapped = MappedPcap::open(std::path::Path::new("tests/fixtures/sip_call.pcap"))
            .expect("fixture opens")
            .expect("fixture maps");
        let base = mapped.whole.as_ptr() as usize;
        let end = base + mapped.whole.len();

        let mut checked = 0usize;
        while let Some(frame) = mapped.next_frame() {
            if frame.data.is_empty() {
                continue;
            }
            let at = frame.data.as_ptr() as usize;
            assert!(
                at < base || at >= end,
                "frame aliases the mapping; release_behind would free it under us"
            );
            checked += 1;
        }
        assert!(checked > 0, "fixture had frames to check");
    }

    /// `caplen` is what [`crate::capture::packet::Packet::from_bytes`]
    /// debug-asserts against `data.len()`, so it must be derived from the data
    /// rather than from a header field that a malformed file controls.
    #[test]
    fn caplen_always_matches_the_data_length() {
        let mut mapped = MappedPcap::open(std::path::Path::new("tests/fixtures/udp_5060.pcap"))
            .expect("fixture opens")
            .expect("fixture maps");
        let mut n = 0;
        while let Some(frame) = mapped.next_frame() {
            assert_eq!(frame.caplen, frame.data.len());
            n += 1;
        }
        assert!(n > 0);
    }

    /// A record whose length field claims more than the file holds must stop
    /// the read, not panic and not read past the mapping.
    #[test]
    fn a_record_longer_than_the_file_stops_the_read() {
        let mut bytes = std::fs::read("tests/fixtures/sip_call.pcap").expect("fixture reads");
        // The first record header sits at 24; its caplen is bytes 8..12 of it.
        let caplen_at = 24 + 8;
        bytes[caplen_at..caplen_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lying.pcap");
        std::fs::write(&path, &bytes).expect("write");

        if let Some(mut mapped) = MappedPcap::open(&path).expect("open succeeds") {
            // Must terminate. Any frame it does yield must fit in the file.
            let limit = bytes.len();
            while let Some(frame) = mapped.next_frame() {
                assert!(frame.data.len() <= limit, "read past the mapping");
            }
        }
    }

    /// Declining is a routine outcome, so it must not be reported as an error.
    #[test]
    fn a_directory_and_an_empty_file_decline_without_erroring() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty.pcap");
        std::fs::write(&empty, b"").expect("write");
        assert!(MappedPcap::open(&empty).expect("no error").is_none());
    }
}
