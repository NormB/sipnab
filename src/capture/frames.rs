//! The frames of one capture file, read through a mapping when the file maps
//! and through libpcap when it does not. Shared by the single-threaded reader
//! in [`crate::capture::file`] and the `--cores` reader in [`crate::parallel`].

/// Where the reader's frames come from, and the reason there are two answers.
///
/// A mapped file hands out slices of one mapping that stay valid for as long as
/// any frame does. libpcap hands out a buffer it reuses on the very next call,
/// so a frame read that way must be copied before it can cross a channel. The
/// copy is the whole difference: it costs nothing on one core and 10.5% of
/// throughput on eight, because the price is the per-frame allocate-here /
/// free-there pair crossing the reader-to-worker boundary rather than the
/// `memcpy` itself. `docs/internals/zero-copy-payloads.md` records the same
/// effect one stage downstream.
///
/// Both arms yield the same [`crate::capture::mapped::MappedFrame`], so the
/// reader loops cannot tell them apart. The `--cores` reader in
/// [`crate::parallel`] and the single-threaded reader in
/// [`crate::capture::file`] both read through it.
pub(crate) enum Frames<'a> {
    /// The always-works arm. Owns the block that frames are copied into.
    Libpcap {
        /// The open capture. Borrowed rather than owned because the caller
        /// opened it and applied any BPF filter before this point.
        cap: &'a mut pcap::Capture<pcap::Offline>,
        /// Frames are cut from a shared block rather than allocated one at a
        /// time.
        ///
        /// `pkt.data.to_vec()` was one allocation per packet on the reader,
        /// freed later by whichever WORKER finished with it. mimalloc's
        /// cross-thread free path is atomic, so a 535k-packet capture paid it
        /// 535k times -- the largest single driver in the profile. Slicing from
        /// a block makes the allocation and its free amortize across every
        /// frame that shares it: at 64 KiB and ~240-byte frames that is ~270
        /// packets per allocation, so the cross-thread traffic falls by the
        /// same factor.
        ///
        /// 64 KiB deliberately, not larger. A block stays alive until the LAST
        /// slice cut from it drops, so an oversized block keeps a whole span of
        /// memory resident because one packet in it is still being processed.
        /// Bigger blocks buy fewer allocations and cost bounded-ness.
        block: bytes::BytesMut,
        /// libpcap's datalink number, read once at open so the reader loop does
        /// not ask per frame.
        link_type: i32,
    },
    /// The fast arm. Maps the file and reads records in place; see
    /// [`crate::capture::mapped`] for what it costs and what it declines.
    Mapped(Box<crate::capture::mapped::MappedPcap>),
}

impl<'a> Frames<'a> {
    /// Block size frames are copied into on the libpcap arm, matching the
    /// mapped reader's own so both arms amortize allocation the same way.
    const BLOCK: usize = 64 * 1024;

    /// Prefer the mapping, fall back to libpcap. `may_map` is false when a BPF
    /// filter is set, because applying it is libpcap's job.
    pub(crate) fn open(
        cap: &'a mut pcap::Capture<pcap::Offline>,
        path: &std::path::Path,
        may_map: bool,
    ) -> Self {
        if may_map {
            if let Some(mapped) = Self::try_map(path) {
                return mapped;
            }
        } else {
            // Said out loud: otherwise the only sign that the fast path was
            // skipped is the absence of the line below, and an absent log line
            // is indistinguishable from a log that was never wired up.
            tracing::debug!(
                "A BPF filter is set, so '{}' reads via libpcap, which applies it",
                crate::capture::archive::source_name(path)
            );
        }
        let link_type = cap.get_datalink().0;
        Frames::Libpcap {
            cap,
            block: bytes::BytesMut::with_capacity(Self::BLOCK),
            link_type,
        }
    }

    /// [`Self::open`], with a mapping of the file made in advance.
    ///
    /// A run that drops privileges maps its input while still privileged and
    /// hands the mapping here, so the read does not depend on opening the path
    /// again as the user it dropped to.
    pub(crate) fn open_premapped(
        cap: &'a mut pcap::Capture<pcap::Offline>,
        premapped: Option<crate::capture::mapped::MappedPcap>,
        path: &std::path::Path,
        may_map: bool,
    ) -> Self {
        match premapped {
            Some(mapped) if may_map => Frames::Mapped(Box::new(mapped)),
            _ => Self::open(cap, path, may_map),
        }
    }

    /// The mapped arm for `path`, or `None` when the file will not map and
    /// libpcap must read it.
    fn try_map(path: &std::path::Path) -> Option<Self> {
        // A file that will not map is the ordinary case for pcapng and
        // gzip, so this is debug-level rather than a warning.
        match crate::capture::mapped::MappedPcap::open(path) {
            Ok(Some(m)) => {
                tracing::debug!(
                    "Mapped '{}' for a copy-free read",
                    crate::capture::archive::source_name(path)
                );
                Some(Frames::Mapped(Box::new(m)))
            }
            Ok(None) => {
                tracing::debug!(
                    "'{}' cannot be mapped; reading via libpcap",
                    crate::capture::archive::source_name(path)
                );
                None
            }
            Err(e) => {
                tracing::debug!(
                    "Mapping '{}' failed ({e}); reading via libpcap",
                    crate::capture::archive::source_name(path)
                );
                None
            }
        }
    }

    /// This file's datalink number, whichever arm is reading it. Both must
    /// report the same value, or a frame would be decoded against one link type
    /// on the fast path and another on the fallback.
    pub(crate) fn link_type(&self) -> i32 {
        match self {
            Frames::Libpcap { link_type, .. } => *link_type,
            Frames::Mapped(m) => m.link_type(),
        }
    }

    /// The next frame, `Ok(None)` at end of file.
    pub(crate) fn next(
        &mut self,
    ) -> Result<Option<crate::capture::mapped::MappedFrame>, anyhow::Error> {
        match self {
            Frames::Mapped(m) => match m.next_frame() {
                Some(f) => Ok(Some(f)),
                // A file that ended mid-record stops the read AND says so, in
                // libpcap's own words, because the fallback path reports it and
                // an operator must not learn that a capture is complete from
                // whichever reader happened to open it.
                None => match m.truncation() {
                    Some((wanted, got)) => Err(anyhow::anyhow!(
                        "truncated dump file; tried to read {wanted} captured bytes, only got {got}"
                    )),
                    None => Ok(None),
                },
            },
            Frames::Libpcap { cap, block, .. } => match cap.next_packet() {
                Ok(pkt) => {
                    // NOT `n`: that name is already the SHARD COUNT in the
                    // caller, and shadowing it fed the frame length to
                    // `shard_for` -- a 236-byte frame indexed shard 236 of 2.
                    let frame_len = pkt.data.len();
                    // A frame larger than the block gets its own exact-sized
                    // one: `split_to` below must not outrun the capacity, and a
                    // jumbo frame should not force every later frame into a
                    // bigger block.
                    if block.capacity() < frame_len {
                        *block = bytes::BytesMut::with_capacity(Self::BLOCK.max(frame_len));
                    }
                    block.extend_from_slice(pkt.data);
                    // `split_to` hands back the bytes just written and leaves
                    // the remaining capacity in `block`, both views of ONE
                    // allocation.
                    let data = block.split_to(frame_len).freeze();
                    Ok(Some(crate::capture::mapped::MappedFrame {
                        timestamp: crate::capture::file::pcap_ts_to_chrono(pkt.header.ts),
                        data,
                        caplen: pkt.header.caplen as usize,
                        origlen: pkt.header.len as usize,
                    }))
                }
                Err(pcap::Error::NoMorePackets) => Ok(None),
                Err(e) => Err(anyhow::Error::new(e)),
            },
        }
    }
}
