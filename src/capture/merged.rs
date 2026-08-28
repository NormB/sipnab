//! Reading a pcapng whose interfaces disagree, which libpcap refuses outright.
//!
//! `mergecap`, and any capture spanning interfaces with different snapshot
//! lengths or link types, produces a file libpcap will not open. It rejects on
//! two independent grounds, and normalizing the first only exposes the second.
//! Measured against a real merged capture carrying 313 interface description
//! blocks:
//!
//! ```text
//! an interface has a snapshot length 8192 different from the snapshot length
//! of the first interface
//! ```
//!
//! and, once every snaplen is rewritten to one value:
//!
//! ```text
//! an interface has a type 274 different from the type of the first interface
//! ```
//!
//! Per-packet encapsulation is the *point* of a merged capture, so there is no
//! rewrite that makes libpcap read one. The answer is to take the link type
//! from each packet's own interface.
//!
//! That turns out to cost very little, because the parser never had the
//! restriction: [`crate::capture::Packet::from_bytes`] has always taken
//! `link_type` per packet. Only the readers collapsed it to a single value for
//! a whole file, by asking libpcap once at open. This reader keeps the
//! per-interface table the file already carries and hands the right one to
//! every frame.
//!
//! Gated on `native` like its siblings: the decoder is `pcap-file`, which only
//! `native` pulls in. Declaring it unconditionally broke every feature
//! combination built without `native` — caught by the gate's `tls`-only and
//! `wasm` legs, not by `--all-features`, which can never see a missing feature.
//!
//! Reads the file into memory rather than streaming it. Deliberate: this path
//! exists for merged captures, which are assembled artifacts rather than live
//! ring buffers, and the alternative is a self-referential borrow of the
//! decoder. The ordinary single-interface path is untouched and still streams
//! through libpcap.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use std::path::Path;

/// One frame from a merged capture, carrying the link type of the interface
/// that recorded it rather than one chosen for the whole file.
pub struct MergedFrame {
    /// Frame bytes as captured.
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub ts: DateTime<Utc>,
    /// Bytes present in the file.
    pub caplen: u32,
    /// Bytes on the wire, which exceeds `caplen` for a snapped frame.
    pub origlen: u32,
    /// Link type of THIS frame's interface. The whole point of this reader.
    pub link_type: i32,
}

/// Whether `path` is a pcapng whose interfaces disagree, so libpcap cannot
/// read it.
///
/// Checked up front rather than by catching libpcap's complaint, because
/// libpcap does not complain at open. It accepts the file, reads the first
/// interface's description, and fails on the first PACKET that names a
/// different one — so an open-time fallback never fires, and the caller that
/// tried one got a read error from deep in the loop instead. Matching on the
/// text of that error would be worse: it is libpcap's wording, not ours, and
/// it differs between the snaplen and link-type cases and between versions.
///
/// Cheap: reads interface description blocks only, and stops at the first
/// disagreement. A single-interface file — the overwhelming majority — costs
/// one short read and takes the ordinary path untouched.
#[must_use]
pub fn is_merged(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    is_merged_in(&mut file)
}

/// The scan itself, over anything readable, so a test can count what it
/// consumed.
///
/// Whether this reads four bytes or the whole capture is the difference
/// between the comment above being true and being a wish, and it is not a
/// detail: all three callers run it before a single packet is read, so a
/// classic pcap that loads itself into memory here pays that on every offline
/// run.
fn is_merged_in<R: std::io::Read + std::io::Seek>(r: &mut R) -> bool {
    // Section Header Block magic, little-endian; anything else is not pcapng.
    // Checked FIRST, against four bytes, because the answer for a classic pcap
    // is already decided here and loading the capture to learn it is the whole
    // defect.
    let mut magic = [0u8; 4];
    if r.read_exact(&mut magic).is_err() {
        return false;
    }
    if magic != 0x0a0d_0d0au32.to_le_bytes() {
        return false;
    }
    // It IS a pcapng, so the interface blocks have to be walked. They may sit
    // anywhere in the section, so the rest is read rather than bounded by a
    // guess -- a pcapng is the uncommon case on this path, and a guess that
    // fell short would silently mis-detect one. `magic` is put back first so
    // every offset below still counts from the start of the file.
    let mut bytes = magic.to_vec();
    if r.read_to_end(&mut bytes).is_err() {
        return false;
    }
    if bytes.len() < 12 {
        return false;
    }
    let mut off = 0usize;
    let mut seen: Option<(u16, u32)> = None;
    while off + 12 <= bytes.len() {
        let btype =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let blen = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]) as usize;
        if blen < 12 || off + blen > bytes.len() {
            return false;
        }
        // Interface Description Block: linktype u16, reserved u16, snaplen u32.
        if btype == 0x0000_0001 && off + 20 <= bytes.len() {
            let lt = u16::from_le_bytes([bytes[off + 8], bytes[off + 9]]);
            let snap = u32::from_le_bytes([
                bytes[off + 12],
                bytes[off + 13],
                bytes[off + 14],
                bytes[off + 15],
            ]);
            match seen {
                None => seen = Some((lt, snap)),
                Some(first) if first != (lt, snap) => return true,
                Some(_) => {}
            }
        }
        off += blen;
    }
    false
}

/// A pcapng read through the pure-Rust decoder, so interfaces may disagree.
pub struct MergedPcapNg {
    /// Frames in file order.
    frames: std::vec::IntoIter<MergedFrame>,
    /// Link types seen, for the summary an operator needs to trust the read.
    link_types: Vec<i32>,
    /// Blocks that carried no frame this reader could use.
    skipped: u64,
}

impl MergedPcapNg {
    /// Decode `path`, or fail with the reason.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or is not a pcapng the
    /// decoder recognizes.
    pub fn open(path: &Path) -> Result<Self> {
        use pcap_file::pcapng::{Block, PcapNgReader};

        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read capture '{}'", path.display()))?;
        let mut reader = PcapNgReader::new(&bytes[..])
            .with_context(|| format!("Not a pcapng file: '{}'", path.display()))?;

        // Interface index -> link type. The table the file already carries,
        // which libpcap discards by insisting every interface agree.
        //
        // Timestamp resolution is per-interface too, but `pcap-file` has
        // already applied each interface's own resolution by the time a block
        // reaches here, so there is nothing to track: a file mixing microsecond
        // and nanosecond interfaces comes back with both correct.
        let mut ifaces: Vec<i32> = Vec::new();
        let mut frames: Vec<MergedFrame> = Vec::new();
        let mut skipped: u64 = 0;

        while let Some(block) = reader.next_block() {
            let block = block.context("Malformed pcapng block")?;
            match block {
                Block::InterfaceDescription(idb) => {
                    ifaces.push(u32::from(idb.linktype) as i32);
                }
                Block::EnhancedPacket(epb) => {
                    let idx = epb.interface_id as usize;
                    let Some(&link_type) = ifaces.get(idx) else {
                        // A packet naming an interface the file never
                        // described. Counted, not dropped in silence.
                        skipped += 1;
                        continue;
                    };
                    let data = epb.data.into_owned();
                    let caplen = data.len() as u32;
                    frames.push(MergedFrame {
                        ts: epoch_to_utc(epb.timestamp),
                        caplen,
                        origlen: epb.original_len,
                        link_type,
                        data,
                    });
                }
                Block::SimplePacket(spb) => {
                    // A simple packet block names no interface, so it belongs
                    // to interface 0 by definition, and carries no timestamp.
                    let Some(&link_type) = ifaces.first() else {
                        skipped += 1;
                        continue;
                    };
                    let data = spb.data.into_owned();
                    let caplen = data.len() as u32;
                    frames.push(MergedFrame {
                        ts: Utc.timestamp_opt(0, 0).single().unwrap_or_default(),
                        caplen,
                        origlen: spb.original_len,
                        link_type,
                        data,
                    });
                }
                _ => {}
            }
        }

        let mut link_types: Vec<i32> = ifaces.clone();
        link_types.sort_unstable();
        link_types.dedup();

        Ok(Self {
            frames: frames.into_iter(),
            link_types,
            skipped,
        })
    }

    /// Distinct link types this file carries, sorted.
    #[must_use]
    pub fn link_types(&self) -> &[i32] {
        &self.link_types
    }

    /// Blocks that named an interface the file never described.
    ///
    /// Reported rather than swallowed: a reader that discards frames without
    /// saying so is indistinguishable from a capture that never held them.
    #[must_use]
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// The next frame, or `None` at end of file.
    pub fn next_frame(&mut self) -> Option<MergedFrame> {
        self.frames.next()
    }
}

/// A pcapng timestamp is a count since the Unix epoch at the interface's own
/// resolution; `pcap-file` has already applied that resolution and hands back a
/// `Duration`.
fn epoch_to_utc(d: std::time::Duration) -> DateTime<Utc> {
    Utc.timestamp_opt(d.as_secs() as i64, d.subsec_nanos())
        .single()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that counts what it hands out, so "did not read the capture"
    /// is asserted as an effect rather than read off the source.
    struct Counting<'a> {
        inner: std::io::Cursor<&'a [u8]>,
        read: usize,
    }

    impl std::io::Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = std::io::Read::read(&mut self.inner, buf)?;
            self.read += n;
            Ok(n)
        }
    }

    impl std::io::Seek for Counting<'_> {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            std::io::Seek::seek(&mut self.inner, pos)
        }
    }

    /// The predicate that gates this whole module, asserted in the direction
    /// that matters. Nothing covered it before: every test here drove
    /// `MergedPcapNg` directly, so a `is_merged` that always answered "no"
    /// would have passed the suite while quietly routing every merged capture
    /// back to the libpcap reader that cannot read one.
    #[test]
    fn a_merged_pcapng_is_detected_and_an_ordinary_one_is_not() {
        let dir = tempfile::tempdir().unwrap();

        let merged = dir.path().join("merged.pcapng");
        merged_fixture(&merged);
        assert!(
            is_merged(&merged),
            "interfaces disagreeing on link type and snaplen is the definition"
        );

        // Same builder, one interface: a perfectly ordinary pcapng, which
        // libpcap reads fine and which must NOT be diverted.
        let plain = dir.path().join("plain.pcapng");
        let mut f = 0x0a0d_0d0au32.to_le_bytes().to_vec();
        f.extend_from_slice(&28u32.to_le_bytes());
        f.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&(-1i64).to_le_bytes());
        f.extend_from_slice(&28u32.to_le_bytes());
        // One Interface Description Block: Ethernet, snaplen 65535.
        f.extend_from_slice(&1u32.to_le_bytes());
        f.extend_from_slice(&20u32.to_le_bytes());
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&65535u32.to_le_bytes());
        f.extend_from_slice(&20u32.to_le_bytes());
        std::fs::write(&plain, &f).unwrap();
        assert!(
            !is_merged(&plain),
            "a single-interface pcapng is not merged and must take the ordinary path"
        );
    }

    /// The regression this exists to prevent shipped in 0.5.118 and survived
    /// to 0.5.121: `is_merged` read the ENTIRE capture into memory and then
    /// rejected it on the first four bytes. Offline reconstruction of a 128 MB
    /// classic pcap fell from 3.29M to 2.39M packets per second because of it.
    #[test]
    fn a_classic_pcap_is_rejected_without_reading_the_capture() {
        // A classic pcap magic, then a megabyte of whatever. The whole point
        // is the "whatever": nothing here should ever be touched.
        let mut file = 0xa1b2_c3d4u32.to_le_bytes().to_vec();
        file.extend(std::iter::repeat_n(0x5au8, 1 << 20));

        let mut r = Counting {
            inner: std::io::Cursor::new(&file[..]),
            read: 0,
        };
        assert!(
            !is_merged_in(&mut r),
            "a classic pcap is not a merged pcapng"
        );
        assert!(
            r.read <= 16,
            "is_merged read {} bytes of a {}-byte capture it rejects on the \
             first four; every offline run pays this before reading a packet",
            r.read,
            file.len()
        );
    }

    /// Build a pcapng whose two interfaces disagree on BOTH link type and
    /// snaplen, then read it back.
    fn merged_fixture(path: &Path) {
        fn block(kind: u32, body: &[u8]) -> Vec<u8> {
            let pad = (4 - body.len() % 4) % 4;
            let total = 12 + body.len() + pad;
            let mut b = Vec::with_capacity(total);
            b.extend_from_slice(&kind.to_le_bytes());
            b.extend_from_slice(&(total as u32).to_le_bytes());
            b.extend_from_slice(body);
            b.extend(std::iter::repeat_n(0u8, pad));
            b.extend_from_slice(&(total as u32).to_le_bytes());
            b
        }
        let mut out = Vec::new();
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        out.extend_from_slice(&block(0x0a0d_0d0a, &shb));

        for (lt, snap) in [(1u16, 65535u32), (12u16, 2048u32)] {
            let mut idb = Vec::new();
            idb.extend_from_slice(&lt.to_le_bytes());
            idb.extend_from_slice(&0u16.to_le_bytes());
            idb.extend_from_slice(&snap.to_le_bytes());
            out.extend_from_slice(&block(0x0000_0001, &idb));
        }

        for (iface, byte) in [(0u32, 0xAAu8), (1u32, 0xBBu8)] {
            let data = vec![byte; 40];
            let mut epb = Vec::new();
            epb.extend_from_slice(&iface.to_le_bytes());
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
            epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
            epb.extend_from_slice(&data);
            out.extend_from_slice(&block(0x0000_0006, &epb));
        }
        std::fs::write(path, out).expect("write fixture");
    }

    /// Every frame must carry ITS OWN interface's link type.
    ///
    /// Reading one link type for the file is exactly the bug: the second
    /// frame here is raw IP, and decoding it as Ethernet would consume
    /// fourteen bytes of IP header as a link header.
    #[test]
    fn each_frame_carries_its_own_interfaces_link_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("merged.pcapng");
        merged_fixture(&path);

        let mut r = MergedPcapNg::open(&path).expect("merged pcapng must open");
        assert_eq!(
            r.link_types(),
            &[1, 12],
            "both interfaces' link types must be visible"
        );

        let first = r.next_frame().expect("first frame");
        let second = r.next_frame().expect("second frame");
        assert_eq!(first.link_type, 1, "frame 0 is on the Ethernet interface");
        assert_eq!(second.link_type, 12, "frame 1 is on the raw-IP interface");
        assert_eq!(first.data[0], 0xAA);
        assert_eq!(second.data[0], 0xBB);
        assert!(r.next_frame().is_none(), "only two frames were written");
        assert_eq!(r.skipped(), 0, "nothing was skipped in a well-formed file");
    }

    /// A packet naming an interface the file never described is COUNTED.
    ///
    /// The negative case: dropping it silently would make a truncated or
    /// malformed capture indistinguishable from one that held fewer packets.
    #[test]
    fn a_packet_naming_an_undescribed_interface_is_counted_not_hidden() {
        fn block(kind: u32, body: &[u8]) -> Vec<u8> {
            let pad = (4 - body.len() % 4) % 4;
            let total = 12 + body.len() + pad;
            let mut b = Vec::with_capacity(total);
            b.extend_from_slice(&kind.to_le_bytes());
            b.extend_from_slice(&(total as u32).to_le_bytes());
            b.extend_from_slice(body);
            b.extend(std::iter::repeat_n(0u8, pad));
            b.extend_from_slice(&(total as u32).to_le_bytes());
            b
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dangling.pcapng");
        let mut out = Vec::new();
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        out.extend_from_slice(&block(0x0a0d_0d0a, &shb));
        let mut idb = Vec::new();
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&block(0x0000_0001, &idb));
        // interface_id 7, which no IDB described.
        let data = vec![0xCCu8; 20];
        let mut epb = Vec::new();
        epb.extend_from_slice(&7u32.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&data);
        out.extend_from_slice(&block(0x0000_0006, &epb));
        std::fs::write(&path, out).unwrap();

        let mut r = MergedPcapNg::open(&path).expect("must still open");
        assert!(
            r.next_frame().is_none(),
            "the dangling packet is not yielded"
        );
        assert_eq!(
            r.skipped(),
            1,
            "it must be COUNTED — a silently dropped frame reads as a capture \
             that never held it"
        );
    }
}
