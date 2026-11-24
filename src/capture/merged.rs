// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

/// [`is_merged`] for a file already open, read from its start.
///
/// The `-I` reader of a run that drops privileges opens each file before
/// the drop, and asks this of the descriptor. The read position is left
/// wherever the scan stopped.
#[must_use]
pub fn is_merged_file(file: &mut std::fs::File) -> bool {
    use std::io::Seek as _;
    file.seek(std::io::SeekFrom::Start(0)).is_ok() && is_merged_in(file)
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
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read capture '{}'", path.display()))?;
        Self::decode(&bytes, path)
    }

    /// [`Self::open`] for a file already open, read from its start, which
    /// goes by `path`.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn from_file(mut file: std::fs::File, path: &Path) -> Result<Self> {
        use std::io::{Read as _, Seek as _};
        let mut bytes = Vec::new();
        file.seek(std::io::SeekFrom::Start(0))
            .and_then(|_| file.read_to_end(&mut bytes))
            .with_context(|| format!("Failed to read capture '{}'", path.display()))?;
        Self::decode(&bytes, path)
    }

    /// Decode the pcapng in `bytes`, read from `path`.
    fn decode(bytes: &[u8], path: &Path) -> Result<Self> {
        use pcap_file::pcapng::{Block, PcapNgReader};

        let mut reader = PcapNgReader::new(bytes)
            .with_context(|| format!("Not a pcapng file: '{}'", path.display()))?;

        /// Enhanced Packet Block type (pcapng 4.3).
        const EPB: u32 = 0x0000_0006;
        /// Simple Packet Block type (pcapng 4.4).
        const SPB: u32 = 0x0000_0003;

        // Every interface's link type, across all sections: the table the
        // file already carries, which libpcap discards by insisting every
        // interface agree. The interfaces of the section being read are
        // pcap-file's state, which a Section Header Block resets (pcapng
        // numbers interfaces per section, 4.1). pcap-file also applies each
        // interface's `if_tsresol` and `if_tsoffset` to its frames' times,
        // and cuts a simple packet at its interface's snap length.
        let mut link_types: Vec<i32> = Vec::new();
        let mut frames: Vec<MergedFrame> = Vec::new();
        let mut skipped: u64 = 0;

        while let Some(next) = reader.next_raw_block() {
            let (raw, state) = next.context("Malformed pcapng block")?;
            // pcap-file refuses a packet that names an interface its section
            // does not describe, and a simple packet in a section with no
            // interface. Both are counted here, not dropped in silence, and
            // the read goes on.
            let described = state.interfaces().len();
            let dangling = match raw.type_ {
                EPB => packet_interface(&raw.body, state.endianness())
                    .is_some_and(|id| id as usize >= described),
                SPB => described == 0,
                _ => false,
            };
            if dangling {
                skipped += 1;
                continue;
            }
            let block = raw
                .try_into_block(state)
                .context("Malformed pcapng block")?;
            match block {
                Block::InterfaceDescription(idb) => {
                    link_types.push(u32::from(idb.linktype) as i32);
                }
                Block::EnhancedPacket(epb) => {
                    let Some(iface) = state.interfaces().get(epb.interface_id as usize) else {
                        skipped += 1;
                        continue;
                    };
                    let data = epb.data.into_owned();
                    let caplen = data.len() as u32;
                    frames.push(MergedFrame {
                        ts: epoch_to_utc(epb.timestamp),
                        caplen,
                        origlen: epb.original_len,
                        link_type: u32::from(iface.linktype) as i32,
                        data,
                    });
                }
                Block::SimplePacket(spb) => {
                    // A simple packet block names no interface, so it belongs
                    // to interface 0 by definition, and carries no timestamp.
                    let Some(iface) = state.interfaces().first() else {
                        skipped += 1;
                        continue;
                    };
                    let data = spb.data.into_owned();
                    let caplen = data.len() as u32;
                    frames.push(MergedFrame {
                        ts: Utc.timestamp_opt(0, 0).single().unwrap_or_default(),
                        caplen,
                        origlen: spb.original_len,
                        link_type: u32::from(iface.linktype) as i32,
                        data,
                    });
                }
                _ => {}
            }
        }

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

/// The interface id an Enhanced Packet Block's `body` names, read in the
/// section's byte order. `None` for a body too short to hold one, which
/// pcap-file then refuses as malformed.
fn packet_interface(body: &[u8], endianness: pcap_file::Endianness) -> Option<u32> {
    let id: [u8; 4] = body.get(..4)?.try_into().ok()?;
    Some(match endianness {
        pcap_file::Endianness::Big => u32::from_be_bytes(id),
        pcap_file::Endianness::Little => u32::from_le_bytes(id),
    })
}

/// A frame's time: pcap-file has applied its interface's resolution and
/// offset and hands back the time since the Unix epoch.
fn epoch_to_utc(d: std::time::Duration) -> DateTime<Utc> {
    i64::try_from(d.as_secs())
        .ok()
        .and_then(|secs| Utc.timestamp_opt(secs, d.subsec_nanos()).single())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod testutil {
    /// Any error a fixture builder can fail with; `?` converts into it.
    pub(crate) type TestError = Box<dyn std::error::Error>;

    /// Write to `path` a pcapng whose two interfaces disagree on BOTH link
    /// type and snaplen, holding one 40-byte frame on each interface.
    pub(crate) fn merged_fixture(path: &std::path::Path) -> Result<(), TestError> {
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
        std::fs::write(path, out).map_err(|e| format!("write fixture {}: {e}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::merged_fixture;
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

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
    fn a_merged_pcapng_is_detected_and_an_ordinary_one_is_not() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;

        let merged = dir.path().join("merged.pcapng");
        merged_fixture(&merged)?;
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
        std::fs::write(&plain, &f)?;
        assert!(
            !is_merged(&plain),
            "a single-interface pcapng is not merged and must take the ordinary path"
        );
        Ok(())
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

    /// Every frame must carry ITS OWN interface's link type.
    ///
    /// Reading one link type for the file is exactly the bug: the second
    /// frame here is raw IP, and decoding it as Ethernet would consume
    /// fourteen bytes of IP header as a link header.
    #[test]
    fn each_frame_carries_its_own_interfaces_link_type() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("merged.pcapng");
        merged_fixture(&path)?;

        let mut r =
            MergedPcapNg::open(&path).map_err(|e| format!("merged pcapng must open: {e:?}"))?;
        assert_eq!(
            r.link_types(),
            &[1, 12],
            "both interfaces' link types must be visible"
        );

        let first = r.next_frame().ok_or("first frame")?;
        let second = r.next_frame().ok_or("second frame")?;
        assert_eq!(first.link_type, 1, "frame 0 is on the Ethernet interface");
        assert_eq!(second.link_type, 12, "frame 1 is on the raw-IP interface");
        assert_eq!(first.data[0], 0xAA);
        assert_eq!(second.data[0], 0xBB);
        assert!(r.next_frame().is_none(), "only two frames were written");
        assert_eq!(r.skipped(), 0, "nothing was skipped in a well-formed file");
        Ok(())
    }

    /// A packet naming an interface the file never described is COUNTED.
    ///
    /// The negative case: dropping it silently would make a truncated or
    /// malformed capture indistinguishable from one that held fewer packets.
    #[test]
    fn a_packet_naming_an_undescribed_interface_is_counted_not_hidden() -> Result<(), TestError> {
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
        let dir = tempfile::tempdir()?;
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
        std::fs::write(&path, out)?;

        let mut r = MergedPcapNg::open(&path).map_err(|e| format!("must still open: {e:?}"))?;
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
        Ok(())
    }

    /// Read-back of every block type the merged-pcapng reader takes, from
    /// bytes built here by hand (not by `pcap-file`), so the reader is held
    /// to the pcapng specification and not to the library that decodes it.
    mod read_back {
        use super::*;

        /// One pcapng block of `kind` around `body`, in either byte order.
        fn block(kind: u32, body: &[u8], be: bool) -> Vec<u8> {
            let u32b = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
            let pad = (4 - body.len() % 4) % 4;
            let total = (12 + body.len() + pad) as u32;
            let mut b = Vec::new();
            b.extend_from_slice(&u32b(kind));
            b.extend_from_slice(&u32b(total));
            b.extend_from_slice(body);
            b.extend(std::iter::repeat_n(0u8, pad));
            b.extend_from_slice(&u32b(total));
            b
        }

        /// One option: code, length, value, padding.
        fn opt(code: u16, value: &[u8], be: bool) -> Vec<u8> {
            let u16b = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
            let mut o = Vec::new();
            o.extend_from_slice(&u16b(code));
            o.extend_from_slice(&u16b(value.len() as u16));
            o.extend_from_slice(value);
            o.extend(std::iter::repeat_n(0u8, (4 - value.len() % 4) % 4));
            o
        }

        /// The end-of-options option.
        fn end(be: bool) -> Vec<u8> {
            opt(0, &[], be)
        }

        fn shb(be: bool) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&if be {
                0x1a2b_3c4du32.to_be_bytes()
            } else {
                0x1a2b_3c4du32.to_le_bytes()
            });
            b.extend_from_slice(&if be {
                1u16.to_be_bytes()
            } else {
                1u16.to_le_bytes()
            });
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&(-1i64).to_le_bytes());
            block(0x0a0d_0d0a, &b, be)
        }

        /// An IDB of `link_type` and `snaplen` with `options` (already
        /// encoded, end marker included, or empty).
        fn idb(link_type: u16, snaplen: u32, options: &[u8], be: bool) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&if be {
                link_type.to_be_bytes()
            } else {
                link_type.to_le_bytes()
            });
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&if be {
                snaplen.to_be_bytes()
            } else {
                snaplen.to_le_bytes()
            });
            b.extend_from_slice(options);
            block(0x0000_0001, &b, be)
        }

        /// An EPB on `iface` stamped `ticks` in that interface's resolution.
        fn epb(
            iface: u32,
            ticks: u64,
            data: &[u8],
            origlen: u32,
            options: &[u8],
            be: bool,
        ) -> Vec<u8> {
            let u32b = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
            let mut b = Vec::new();
            b.extend_from_slice(&u32b(iface));
            b.extend_from_slice(&u32b((ticks >> 32) as u32));
            b.extend_from_slice(&u32b(ticks as u32));
            b.extend_from_slice(&u32b(data.len() as u32));
            b.extend_from_slice(&u32b(origlen));
            b.extend_from_slice(data);
            b.extend(std::iter::repeat_n(0u8, (4 - data.len() % 4) % 4));
            b.extend_from_slice(options);
            block(0x0000_0006, &b, be)
        }

        /// A Simple Packet Block.
        fn spb(data: &[u8], origlen: u32, be: bool) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&if be {
                origlen.to_be_bytes()
            } else {
                origlen.to_le_bytes()
            });
            b.extend_from_slice(data);
            block(0x0000_0003, &b, be)
        }

        /// Decode `bytes` and return every frame and the skipped count.
        fn read(bytes: &[u8]) -> Result<(Vec<MergedFrame>, Vec<i32>, u64), TestError> {
            let mut r = MergedPcapNg::decode(bytes, Path::new("test.pcapng"))
                .map_err(|e| format!("the file must decode: {e:#}"))?;
            let mut frames = Vec::new();
            while let Some(f) = r.next_frame() {
                frames.push(f);
            }
            Ok((frames, r.link_types().to_vec(), r.skipped()))
        }

        /// 2023-11-14 22:13:20 UTC.
        const T0: i64 = 1_700_000_000;

        fn utc(secs: i64, nanos: u32) -> Result<DateTime<Utc>, TestError> {
            Utc.timestamp_opt(secs, nanos)
                .single()
                .ok_or_else(|| "a valid instant".into())
        }

        #[test]
        fn a_nanosecond_interface_stamps_each_frame_to_the_nanosecond() -> Result<(), TestError> {
            for be in [false, true] {
                let mut f = shb(be);
                f.extend(idb(1, 65535, &[opt(9, &[9], be), end(be)].concat(), be));
                let ticks = T0 as u64 * 1_000_000_000 + 123_456_789;
                f.extend(epb(0, ticks, &[0xAB; 42], 42, &[], be));
                let (frames, _, skipped) = read(&f)?;
                assert_eq!(frames.len(), 1, "one frame (big-endian {be})");
                assert_eq!(
                    frames[0].ts,
                    utc(T0, 123_456_789)?,
                    "nanosecond time (big-endian {be})"
                );
                assert_eq!(
                    frames[0].data,
                    vec![0xAB; 42],
                    "the data without its padding (big-endian {be})"
                );
                assert_eq!(skipped, 0, "nothing skipped (big-endian {be})");
            }
            Ok(())
        }

        /// A packet's options (a comment here) do not change its bytes.
        #[test]
        fn a_packet_with_options_keeps_its_bytes() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(
                1,
                65535,
                &[opt(9, &[9], false), end(false)].concat(),
                false,
            ));
            let opts = [opt(1, b"a note", false), end(false)].concat();
            f.extend(epb(0, 5, &[7; 13], 1514, &opts, false));
            let (frames, _, _) = read(&f)?;
            assert_eq!(frames[0].data, vec![7; 13], "the 13 captured bytes");
            assert_eq!(frames[0].caplen, 13, "caplen is the captured length");
            assert_eq!(frames[0].origlen, 1514, "the wire length is kept");
            Ok(())
        }

        /// A Simple Packet Block captured to a snap length holds the snapped
        /// bytes, and its wire length.
        #[test]
        fn a_simple_packet_is_cut_at_the_interface_snap_length() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(1, 16, &[], false));
            f.extend(spb(&[9; 16], 1500, false));
            let (frames, _, _) = read(&f)?;
            assert_eq!(frames[0].data, vec![9; 16], "the 16 snapped bytes");
            assert_eq!(frames[0].origlen, 1500, "the wire length");
            Ok(())
        }

        /// A Simple Packet Block in a file with no interface is counted.
        #[test]
        fn a_simple_packet_without_an_interface_is_counted_not_hidden() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(spb(&[9; 8], 8, false));
            let (frames, _, skipped) = read(&f)?;
            assert!(frames.is_empty(), "no frame");
            assert_eq!(skipped, 1, "the packet is counted");
            Ok(())
        }

        /// Blocks the reader does not take (name resolution, interface
        /// statistics, decryption secrets, custom, an unknown type) are passed
        /// over and the frames after them are read.
        #[test]
        fn blocks_that_carry_no_frame_are_passed_over() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(
                1,
                65535,
                &[opt(9, &[9], false), end(false)].concat(),
                false,
            ));
            // NRB: one IPv4 record, the end record.
            let mut nrb = Vec::new();
            nrb.extend_from_slice(&1u16.to_le_bytes());
            nrb.extend_from_slice(&6u16.to_le_bytes());
            nrb.extend_from_slice(&[192, 0, 2, 1, b'a', 0]);
            nrb.extend_from_slice(&[0, 0]);
            nrb.extend_from_slice(&[0, 0, 0, 0]);
            f.extend(block(0x0000_0004, &nrb, false));
            // ISB: interface 0, time 0, no options.
            f.extend(block(0x0000_0005, &[0; 12], false));
            // DSB: TLS key log, 4 bytes.
            let mut dsb = Vec::new();
            dsb.extend_from_slice(&0x544c_534bu32.to_le_bytes());
            dsb.extend_from_slice(&4u32.to_le_bytes());
            dsb.extend_from_slice(b"KEY\n");
            f.extend(block(0x0000_000A, &dsb, false));
            // Custom block (copiable): a private enterprise number and data.
            f.extend(block(0x0000_0BAD, &[0, 0, 0x7f, 0xff, 1, 2, 3, 4], false));
            // A block type nobody defined.
            f.extend(block(0x0000_7777, &[1, 2, 3, 4], false));
            f.extend(epb(0, 1, &[5; 8], 8, &[], false));
            let (frames, _, skipped) = read(&f)?;
            assert_eq!(frames.len(), 1, "the frame after them is read");
            assert_eq!(frames[0].data, vec![5; 8], "with its bytes");
            assert_eq!(skipped, 0, "they are not packets, so not skipped packets");
            Ok(())
        }

        /// A packet after an undescribed one is still read.
        #[test]
        fn a_dangling_packet_does_not_stop_the_read() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(1, 65535, &[], false));
            f.extend(epb(3, 1, &[2; 8], 8, &[], false));
            f.extend(epb(0, 1, &[4; 8], 8, &[], false));
            let (frames, _, skipped) = read(&f)?;
            assert_eq!(frames.len(), 1, "the described packet");
            assert_eq!(frames[0].data, vec![4; 8], "its bytes");
            assert_eq!(skipped, 1, "the dangling one counted");
            Ok(())
        }

        /// No `if_tsresol` means microseconds (pcapng 4.2), the resolution
        /// libpcap and most tools write.
        #[test]
        fn an_interface_without_a_resolution_counts_microseconds() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(1, 65535, &[], false));
            f.extend(epb(
                0,
                T0 as u64 * 1_000_000 + 654_321,
                &[1; 20],
                20,
                &[],
                false,
            ));
            let (frames, _, _) = read(&f)?;
            assert_eq!(frames.len(), 1, "one frame");
            assert_eq!(
                frames[0].ts,
                utc(T0, 654_321_000)?,
                "a microsecond tick count must not be read as nanoseconds"
            );
            Ok(())
        }

        #[test]
        fn an_explicit_microsecond_resolution_counts_microseconds() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(
                1,
                65535,
                &[opt(9, &[6], false), end(false)].concat(),
                false,
            ));
            f.extend(epb(0, T0 as u64 * 1_000_000 + 1, &[1; 20], 20, &[], false));
            let (frames, _, _) = read(&f)?;
            assert_eq!(
                frames[0].ts,
                utc(T0, 1_000)?,
                "if_tsresol 6 is microseconds"
            );
            Ok(())
        }

        /// Two interfaces at different resolutions in one file: each frame
        /// in its own interface's resolution.
        #[test]
        fn interfaces_at_different_resolutions_each_keep_their_own() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(
                1,
                65535,
                &[opt(9, &[6], false), end(false)].concat(),
                false,
            ));
            f.extend(idb(
                12,
                65535,
                &[opt(9, &[9], false), end(false)].concat(),
                false,
            ));
            f.extend(epb(0, T0 as u64 * 1_000_000 + 2, &[1; 20], 20, &[], false));
            f.extend(epb(
                1,
                T0 as u64 * 1_000_000_000 + 2,
                &[2; 20],
                20,
                &[],
                false,
            ));
            let (frames, link_types, _) = read(&f)?;
            assert_eq!(link_types, vec![1, 12], "both link types");
            assert_eq!(frames[0].ts, utc(T0, 2_000)?, "frame 0 in microseconds");
            assert_eq!(frames[1].ts, utc(T0, 2)?, "frame 1 in nanoseconds");
            assert_eq!(frames[1].link_type, 12, "frame 1 on interface 1");
            Ok(())
        }

        /// `if_tsoffset` (pcapng 4.2) is added to every timestamp of the
        /// interface.
        #[test]
        fn an_interface_offset_is_added_to_its_timestamps() -> Result<(), TestError> {
            let mut f = shb(false);
            let opts = [
                opt(9, &[9], false),
                opt(14, &100i64.to_le_bytes(), false),
                end(false),
            ]
            .concat();
            f.extend(idb(1, 65535, &opts, false));
            f.extend(epb(0, T0 as u64 * 1_000_000_000, &[1; 20], 20, &[], false));
            let (frames, _, _) = read(&f)?;
            assert_eq!(frames[0].ts, utc(T0 + 100, 0)?, "the offset is in seconds");
            Ok(())
        }

        /// A Simple Packet Block is interface 0's, carries no time, and holds
        /// the captured bytes only, not the block's padding.
        #[test]
        fn a_simple_packet_is_interface_zeros_and_holds_only_its_bytes() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(113, 0, &[], false));
            f.extend(spb(&[9; 41], 41, false));
            let (frames, _, skipped) = read(&f)?;
            assert_eq!(frames.len(), 1, "one frame");
            assert_eq!(
                frames[0].data,
                vec![9; 41],
                "41 bytes, without the 3 bytes of padding"
            );
            assert_eq!(frames[0].link_type, 113, "interface 0's link type");
            assert_eq!(frames[0].ts, utc(0, 0)?, "no time");
            assert_eq!(skipped, 0, "nothing skipped");
            Ok(())
        }

        /// A second section starts a new interface table (pcapng 4.1):
        /// interface 0 of section 2 is section 2's first IDB.
        #[test]
        fn each_section_numbers_its_own_interfaces() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(1, 65535, &[], false));
            f.extend(epb(0, 1, &[1; 8], 8, &[], false));
            f.extend(shb(true));
            f.extend(idb(12, 65535, &[], true));
            f.extend(epb(0, 1, &[2; 8], 8, &[], true));
            let (frames, link_types, skipped) = read(&f)?;
            assert_eq!(frames.len(), 2, "a frame from each section");
            assert_eq!(frames[0].link_type, 1, "section 1's interface 0");
            assert_eq!(frames[1].link_type, 12, "section 2's interface 0");
            assert_eq!(link_types, vec![1, 12], "both link types");
            assert_eq!(skipped, 0, "nothing skipped");
            Ok(())
        }

        /// A second section without interfaces: its packet is counted,
        /// not attributed to the first section's interface.
        #[test]
        fn a_packet_in_a_section_without_interfaces_is_counted() -> Result<(), TestError> {
            let mut f = shb(false);
            f.extend(idb(1, 65535, &[], false));
            f.extend(shb(false));
            f.extend(epb(0, 1, &[2; 8], 8, &[], false));
            let (frames, _, skipped) = read(&f)?;
            assert!(
                frames.is_empty(),
                "no interface of its section describes it"
            );
            assert_eq!(skipped, 1, "counted");
            Ok(())
        }
    }
}
