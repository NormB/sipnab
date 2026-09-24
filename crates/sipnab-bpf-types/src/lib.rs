// SPDX-License-Identifier: MIT OR Apache-2.0

#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(not(target_arch = "bpf"))]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The largest plaintext one record carries.
///
/// Matches the tracefs backend's largest band, so a message readable by one
/// backend is readable by the other and an operator switching between them
/// sees the same truncation boundary rather than a new one.
pub const MAX_PAYLOAD: usize = 2048;

/// Address family: the tuple holds an IPv4 address in the first four bytes.
pub const FAMILY_IPV4: u16 = 2;
/// Address family: the tuple holds a full IPv6 address.
pub const FAMILY_IPV6: u16 = 10;

/// This record's addresses were observed, rather than left unknown.
///
/// The whole point of the BPF backend is that it can answer this `true`. The
/// tracefs backend never can, and a record that reaches the host with the flag
/// clear must be reported with no peer rather than with `0.0.0.0:0` presented
/// as a fact.
pub const FLAG_HAS_TUPLE: u32 = 1 << 0;
/// The application wrote more than [`MAX_PAYLOAD`], so `data` is a prefix.
pub const FLAG_TRUNCATED: u32 = 1 << 1;

/// One plaintext write, with the socket it went out on when that is known.
///
/// Field order is chosen so every multi-byte field is naturally aligned and the
/// large array sits last: a layout the two compilers cannot disagree about, and
/// one where the payload can be read without copying the header twice.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsRecord {
    /// Process that made the write.
    pub pid: u32,
    /// Thread that made the write. **This is the correlation key**: the
    /// plaintext hook and the socket hook are two different programs, and the
    /// only thing tying one call to the other is that the same thread made
    /// both, back to back.
    pub tid: u32,
    /// Bytes the application passed, before any truncation.
    pub len: u32,
    /// [`FLAG_HAS_TUPLE`] and [`FLAG_TRUNCATED`].
    pub flags: u32,
    /// Source address, IPv4 in the first four bytes when `family` says so.
    pub saddr: [u8; 16],
    /// Destination address, likewise.
    pub daddr: [u8; 16],
    /// Source port, host order.
    pub sport: u16,
    /// Destination port, host order.
    pub dport: u16,
    /// [`FAMILY_IPV4`] or [`FAMILY_IPV6`]. Zero when no tuple was observed.
    pub family: u16,
    /// Explicit, so neither compiler gets to choose a hole here.
    pub _pad: u16,
    /// The process's command name, NUL-padded.
    pub comm: [u8; 16],
    /// The plaintext, valid for `min(len, MAX_PAYLOAD)` bytes.
    pub data: [u8; MAX_PAYLOAD],
}

impl TlsRecord {
    /// Bytes of this record that carry meaning, header included.
    ///
    /// A short write still occupies a whole `TlsRecord` in the kernel, and
    /// pushing 2 KiB through the ring for a 200-byte `BYE` wastes most of it.
    /// The program submits only this much.
    #[must_use]
    pub const fn used_len(payload: usize) -> usize {
        Self::HEADER_LEN + payload
    }

    /// Size of everything before `data`.
    pub const HEADER_LEN: usize = core::mem::size_of::<TlsRecord>() - MAX_PAYLOAD;
}

impl TlsRecord {
    /// A record with every byte zero, for filling in only the fields that
    /// matter.
    ///
    /// Arrays longer than 32 elements have no `Default`, so this stands in for
    /// one. A constant, not a function, so nothing 2 KiB long is ever built on
    /// a BPF stack.
    ///
    /// ```
    /// use sipnab_bpf_types::{FLAG_HAS_TUPLE, TlsRecord};
    ///
    /// let rec = TlsRecord { pid: 7, flags: FLAG_HAS_TUPLE, ..TlsRecord::ZEROED };
    /// assert_eq!((rec.pid, rec.len, rec.family), (7, 0, 0));
    /// assert!(rec.data.iter().all(|&b| b == 0));
    /// ```
    pub const ZEROED: Self = Self {
        pid: 0,
        tid: 0,
        len: 0,
        flags: 0,
        saddr: [0; 16],
        daddr: [0; 16],
        sport: 0,
        dport: 0,
        family: 0,
        _pad: 0,
        comm: [0; 16],
        data: [0; MAX_PAYLOAD],
    };
}

/// The host's side of the contract: reading what the program wrote.
///
/// Not compiled for the BPF target. The reader returns a whole `TlsRecord` by
/// value, and 2 KiB on the stack is four times what the BPF verifier allows,
/// so the kernel half keeps its records in a map and never calls these.
#[cfg(not(target_arch = "bpf"))]
impl TlsRecord {
    /// Read one perf sample: the record's header, and the payload that is
    /// safe to use.
    ///
    /// The sample is `used_len(payload)` bytes, shorter than the struct, so it
    /// cannot be viewed in place. The header is copied out **by the struct's
    /// own layout**, never at offsets counted by hand. That is how sipnab once
    /// read `sport` from 64 when the kernel wrote it at 48, and reported every
    /// peer as `0.0.0.0:0`. The returned record's `data` holds the bytes that
    /// arrived and zeros after them.
    ///
    /// The payload is the smallest of `len`, [`MAX_PAYLOAD`] and the bytes
    /// that arrived after the header. Returns `None` for a sample shorter than
    /// [`HEADER_LEN`](Self::HEADER_LEN) rather than decoding part of a header.
    /// Every field is in the host's byte order, the order the kernel on the
    /// same machine wrote.
    ///
    /// ```
    /// use sipnab_bpf_types::{MAX_PAYLOAD, TlsRecord};
    ///
    /// let sent = TlsRecord { pid: 99, len: 7, ..TlsRecord::ZEROED };
    /// let mut sample = sent.header_bytes().to_vec();
    /// sample.extend_from_slice(b"OPTIONS sip:a SIP/2.0\r\n");
    ///
    /// // `len` bounds the payload even when more bytes arrived.
    /// let (rec, payload) = TlsRecord::read(&sample).unwrap();
    /// assert_eq!((rec.pid, payload), (99, &b"OPTIONS"[..]));
    ///
    /// // A header and nothing else is a record with nothing written.
    /// let bare = TlsRecord::read(&sample[..TlsRecord::HEADER_LEN]).unwrap();
    /// assert!(bare.1.is_empty());
    ///
    /// // One byte short of a header is refused.
    /// assert!(TlsRecord::read(&sample[..TlsRecord::HEADER_LEN - 1]).is_none());
    /// assert!(sample.len() - TlsRecord::HEADER_LEN <= MAX_PAYLOAD);
    /// ```
    #[must_use]
    pub fn read(sample: &[u8]) -> Option<(TlsRecord, &[u8])> {
        if sample.len() < Self::HEADER_LEN {
            return None;
        }
        let mut rec = Self::ZEROED;
        let n = sample.len().min(core::mem::size_of::<TlsRecord>());
        // SAFETY: `TlsRecord` is `#[repr(C)]` plain data with its padding
        // named and no pointers, so any byte pattern is a valid value. `n` is
        // bounded by the sample and by the struct, and the two do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(
                sample.as_ptr(),
                core::ptr::from_mut(&mut rec).cast::<u8>(),
                n,
            );
        }
        let arrived = sample.len() - Self::HEADER_LEN;
        let usable = (rec.len as usize).min(MAX_PAYLOAD).min(arrived);
        Some((rec, &sample[Self::HEADER_LEN..Self::HEADER_LEN + usable]))
    }

    /// The source and destination the write went out on, or `None` when the
    /// program did not observe them.
    ///
    /// `None` unless [`FLAG_HAS_TUPLE`] is set: without it the address fields
    /// hold whatever was in the buffer, and a guessed peer would look exactly
    /// like an observed one. `None` too for a family other than
    /// [`FAMILY_IPV4`] or [`FAMILY_IPV6`]. IPv4 is the first four bytes of
    /// each address, and IPv6 all sixteen.
    ///
    /// ```
    /// use core::net::SocketAddr;
    /// use sipnab_bpf_types::{FAMILY_IPV4, FLAG_HAS_TUPLE, TlsRecord};
    ///
    /// let mut rec = TlsRecord {
    ///     flags: FLAG_HAS_TUPLE,
    ///     family: FAMILY_IPV4,
    ///     sport: 40000,
    ///     dport: 5061,
    ///     ..TlsRecord::ZEROED
    /// };
    /// rec.saddr = [10, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0];
    /// rec.daddr[..4].copy_from_slice(&[10, 0, 0, 9]);
    /// assert_eq!(
    ///     rec.socket_addrs(),
    ///     Some((
    ///         "10.0.0.5:40000".parse::<SocketAddr>().unwrap(),
    ///         "10.0.0.9:5061".parse::<SocketAddr>().unwrap(),
    ///     ))
    /// );
    ///
    /// rec.flags = 0;
    /// assert_eq!(rec.socket_addrs(), None, "no FLAG_HAS_TUPLE, no peer");
    /// ```
    #[must_use]
    pub fn socket_addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        if self.flags & FLAG_HAS_TUPLE == 0 {
            return None;
        }
        let (src, dst) = match self.family {
            FAMILY_IPV4 => {
                let v4 = |a: &[u8; 16]| IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
                (v4(&self.saddr), v4(&self.daddr))
            }
            FAMILY_IPV6 => (
                IpAddr::V6(Ipv6Addr::from(self.saddr)),
                IpAddr::V6(Ipv6Addr::from(self.daddr)),
            ),
            _ => return None,
        };
        Some((
            SocketAddr::new(src, self.sport),
            SocketAddr::new(dst, self.dport),
        ))
    }

    /// The command name of the process that wrote, up to its first NUL.
    ///
    /// ```
    /// use sipnab_bpf_types::TlsRecord;
    ///
    /// let mut rec = TlsRecord::ZEROED;
    /// rec.comm[..8].copy_from_slice(b"kamailio");
    /// assert_eq!(rec.command(), b"kamailio");
    /// ```
    #[must_use]
    pub fn command(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        &self.comm[..end]
    }

    /// The first [`HEADER_LEN`](Self::HEADER_LEN) bytes of this record, as
    /// the program puts them on the ring ahead of the payload.
    ///
    /// For building samples in a test, and the inverse of [`read`](Self::read).
    ///
    /// ```
    /// use sipnab_bpf_types::TlsRecord;
    ///
    /// let sent = TlsRecord { pid: 1234, tid: 1235, ..TlsRecord::ZEROED };
    /// let sample = sent.header_bytes();
    /// assert_eq!(sample.len(), TlsRecord::HEADER_LEN);
    /// let (back, payload) = TlsRecord::read(&sample).unwrap();
    /// assert_eq!((back.pid, back.tid), (1234, 1235));
    /// assert!(payload.is_empty());
    /// ```
    #[must_use]
    pub fn header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut out = [0u8; Self::HEADER_LEN];
        // SAFETY: `TlsRecord` is `#[repr(C)]` plain data with its padding
        // named, so its first `HEADER_LEN` bytes are all initialized. `out` is
        // exactly that long, and the two do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(self).cast::<u8>(),
                out.as_mut_ptr(),
                Self::HEADER_LEN,
            );
        }
        out
    }
}

/// Where the fields of `struct sock` sit, in bytes from its start.
///
/// **Read from the running kernel's own BTF by the host and handed to the
/// program before it attaches**, rather than compiled in. `aya-ebpf` at the
/// version this builds against has no CO-RE read helpers, so a program with
/// baked-in offsets is correct only on the kernel it was built against — and
/// wrong on any other in the worst possible way, by reading whatever happens to
/// live at that offset and reporting it as an address.
///
/// Doing the lookup in userspace gets the same portability CO-RE would: the
/// offsets come from the kernel that is actually running, every time.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct SockOffsets {
    /// `__sk_common.skc_family`.
    pub family: u32,
    /// `__sk_common.skc_rcv_saddr` — local IPv4.
    pub saddr4: u32,
    /// `__sk_common.skc_daddr` — remote IPv4.
    pub daddr4: u32,
    /// `__sk_common.skc_v6_rcv_saddr` — local IPv6.
    pub saddr6: u32,
    /// `__sk_common.skc_v6_daddr` — remote IPv6.
    pub daddr6: u32,
    /// `__sk_common.skc_num` — local port, host order in the kernel.
    pub sport: u32,
    /// `__sk_common.skc_dport` — remote port, network order in the kernel.
    pub dport: u32,
    /// Set when every offset above was resolved. The program refuses to read a
    /// socket at all while this is clear, because a zero offset is a valid
    /// offset and would otherwise read the start of the struct as an address.
    pub valid: u32,
}

// SAFETY: `#[repr(C)]`, every field a fixed-size integer or an array of them,
// no padding the compiler chooses and no pointers — which is exactly what `Pod`
// asserts. `every_field_sits_where_both_halves_expect_it` pins the layout, so a
// field added without thinking fails there rather than inside a map read.
//
// Gated on the TARGET as well as the feature: `aya` is a Linux-only dependency
// (it calls `SYS_bpf` and friends), so on macOS the feature can be on while the
// crate is absent — which is exactly what `--all-features` does on the macOS CI
// job, and what turned main red twice.
#[cfg(all(feature = "pod", target_os = "linux"))]
unsafe impl aya::Pod for SockOffsets {}

// SAFETY: as above. The 2 KiB payload is a byte array; nothing here is a
// reference, and any byte pattern is a valid value.
#[cfg(all(feature = "pod", target_os = "linux"))]
unsafe impl aya::Pod for TlsRecord {}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::vec::Vec;

    const INVITE: &[u8] = b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: x\r\n\r\n";

    /// A record with a tuple, an IPv4 pair and a command name. The bytes after
    /// the first four of each address are deliberately not zero: an IPv4
    /// reader looking anywhere else reads them.
    fn ipv4_record(payload: &[u8]) -> TlsRecord {
        let mut rec = TlsRecord {
            pid: 4242,
            tid: 4243,
            len: u32::try_from(payload.len()).unwrap(),
            flags: FLAG_HAS_TUPLE,
            sport: 5061,
            dport: 5060,
            family: FAMILY_IPV4,
            ..TlsRecord::ZEROED
        };
        rec.saddr = [192, 0, 2, 10, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        rec.daddr = [198, 51, 100, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];
        rec.comm[..8].copy_from_slice(b"opensips");
        rec.data[..payload.len()].copy_from_slice(payload);
        rec
    }

    /// The sample the program submits: the record's own memory, cut to
    /// `used_len`. Viewed through a pointer, as the perf ring does, and never
    /// through `header_bytes`, so a reader and a writer that agree with each
    /// other and not with the kernel cannot pass here together.
    fn sample(rec: &TlsRecord, payload: usize) -> Vec<u8> {
        // SAFETY: `TlsRecord` is `#[repr(C)]` plain data with its padding
        // named, so every byte of it is initialized and viewing it as bytes is
        // exactly what the perf ring does.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(rec).cast::<u8>(),
                core::mem::size_of::<TlsRecord>(),
            )
        };
        bytes[..TlsRecord::used_len(payload)].to_vec()
    }

    #[test]
    fn a_short_sample_decodes() {
        let rec = ipv4_record(INVITE);
        let raw = sample(&rec, INVITE.len());
        assert!(raw.len() < core::mem::size_of::<TlsRecord>());
        let (got, payload) = TlsRecord::read(&raw).expect("a whole header decodes");
        assert_eq!(payload, INVITE);
        assert_eq!((got.pid, got.tid, got.len), (4242, 4243, 48));
        assert_eq!(got.flags, FLAG_HAS_TUPLE);
        assert_eq!(&got.data[..INVITE.len()], INVITE);
        assert!(got.data[INVITE.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_sample_shorter_than_the_header_is_refused() {
        let raw = sample(&ipv4_record(INVITE), INVITE.len());
        for n in 0..TlsRecord::HEADER_LEN {
            assert!(
                TlsRecord::read(&raw[..n]).is_none(),
                "a {n}-byte sample has no whole header and must not decode"
            );
        }
        let (_, payload) = TlsRecord::read(&raw[..TlsRecord::HEADER_LEN])
            .expect("a bare header is a record with nothing written");
        assert!(payload.is_empty());
    }

    #[test]
    fn the_payload_stops_at_len() {
        let mut rec = ipv4_record(INVITE);
        rec.len = 6;
        let raw = sample(&rec, INVITE.len());
        let (_, payload) = TlsRecord::read(&raw).unwrap();
        assert_eq!(payload, b"INVITE");
    }

    #[test]
    fn the_payload_stops_at_the_bytes_that_arrived() {
        let mut rec = ipv4_record(INVITE);
        rec.len = u32::try_from(MAX_PAYLOAD).unwrap();
        let raw = sample(&rec, INVITE.len());
        let (_, payload) = TlsRecord::read(&raw).unwrap();
        assert_eq!(payload, INVITE, "a claimed length must not widen the read");
    }

    #[test]
    fn the_payload_stops_at_max_payload() {
        // A write larger than one record, and a sample with trailing bytes:
        // perf pads a sample to a multiple of eight bytes, so more can arrive
        // than was sent.
        let mut rec = ipv4_record(&[b'x'; MAX_PAYLOAD]);
        rec.len = 5000;
        rec.flags |= FLAG_TRUNCATED;
        let mut raw = sample(&rec, MAX_PAYLOAD);
        raw.extend_from_slice(&[0xAA; 7]);
        let (got, payload) = TlsRecord::read(&raw).unwrap();
        assert_eq!(payload.len(), MAX_PAYLOAD);
        assert!(payload.iter().all(|&b| b == b'x'));
        assert_eq!(got.len, 5000, "the length the application passed survives");
        assert_ne!(got.flags & FLAG_TRUNCATED, 0);
    }

    #[test]
    fn no_tuple_flag_means_no_peer() {
        let mut rec = ipv4_record(INVITE);
        rec.flags = FLAG_TRUNCATED;
        let (got, _) = TlsRecord::read(&sample(&rec, INVITE.len())).unwrap();
        assert_eq!(
            got.socket_addrs(),
            None,
            "addresses left in the buffer must not be reported as observed"
        );
    }

    #[test]
    fn an_unknown_family_means_no_peer() {
        let mut rec = ipv4_record(INVITE);
        rec.family = 777;
        let (got, _) = TlsRecord::read(&sample(&rec, INVITE.len())).unwrap();
        assert_eq!(got.socket_addrs(), None);
    }

    #[test]
    fn ipv4_sits_in_the_first_four_bytes() {
        let (got, _) = TlsRecord::read(&sample(&ipv4_record(INVITE), INVITE.len())).unwrap();
        let (src, dst) = got.socket_addrs().expect("the tuple was observed");
        assert_eq!(
            src,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 5061)
        );
        assert_eq!(
            dst,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 5060)
        );
    }

    #[test]
    fn ipv6_uses_all_sixteen_bytes() {
        let s = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let d = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut rec = ipv4_record(INVITE);
        rec.family = FAMILY_IPV6;
        rec.saddr = s.octets();
        rec.daddr = d.octets();
        let (got, _) = TlsRecord::read(&sample(&rec, INVITE.len())).unwrap();
        assert_eq!(
            got.socket_addrs(),
            Some((
                SocketAddr::new(IpAddr::V6(s), 5061),
                SocketAddr::new(IpAddr::V6(d), 5060)
            ))
        );
    }

    #[test]
    fn the_command_stops_at_its_first_nul() {
        let rec = ipv4_record(INVITE);
        assert_eq!(rec.command(), b"opensips");
        let full = TlsRecord {
            comm: *b"sixteen-bytes-ok",
            ..TlsRecord::ZEROED
        };
        assert_eq!(full.command(), b"sixteen-bytes-ok");
        assert_eq!(TlsRecord::ZEROED.command(), b"");
    }

    /// `header_bytes` is what the program puts on the ring ahead of the
    /// payload, byte for byte.
    #[test]
    fn header_bytes_are_the_records_own_memory() {
        let rec = ipv4_record(INVITE);
        assert_eq!(
            &rec.header_bytes()[..],
            &sample(&rec, 0)[..],
            "header_bytes must match the kernel's view of the same record"
        );
    }

    #[test]
    fn the_zeroed_record_is_all_zero() {
        let z = TlsRecord::ZEROED;
        assert!(z.header_bytes().iter().all(|&b| b == 0));
        assert!(z.data.iter().all(|&b| b == 0));
    }

    /// The layout is the contract. If any of these move, a host reading a
    /// record written by a kernel program built from a different revision
    /// decodes the wrong bytes — and the result still looks like a message,
    /// which is why this is pinned rather than left to review.
    #[test]
    fn the_wire_layout_is_pinned() {
        assert_eq!(
            core::mem::size_of::<TlsRecord>(),
            TlsRecord::HEADER_LEN + MAX_PAYLOAD
        );
        assert_eq!(core::mem::align_of::<TlsRecord>(), 4);
        assert_eq!(TlsRecord::HEADER_LEN, 72, "header layout changed");
    }

    /// **Every field, not just the total size.** The header length alone was
    /// pinned once, and it passed while a reader looked for `sport` at 64 where
    /// the kernel had written it at 48 — so every captured message reported
    /// `0.0.0.0:0` while the suite stayed green. A size check cannot see a
    /// field in the wrong place; these can.
    #[test]
    fn every_field_sits_where_both_halves_expect_it() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(TlsRecord, pid), 0);
        assert_eq!(offset_of!(TlsRecord, tid), 4);
        assert_eq!(offset_of!(TlsRecord, len), 8);
        assert_eq!(offset_of!(TlsRecord, flags), 12);
        assert_eq!(offset_of!(TlsRecord, saddr), 16);
        assert_eq!(offset_of!(TlsRecord, daddr), 32);
        assert_eq!(offset_of!(TlsRecord, sport), 48);
        assert_eq!(offset_of!(TlsRecord, dport), 50);
        assert_eq!(offset_of!(TlsRecord, family), 52);
        assert_eq!(offset_of!(TlsRecord, comm), 56);
        assert_eq!(offset_of!(TlsRecord, data), 72);
        assert_eq!(
            offset_of!(TlsRecord, data),
            TlsRecord::HEADER_LEN,
            "the payload must begin exactly where the header ends"
        );
    }

    #[test]
    fn a_short_write_does_not_pay_for_the_whole_buffer() {
        assert_eq!(TlsRecord::used_len(0), TlsRecord::HEADER_LEN);
        assert!(
            TlsRecord::used_len(200) < core::mem::size_of::<TlsRecord>(),
            "a 200-byte BYE must not cost a 2 KiB ring slot"
        );
        assert_eq!(
            TlsRecord::used_len(MAX_PAYLOAD),
            core::mem::size_of::<TlsRecord>(),
            "a full payload is exactly the whole record"
        );
    }

    /// The flags answer different questions and must not be confused: one says
    /// the peer is known, the other says the message is incomplete.
    #[test]
    fn the_flags_are_independent() {
        assert_ne!(FLAG_HAS_TUPLE, FLAG_TRUNCATED);
        assert_eq!(FLAG_HAS_TUPLE & FLAG_TRUNCATED, 0);
    }
}
