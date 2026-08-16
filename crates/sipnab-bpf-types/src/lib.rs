// SPDX-License-Identifier: MIT OR Apache-2.0

//! The record the BPF program writes and sipnab reads.
//!
//! **One definition, two very different compilers.** The kernel half of the
//! uprobe backend is a `no_std` crate built for `bpfel-unknown-none` with a
//! nightly toolchain; the host half is ordinary sipnab. They exchange bytes
//! through a perf ring, so the layout has to match exactly — and the way that
//! goes wrong is not a compile error, it is a host that decodes a plausible SIP
//! message out of misaligned fields.
//!
//! So this crate exists to be the single definition. It is `no_std` and has no
//! dependencies, because everything here has to compile for a target with no
//! allocator, no `std`, and a verifier that rejects anything it cannot prove.
//!
//! # Why the layout is spelled out
//!
//! `#[repr(C)]`, fixed-size arrays, and explicit padding. Rust's default
//! representation gives no guarantee about field order, so a `repr(Rust)`
//! struct written by one compiler and read by another is undefined in practice
//! as well as in principle. The padding is named rather than implicit for the
//! same reason: a hole the compiler chooses is a hole the two halves can
//! disagree about.

#![no_std]

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
