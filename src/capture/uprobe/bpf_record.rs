// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning one BPF record into a packet.
//!
//! Split from the loader on purpose. The loader needs `aya`, a nightly-built
//! kernel object and a BTF-carrying kernel, none of which the development host
//! has — so a test living beside it would be skipped exactly where a mistake
//! costs most. This half needs none of that, and it is the half where a wrong
//! answer would be *invented*: the difference between "these are the addresses
//! the plaintext went out on" and "these are the bytes that happened to be in
//! the buffer".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sipnab_bpf_types::{FLAG_HAS_TUPLE, FLAG_TRUNCATED, MAX_PAYLOAD, TlsRecord};

use crate::capture::packet::{FrameOrigin, Packet, PreParsed};

/// TLS runs over TCP; that is not in doubt even when the addresses are.
const IP_PROTO_TCP: u8 = 6;

/// Turn one raw record into a packet, or reject it.
///
/// Separate from the reader so the conversion — which is where a wrong answer
/// would be invented — is testable without a kernel.
#[must_use]
pub fn decode(raw: &[u8], ordinal: u64) -> Option<Packet> {
    let rec = read_record(raw)?;

    // Only what the application wrote, bounded by what the record can hold.
    // The kernel truncated at MAX_PAYLOAD and said so; nothing past that may
    // be read here either.
    let available = raw.len() - TlsRecord::HEADER_LEN;
    let usable = (rec.len as usize).min(MAX_PAYLOAD).min(available);
    if usable == 0 {
        return None;
    }
    let data = &raw[TlsRecord::HEADER_LEN..TlsRecord::HEADER_LEN + usable];
    if !crate::sip::is_sip_message(data) {
        return None;
    }

    let end = rec
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(rec.comm.len());
    let comm = String::from_utf8_lossy(&rec.comm[..end])
        .trim()
        .replace('/', "_");

    // The whole point of this backend, and the one thing it must not fake.
    let (src, dst, sport, dport) = if rec.flags & FLAG_HAS_TUPLE != 0 {
        match rec.family {
            sipnab_bpf_types::FAMILY_IPV4 => {
                let s = IpAddr::V4(Ipv4Addr::new(
                    rec.saddr[0],
                    rec.saddr[1],
                    rec.saddr[2],
                    rec.saddr[3],
                ));
                let d = IpAddr::V4(Ipv4Addr::new(
                    rec.daddr[0],
                    rec.daddr[1],
                    rec.daddr[2],
                    rec.daddr[3],
                ));
                (s, d, rec.sport, rec.dport)
            }
            sipnab_bpf_types::FAMILY_IPV6 => (
                IpAddr::V6(Ipv6Addr::from(rec.saddr)),
                IpAddr::V6(Ipv6Addr::from(rec.daddr)),
                rec.sport,
                rec.dport,
            ),
            // A family sipnab does not carry. Reported as no peer rather than
            // as a peer it cannot name.
            _ => (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                0,
            ),
        }
    } else {
        (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            0,
        )
    };

    let mut pkt = Packet::with_pre_parsed(
        chrono::Utc::now(),
        data.to_vec(),
        Some(format!("uprobe:{comm}/{pid}", pid = rec.pid)),
        PreParsed {
            src_addr: src,
            dst_addr: dst,
            src_port: sport,
            dst_port: dport,
            ip_protocol: IP_PROTO_TCP,
            // A uprobe read has no wrapper to assert anything.
            hep: None,
        },
    );
    // No digest, and none is possible: a digest exists so a resolver can prove
    // it found the same bytes again, and these cannot be read twice.
    pkt.origin = Some(FrameOrigin {
        ordinal,
        digest: None,
    });
    if rec.flags & FLAG_TRUNCATED != 0 {
        tracing::debug!(
            "bpf: a {}-byte write from {comm}/{} exceeded the {MAX_PAYLOAD}-byte \
             record and reached sipnab as a prefix",
            rec.len,
            rec.pid
        );
    }
    Some(pkt)
}

/// Read the record header **by field**, never by hand-counted offset.
///
/// This function exists because hand-counted offsets were wrong once already
/// and the tests were wrong in the same way, so they agreed with each other and
/// not with the kernel: `sport` sat at 48 and was read from 64. Every address
/// came back as `0.0.0.0:0` on a capture where the kernel had recorded the
/// peer perfectly well.
///
/// Copying into the shared `#[repr(C)]` type makes the layout the single
/// source of truth for both halves — the same reason the type lives in its own
/// crate. Returns `None` for a record too short to hold a header rather than
/// decoding a partial one.
fn read_record(raw: &[u8]) -> Option<TlsRecord> {
    if raw.len() < TlsRecord::HEADER_LEN {
        return None;
    }
    // Zeroed, then overwritten with as much as arrived: a record carrying a
    // short payload is shorter than the full struct, and the tail is padding
    // this never reads.
    let mut rec = TlsRecord {
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
    let n = raw.len().min(size_of::<TlsRecord>());
    // SAFETY: `rec` is `#[repr(C)]` plain data with no padding the compiler
    // chose and no pointers, so any byte pattern is a valid value; `n` is
    // bounded by both buffers.
    unsafe {
        std::ptr::copy_nonoverlapping(raw.as_ptr(), std::ptr::from_mut(&mut rec).cast::<u8>(), n);
    }
    Some(rec)
}

/// Present a perf sample as one contiguous record.
///
/// The kernel writes a sample in one run only when it fits before the end of
/// the ring; otherwise it wraps, and the reader is handed the two pieces. The
/// common case borrows the mapping directly and copies nothing — `stitch` is
/// touched only for the sample that actually wrapped, and is reused across
/// reads so that case does not allocate either.
///
/// Lives here rather than beside the reader on purpose: this module is the one
/// that compiles and runs its tests without the `bpf` feature, a kernel, or
/// `aya`. A wrapped sample is rare and load-dependent, so a bug in reassembly
/// would otherwise be found by a capture rather than by the suite.
pub fn assemble<'a>(head: &'a [u8], tail: &[u8], stitch: &'a mut Vec<u8>) -> &'a [u8] {
    if tail.is_empty() {
        return head;
    }
    stitch.clear();
    stitch.extend_from_slice(head);
    stitch.extend_from_slice(tail);
    stitch.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a record **through the shared type**, exactly as the kernel does.
    ///
    /// Never by writing bytes at hand-counted offsets. That is precisely how
    /// the first version of this file went wrong: the test and the code agreed
    /// with each other and disagreed with the kernel, so a green suite sat on
    /// top of a capture that reported `0.0.0.0:0` for every message.
    fn record(flags: u32, family: u16, payload: &[u8]) -> Vec<u8> {
        let mut rec = TlsRecord {
            pid: 4242,
            tid: 4243,
            len: payload.len() as u32,
            flags,
            saddr: [0; 16],
            daddr: [0; 16],
            sport: 5061,
            dport: 5060,
            family,
            _pad: 0,
            comm: [0; 16],
            data: [0; MAX_PAYLOAD],
        };
        // 203.0.113.5 -> 198.51.100.9, in the byte order the kernel stores.
        rec.saddr[..4].copy_from_slice(&[203, 0, 113, 5]);
        rec.daddr[..4].copy_from_slice(&[198, 51, 100, 9]);
        rec.comm[..8].copy_from_slice(b"opensips");
        rec.data[..payload.len()].copy_from_slice(payload);

        // SAFETY: `TlsRecord` is `#[repr(C)]` plain data; viewing it as bytes
        // is exactly what the perf ring does.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&rec).cast::<u8>(),
                size_of::<TlsRecord>(),
            )
        };
        bytes[..TlsRecord::HEADER_LEN + payload.len()].to_vec()
    }

    /// Set an IPv6 pair on an already-built record, through the same type.
    fn with_ipv6(payload: &[u8], s: Ipv6Addr, d: Ipv6Addr) -> Vec<u8> {
        let mut raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV6, payload);
        // Offsets taken from the type, not counted by hand.
        let base = std::mem::offset_of!(TlsRecord, saddr);
        let dbase = std::mem::offset_of!(TlsRecord, daddr);
        raw[base..base + 16].copy_from_slice(&s.octets());
        raw[dbase..dbase + 16].copy_from_slice(&d.octets());
        raw
    }

    const INVITE: &[u8] = b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: x\r\n\r\n";

    /// **The reason this backend exists.** With the tuple flag set, the packet
    /// carries the addresses the plaintext actually went out on.
    #[test]
    fn a_record_with_a_tuple_produces_a_packet_with_real_addresses() {
        let raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        let pkt = decode(&raw, 7).expect("a SIP record decodes");
        let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");

        assert_eq!(meta.src_addr.to_string(), "203.0.113.5");
        assert_eq!(meta.dst_addr.to_string(), "198.51.100.9");
        assert_eq!(meta.src_port, 5061);
        assert_eq!(meta.dst_port, 5060);
        assert_eq!(meta.ip_protocol, IP_PROTO_TCP);
        assert!(pkt.interface.as_deref().unwrap().contains("opensips"));
    }

    /// **And the rule that makes the above worth anything.** Without the flag,
    /// the packet must look exactly like a tracefs one — no peer at all —
    /// rather than carrying whatever happened to be in the record.
    #[test]
    fn a_record_without_a_tuple_claims_no_peer_at_all() {
        // Addresses ARE present in the bytes; the flag says they were not
        // observed for this write. The flag wins.
        let raw = record(0, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        let pkt = decode(&raw, 0).expect("still a SIP record");
        let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");

        assert!(
            meta.src_addr.is_unspecified() && meta.dst_addr.is_unspecified(),
            "an unpaired write must not wear the addresses left in the buffer"
        );
        assert_eq!(meta.src_port, 0);
        assert_eq!(meta.dst_port, 0);
    }

    /// A family sipnab does not carry is reported as no peer, not as a peer it
    /// cannot name.
    #[test]
    fn an_unknown_address_family_yields_no_peer() {
        let raw = record(FLAG_HAS_TUPLE, 777, INVITE);
        let pkt = decode(&raw, 0).expect("decodes");
        let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");
        assert!(meta.src_addr.is_unspecified() && meta.dst_addr.is_unspecified());
    }

    #[test]
    fn ipv6_addresses_survive_the_round_trip() {
        let raw = with_ipv6(
            INVITE,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        );
        let pkt = decode(&raw, 0).expect("decodes");
        let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");
        assert_eq!(meta.src_addr.to_string(), "2001:db8::1");
        assert_eq!(meta.dst_addr.to_string(), "2001:db8::2");
    }

    /// Non-SIP never reaches a dialog store. The kernel filters too, but a
    /// record that slipped through must not be treated as a message here.
    #[test]
    fn a_non_sip_record_is_rejected() {
        let raw = record(
            FLAG_HAS_TUPLE,
            sipnab_bpf_types::FAMILY_IPV4,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        assert!(decode(&raw, 0).is_none());
    }

    /// A record shorter than its own header cannot be decoded into anything,
    /// and must not be decoded into something that looks like a message.
    #[test]
    fn a_short_record_is_refused_rather_than_decoded_partially() {
        assert!(decode(&[0u8; 8], 0).is_none());
        assert!(decode(&[], 0).is_none());
    }

    /// A length longer than the bytes present must not read past them.
    #[test]
    fn a_length_larger_than_the_payload_is_clamped() {
        let mut raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        // Claim a full 2 KiB write while carrying only the INVITE.
        let at = std::mem::offset_of!(TlsRecord, len);
        raw[at..at + 4].copy_from_slice(&(MAX_PAYLOAD as u32).to_ne_bytes());
        let pkt = decode(&raw, 0).expect("decodes what is actually there");
        assert_eq!(
            pkt.data.len(),
            INVITE.len(),
            "the claimed length must never widen the read past the record"
        );
    }

    /// The pointer must survive, and must still refuse to name a frame.
    #[test]
    fn the_packet_carries_a_pointer_that_cannot_be_resolved_to_a_frame() {
        let raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        let pkt = decode(&raw, 9).expect("decodes");
        let loc = pkt.frame_locator().expect("both halves present");
        assert_eq!(loc.origin.ordinal, 9);
        assert!(loc.origin.digest.is_none());
        let r = pkt.frame_ref().expect("owned pointer");
        assert!(matches!(
            r.source_kind(),
            crate::capture::packet::FrameSource::Uprobe { pid: 4242, .. }
        ));
    }

    /// **A sample that wrapped the ring must decode to the same packet.**
    ///
    /// Swept across every split point rather than one chosen boundary,
    /// because the interesting ones are precisely the offsets a hand-picked
    /// case misses: inside the header, on a field edge, and one byte either
    /// side of the header/payload seam.
    #[test]
    fn a_wrapped_sample_decodes_the_same_as_a_contiguous_one() {
        let raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        let whole = decode(&raw, 7).expect("the contiguous record decodes");
        let expected = whole.pre_parsed.as_ref().expect("pre-parsed");

        let mut stitch = Vec::new();
        for split in 0..=raw.len() {
            let (head, tail) = raw.split_at(split);
            let joined = assemble(head, tail, &mut stitch);
            assert_eq!(joined, &raw[..], "split at {split} lost or reordered bytes");

            let pkt =
                decode(joined, 7).unwrap_or_else(|| panic!("split at {split} failed to decode"));
            let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");
            assert_eq!(meta.src_addr, expected.src_addr, "split at {split}");
            assert_eq!(meta.dst_addr, expected.dst_addr, "split at {split}");
            assert_eq!(meta.src_port, expected.src_port, "split at {split}");
            assert_eq!(meta.dst_port, expected.dst_port, "split at {split}");
            assert_eq!(pkt.data, whole.data, "split at {split}");
        }
    }

    /// The unwrapped case must not pay for the wrapped one.
    ///
    /// Asserts the EFFECT — that nothing was copied — by observing that the
    /// reassembly buffer was never written, and that the returned slice is the
    /// caller's own memory rather than a duplicate of it.
    #[test]
    fn a_contiguous_sample_is_borrowed_not_copied() {
        let raw = record(FLAG_HAS_TUPLE, sipnab_bpf_types::FAMILY_IPV4, INVITE);
        let mut stitch = Vec::new();

        let got = assemble(&raw, &[], &mut stitch);
        assert_eq!(got.as_ptr(), raw.as_ptr(), "the sample was copied");
        assert!(stitch.is_empty(), "the reassembly buffer was touched");
    }
}
