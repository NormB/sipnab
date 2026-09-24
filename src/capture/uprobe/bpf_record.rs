// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning one BPF record into a packet — no kernel, no `aya`, always tested.
//!
//! Split from the loader on purpose. The loader needs `aya`, a nightly-built
//! kernel object and a BTF-carrying kernel, none of which the development host
//! has — so a test living beside it would be skipped exactly where a mistake
//! costs most. This half needs none of that, and it is the half where a wrong
//! answer would be *invented*: the difference between "these are the addresses
//! the plaintext went out on" and "these are the bytes that happened to be in
//! the buffer".

use std::net::{IpAddr, Ipv4Addr};

use sipnab_bpf_types::{FLAG_TRUNCATED, MAX_PAYLOAD, TlsRecord};

#[cfg(feature = "native")]
use crate::capture::channel::PacketTx;
use crate::capture::packet::{FrameOrigin, Packet, PreParsed};

/// TLS runs over TCP; that is not in doubt even when the addresses are.
const IP_PROTO_TCP: u8 = 6;

/// Turn one raw record into a packet, or reject it.
///
/// Separate from the reader so the conversion — which is where a wrong answer
/// would be invented — is testable without a kernel.
#[must_use]
pub fn decode(raw: &[u8], ordinal: u64) -> Option<Packet> {
    // The payload is bounded inside `read` by `len`, MAX_PAYLOAD and the
    // bytes that arrived: the kernel truncated at MAX_PAYLOAD and said so, and
    // nothing past that may be read here either.
    let (rec, data) = TlsRecord::read(raw)?;
    if data.is_empty() || !crate::sip::is_sip_message(data) {
        return None;
    }

    let comm = String::from_utf8_lossy(rec.command())
        .trim()
        .replace('/', "_");

    // The whole point of this backend, and the one thing it must not fake.
    // `socket_addrs` answers `None` without FLAG_HAS_TUPLE and for a family
    // sipnab does not carry, and either is reported as no peer rather than as
    // a peer it cannot name.
    let (src, dst, sport, dport) = match rec.socket_addrs() {
        Some((s, d)) => (s.ip(), d.ip(), s.port(), d.port()),
        None => (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            0,
        ),
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
        // Read out of a process, never a frame on a wire. There is
        // nothing to re-read, so there is nothing a digest could check.
        verifiable: false,
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

// ── The loader's kernel-free half ────────────────────────────────────
//
// Pieces of `bpf.rs` that need neither `aya` nor a kernel. They live here, not
// beside the loader, for the reason at the top of this file, and for one more:
// `bpf.rs` compiles only with the `bpf` feature, which `full` leaves out, so a
// test there is counted by `cargo test --all-features` and not by
// `cargo test --features full` -- and those are the two suites that pin the
// homepage's one test count.

/// One event from a per-CPU perf ring, in terms that need no `aya`.
#[cfg(feature = "native")]
pub enum RingEvent<'a> {
    /// The kernel dropped this many records because the reader fell behind.
    Lost(u64),
    /// One record; `tail` is non-empty when it wrapped the ring's end.
    Sample {
        /// The bytes up to the ring's end.
        head: &'a [u8],
        /// The bytes that wrapped to the ring's start.
        tail: &'a [u8],
    },
}

/// What one ring event contributes: `(packets sent, records lost)`.
///
/// Pulled out of `BpfReader::drain_once` because the ring it iterates is an
/// `aya` map that only a loaded program can open, while this -- the part that
/// decides what a sample becomes -- needs nothing but the event.
#[cfg(feature = "native")]
pub fn take_event(
    event: RingEvent<'_>,
    stitch: &mut Vec<u8>,
    ordinal: &mut u64,
    tx: &PacketTx,
) -> (usize, u64) {
    match event {
        RingEvent::Lost(count) => (0, count),
        RingEvent::Sample { head, tail } => {
            // The slices borrow the kernel mapping directly, so a sample that
            // did not wrap decodes without copying.
            let raw = assemble(head, tail, stitch);
            let Some(packet) = decode(raw, *ordinal) else {
                return (0, 0);
            };
            if tx.send(packet).is_ok() {
                *ordinal += 1;
                (1, 0)
            } else {
                (0, 0)
            }
        }
    }
}

/// The program, copied into a buffer aligned for an ELF header.
///
/// **`include_bytes!` yields alignment 1**, and the ELF parser underneath `aya`
/// reads the header by casting it out of the buffer rather than copying it —
/// so a byte-aligned buffer is refused. The refusal is
/// `error parsing ELF data`, which reads as a corrupt object and sends you
/// looking at the build. Measured: the same bytes load from an aligned buffer
/// and fail from one offset by a single byte.
///
/// Backed by a `Vec<u64>` so the alignment is guaranteed by the type rather
/// than by whatever the allocator happens to return for a `Vec<u8>`.
///
/// Takes the object as an argument rather than reading the built `PROGRAM` so the copy
/// is testable on a build whose object is empty.
pub fn aligned_copy(program: &[u8]) -> (Vec<u64>, usize) {
    let words = program.len().div_ceil(size_of::<u64>());
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` owns `words * 8` initialized bytes, and a `u64` slice may
    // be viewed as bytes — the reverse direction is the one that needs care.
    let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), words * 8) };
    bytes[..program.len()].copy_from_slice(program);
    (buf, program.len())
}

/// The refusal a build without kernel programs gives, or `Ok` when it has them.
///
/// Built on a machine without `bpf-linker`: the feature is compiled, the
/// kernel programs are not. Refused by name rather than attached to nothing,
/// because a capture attached to nothing reads exactly like a quiet trunk.
///
/// # Errors
///
/// `program` is empty.
pub fn refuse_without_programs(program: &[u8]) -> std::io::Result<()> {
    if program.is_empty() {
        return Err(std::io::Error::other(
            "this binary carries the `bpf` feature but no kernel programs: it \
                 was built on a machine without bpf-linker. Rebuild where \
                 `cargo install bpf-linker` has run, or use --uprobe-backend \
                 tracefs, which needs neither it nor BTF",
        ));
    }
    Ok(())
}

/// The capture targets as the attach messages name them: `library:symbol`,
/// comma-separated, in the order given.
#[cfg(feature = "native")]
#[must_use]
pub fn describe_targets(targets: &[crate::capture::UprobeTarget]) -> String {
    targets
        .iter()
        .map(|t| format!("{}:{}", t.library, t.symbol))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A failed attach: answer readiness with the failure, then return it.
///
/// The launch sequence waits on the readiness channel before dropping the
/// privileges loading BPF needs, so the failure goes there FIRST, and the
/// same message is returned so the two cannot disagree. Nobody listening does
/// not turn it into a success.
#[cfg(feature = "native")]
pub fn attach_failed(
    described: &str,
    err: &dyn std::fmt::Display,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> anyhow::Error {
    let msg = format!("BPF capture on [{described}] failed: {err}");
    if let Some(tx) = ready_tx {
        let _ = tx.send(Err(msg.clone()));
    }
    anyhow::anyhow!(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipnab_bpf_types::FLAG_HAS_TUPLE;
    use std::net::Ipv6Addr;

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

#[cfg(all(test, feature = "native"))]
mod loader_tests {
    //! The loader's kernel-free half, moved out of `bpf.rs` with its tests.
    //!
    //! Loading the programs needs `CAP_BPF`, a BTF-carrying kernel and a build
    //! with `bpf-linker`; the development host has none of the three and CI's
    //! coverage run has neither of the first two. So what is pinned here is
    //! everything around the load: the refusal a program-less build must give,
    //! the failure contract when attaching fails, the aligned copy the ELF
    //! parser needs, and what one ring event turns into.
    use super::*;
    use crate::capture::channel::packet_channel;
    use sipnab_bpf_types::FLAG_HAS_TUPLE;

    const INVITE: &[u8] = b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: x\r\n\r\n";

    /// One record as the kernel program emits it, every field placed at the
    /// offset the shared type gives it -- never at a hand-counted one (see
    /// `bpf_record`'s tests for why that matters).
    fn record(payload: &[u8]) -> Vec<u8> {
        use std::mem::offset_of;
        let mut raw = vec![0u8; TlsRecord::HEADER_LEN + payload.len()];
        let mut put = |at: usize, bytes: &[u8]| raw[at..at + bytes.len()].copy_from_slice(bytes);
        put(offset_of!(TlsRecord, pid), &4242u32.to_ne_bytes());
        put(offset_of!(TlsRecord, tid), &4243u32.to_ne_bytes());
        put(
            offset_of!(TlsRecord, len),
            &(payload.len() as u32).to_ne_bytes(),
        );
        put(offset_of!(TlsRecord, flags), &FLAG_HAS_TUPLE.to_ne_bytes());
        put(offset_of!(TlsRecord, saddr), &[203, 0, 113, 5]);
        put(offset_of!(TlsRecord, daddr), &[198, 51, 100, 9]);
        put(offset_of!(TlsRecord, sport), &5061u16.to_ne_bytes());
        put(offset_of!(TlsRecord, dport), &5060u16.to_ne_bytes());
        put(
            offset_of!(TlsRecord, family),
            &sipnab_bpf_types::FAMILY_IPV4.to_ne_bytes(),
        );
        put(offset_of!(TlsRecord, comm), b"opensips");
        put(offset_of!(TlsRecord, data), payload);
        raw
    }

    /// A build without `bpf-linker` carries the feature and no programs. It
    /// must refuse by name and point at the backend that works, never attach
    /// to nothing and read as a quiet trunk.
    #[test]
    fn a_build_without_kernel_programs_is_refused_by_name() {
        let err = refuse_without_programs(&[])
            .expect_err("no programs, no capture")
            .to_string();
        assert!(err.contains("no kernel programs"), "{err}");
        assert!(
            err.contains("--uprobe-backend tracefs"),
            "the refusal names the way forward: {err}"
        );
    }

    /// The failure is on the readiness channel BEFORE it is returned, with
    /// every target named: the launch sequence waits on that channel before
    /// dropping the privileges loading BPF needs.
    #[test]
    fn a_failed_attach_is_reported_on_the_ready_channel_with_every_target_named() {
        let targets = [
            crate::capture::UprobeTarget {
                library: "/lib/libssl.so.3".to_string(),
                symbol: "SSL_write".to_string(),
            },
            crate::capture::UprobeTarget {
                library: "/lib/libwolfssl.so.42".to_string(),
                symbol: "wolfSSL_write".to_string(),
            },
        ];
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let refusal = refuse_without_programs(&[]).expect_err("no programs");

        let err = attach_failed(&describe_targets(&targets), &refusal, Some(ready_tx)).to_string();

        let reported = ready_rx
            .try_recv()
            .expect("readiness must be answered")
            .expect_err("and the answer is a failure");
        assert_eq!(reported, err, "one message, both places");
        assert!(
            err.starts_with(
                "BPF capture on [/lib/libssl.so.3:SSL_write, \
                 /lib/libwolfssl.so.42:wolfSSL_write] failed:"
            ),
            "{err}"
        );
    }

    /// Nobody waiting on readiness does not turn the failure into a success.
    #[test]
    fn a_failed_attach_without_a_ready_channel_still_fails() {
        let refusal = refuse_without_programs(&[]).expect_err("no programs");
        let err = attach_failed("", &refusal, None).to_string();
        assert!(err.contains("no kernel programs"), "{err}");
    }

    /// The copy handed to the ELF parser is the object byte for byte, whole
    /// words long, zero-padded, and reports the object's own length -- for
    /// lengths on, off and either side of a word boundary.
    #[test]
    fn the_aligned_copy_is_the_object_byte_for_byte_on_a_word_boundary() {
        for len in [0usize, 1, 7, 8, 9, 1001] {
            let object: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
            let (words, n) = aligned_copy(&object);
            assert_eq!(n, len, "the object's length, not the buffer's");
            assert_eq!(words.len(), len.div_ceil(8), "whole words, no more");
            assert_eq!(
                words.as_ptr() as usize % align_of::<u64>(),
                0,
                "the parser casts the header out of this buffer"
            );
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
            assert_eq!(&bytes[..len], &object[..], "len {len}");
            assert!(
                bytes[len..].iter().all(|&b| b == 0),
                "the tail of the last word is padding, not garbage: len {len}"
            );
        }
    }

    // ── One ring event ───────────────────────────────────────────────────

    /// A lost-records event is counted and sends nothing.
    #[test]
    fn a_lost_event_is_counted_and_sends_nothing() {
        let (tx, rx) = packet_channel(16);
        let (mut stitch, mut ordinal) = (Vec::new(), 7u64);
        let got = take_event(RingEvent::Lost(5), &mut stitch, &mut ordinal, &tx);
        assert_eq!(got, (0, 5));
        assert_eq!(ordinal, 7, "no packet, no ordinal");
        assert!(rx.try_iter().next().is_none());
    }

    /// A sample becomes one packet carrying the running ordinal, which then
    /// advances -- the ordinal is the reader's, threaded across sweeps.
    #[test]
    fn a_sample_becomes_one_packet_carrying_the_running_ordinal() {
        let (tx, rx) = packet_channel(16);
        let raw = record(INVITE);
        let (mut stitch, mut ordinal) = (Vec::new(), 41u64);

        let got = take_event(
            RingEvent::Sample {
                head: &raw,
                tail: &[],
            },
            &mut stitch,
            &mut ordinal,
            &tx,
        );

        assert_eq!(got, (1, 0));
        assert_eq!(ordinal, 42);
        let pkt = rx.try_iter().next().expect("a packet");
        assert_eq!(&pkt.data[..], INVITE);
        assert_eq!(pkt.origin.map(|o| o.ordinal), Some(41));
        assert_eq!(
            pkt.pre_parsed.as_ref().map(|p| p.dst_port),
            Some(5060),
            "the tuple the kernel read out of the socket survives"
        );
    }

    /// A sample the kernel split across the ring boundary decodes exactly as
    /// the contiguous one does.
    #[test]
    fn a_split_sample_is_stitched_before_it_is_decoded() {
        let (tx, rx) = packet_channel(16);
        let raw = record(INVITE);
        let (head, tail) = raw.split_at(TlsRecord::HEADER_LEN + 10);
        let (mut stitch, mut ordinal) = (Vec::new(), 0u64);

        let got = take_event(
            RingEvent::Sample { head, tail },
            &mut stitch,
            &mut ordinal,
            &tx,
        );

        assert_eq!(got, (1, 0));
        assert_eq!(&rx.try_iter().next().expect("a packet").data[..], INVITE);
    }

    /// A record that is not SIP sends nothing and does not consume an ordinal.
    #[test]
    fn a_sample_that_is_not_sip_sends_nothing_and_keeps_the_ordinal() {
        let (tx, rx) = packet_channel(16);
        let raw = record(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let (mut stitch, mut ordinal) = (Vec::new(), 3u64);
        let got = take_event(
            RingEvent::Sample {
                head: &raw,
                tail: &[],
            },
            &mut stitch,
            &mut ordinal,
            &tx,
        );
        assert_eq!(got, (0, 0));
        assert_eq!(ordinal, 3);
        assert!(rx.try_iter().next().is_none());
    }

    /// A packet nobody can receive is not numbered, so the next one that is
    /// delivered still carries the next ordinal.
    #[test]
    fn a_closed_channel_sends_nothing_and_keeps_the_ordinal() {
        let (tx, rx) = packet_channel(16);
        drop(rx);
        let raw = record(INVITE);
        let (mut stitch, mut ordinal) = (Vec::new(), 9u64);
        let got = take_event(
            RingEvent::Sample {
                head: &raw,
                tail: &[],
            },
            &mut stitch,
            &mut ordinal,
            &tx,
        );
        assert_eq!(got, (0, 0));
        assert_eq!(ordinal, 9);
    }
}
