// SPDX-License-Identifier: MIT OR Apache-2.0

//! The host half of the BPF capture backend: load, attach, drain, convert.
//!
//! This is the backend that can answer the question the tracefs one cannot —
//! **who was the peer**. It loads the two programs from [`super`]'s kernel
//! crate, hands them the struct offsets read from the running kernel's BTF,
//! attaches a uprobe per TLS library and one kprobe on `tcp_sendmsg`, and turns
//! every record into the same [`Packet`](crate::capture::packet::Packet) the
//! tracefs reader produces.
//!
//! Loading and attaching the BPF programs needs `aya` and a built object, so
//! this half is Linux only as well as feature-gated: `aya` calls `SYS_bpf`,
//! `SYS_perf_event_open` and `CLOCK_BOOTTIME`, so it does not compile on Apple
//! at all — and `--all-features` reaches this on every platform CI builds.
//!
//! # It is not the default, deliberately
//!
//! It needs BTF, and a kernel without `CONFIG_DEBUG_INFO_BTF` has none — the
//! development host is one such machine. A backend that is unavailable on the
//! box its authors use is a backend nobody tests, so the tracefs reader stays
//! the default and this is chosen explicitly.
//!
//! # The one thing it adds, and the one thing it must not fake
//!
//! A record arrives with [`FLAG_HAS_TUPLE`](sipnab_bpf_types::FLAG_HAS_TUPLE)
//! set or clear. Set, the addresses
//! were read out of the socket the plaintext actually went out on, and the
//! packet carries them. Clear, the pairing did not hold — a write the library
//! buffered rather than sent — and the packet is built exactly as the tracefs
//! backend builds one: no addresses, port zero, the process named instead.
//! Filling in a plausible peer for the second case would make the first case
//! worthless, because nothing downstream could tell them apart.

use std::io;

use aya::maps::perf::PerfEvent;
use aya::maps::{Array, MapData, PerfEventArray};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{KProbe, UProbe};
use aya::{Ebpf, EbpfLoader};
use sipnab_bpf_types::{SockOffsets, TlsRecord};

use super::bpf_record::{assemble, decode};
use super::btf::Btf;
use super::reader::Target;
use crate::capture::channel::PacketTx;

/// The compiled kernel programs.
///
/// Built from `bpf/` by [`build.rs`](https://github.com/NormB/sipnab/blob/main/build.rs)
/// when the `bpf` feature is on, which is the only configuration that compiles
/// this module.
const PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sipnab-bpf"));

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
/// Takes the object as an argument rather than reading [`PROGRAM`] so the copy
/// is testable on a build whose object is empty.
fn aligned_copy(program: &[u8]) -> (Vec<u64>, usize) {
    let words = program.len().div_ceil(size_of::<u64>());
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` owns `words * 8` initialized bytes, and a `u64` slice may
    // be viewed as bytes — the reverse direction is the one that needs care.
    let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), words * 8) };
    bytes[..program.len()].copy_from_slice(program);
    (buf, program.len())
}

/// A loaded, attached BPF capture.
///
/// Holds the loaded object because dropping it detaches every program and
/// frees every map — the same reason the tracefs reader owns its probe guard,
/// with the difference that the kernel cleans up after this one automatically.
pub struct BpfReader {
    /// The loaded object. Dropping it detaches everything.
    _bpf: Ebpf,
    /// Per-CPU ring buffers, already opened.
    ///
    /// The **synchronous** reader, not `aya`'s async one. sipnab's capture
    /// sources are plain OS threads that own their loop; wrapping this one in
    /// a runtime would put a scheduler between the kernel ring and the channel
    /// for no benefit, and would drag `tokio` into a feature that otherwise
    /// needs none.
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<MapData>>,
    /// Reassembly buffer for the rare sample that wraps the ring boundary.
    ///
    /// The kernel writes a sample as one contiguous run only when it fits
    /// before the end of the mapping; otherwise it splits, and the reader is
    /// handed two slices. Reused across reads so the common (unsplit) case
    /// never allocates.
    stitch: Vec<u8>,
    /// Records the kernel dropped because this reader fell behind.
    lost: u64,
}

impl BpfReader {
    /// Load the programs, hand them the kernel's own struct offsets, and
    /// attach one uprobe per target plus the `tcp_sendmsg` kprobe.
    ///
    /// # Errors
    ///
    /// Every failure is reported rather than downgraded, because a capture that
    /// silently attached to nothing reads exactly like quiet traffic. A kernel
    /// with no BTF fails here by design: this backend has nothing to offer over
    /// the tracefs one without it, so falling back silently would leave an
    /// operator believing they had addresses they do not have.
    pub fn attach(targets: &[Target]) -> io::Result<Self> {
        Self::attach_program(PROGRAM, targets)
    }

    /// [`Self::attach`], with the compiled object as an argument.
    ///
    /// Separate so the refusal below is testable on EVERY build: a test that
    /// called `attach` on a build carrying the programs would try to load them.
    fn attach_program(program: &[u8], targets: &[Target]) -> io::Result<Self> {
        // Built on a machine without `bpf-linker`: the feature is compiled, the
        // kernel programs are not. Refused by name rather than attached to
        // nothing, because a capture attached to nothing reads exactly like a
        // quiet trunk.
        if program.is_empty() {
            return Err(io::Error::other(
                "this binary carries the `bpf` feature but no kernel programs: it \
                 was built on a machine without bpf-linker. Rebuild where \
                 `cargo install bpf-linker` has run, or use --uprobe-backend \
                 tracefs, which needs neither it nor BTF",
            ));
        }

        let offsets = Btf::from_sys_fs()
            .and_then(|btf| btf.sock_offsets())
            .map_err(|e| {
                io::Error::other(format!(
                    "the BPF backend needs this kernel's BTF to locate the socket \
                     addresses, and could not read it: {e}. The tracefs backend \
                     works without BTF but cannot report addresses"
                ))
            })?;

        let (aligned, len) = aligned_copy(program);
        // SAFETY: `aligned` holds at least `len` initialized bytes, and a
        // `u64` buffer is readable as bytes.
        let program = unsafe { std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), len) };
        let mut bpf = EbpfLoader::new()
            .load(program)
            .map_err(|e| io::Error::other(format!("loading the BPF programs failed: {e}")))?;

        // Written BEFORE either program attaches. The program refuses to read a
        // socket while `valid` is zero, so there is no window in which it could
        // read at offset zero and report the result as an address.
        {
            let mut map: Array<_, SockOffsets> = Array::try_from(
                bpf.map_mut("OFFSETS")
                    .ok_or_else(|| io::Error::other("the object has no OFFSETS map"))?,
            )
            .map_err(|e| io::Error::other(format!("OFFSETS is not an array: {e}")))?;
            map.set(0, offsets, 0)
                .map_err(|e| io::Error::other(format!("could not publish offsets: {e}")))?;
        }

        // The socket half first: a uprobe that fired before the kprobe existed
        // would park plaintext nothing would ever claim.
        {
            let prog: &mut KProbe = bpf
                .program_mut("sipnab_tcp_sendmsg")
                .ok_or_else(|| io::Error::other("the object has no tcp_sendmsg program"))?
                .try_into()
                .map_err(|e| io::Error::other(format!("not a kprobe: {e}")))?;
            prog.load()
                .map_err(|e| io::Error::other(format!("verifier rejected the kprobe: {e}")))?;
            prog.attach("tcp_sendmsg", 0)
                .map_err(|e| io::Error::other(format!("attaching tcp_sendmsg failed: {e}")))?;
        }

        {
            let prog: &mut UProbe = bpf
                .program_mut("sipnab_tls_write")
                .ok_or_else(|| io::Error::other("the object has no TLS write program"))?
                .try_into()
                .map_err(|e| io::Error::other(format!("not a uprobe: {e}")))?;
            prog.load()
                .map_err(|e| io::Error::other(format!("verifier rejected the uprobe: {e}")))?;
            for t in targets {
                prog.attach(t.symbol.as_str(), &t.library, UProbeScope::AllProcesses)
                    .map_err(|e| {
                        io::Error::other(format!(
                            "attaching {}:{} failed: {e}",
                            t.library.display(),
                            t.symbol
                        ))
                    })?;
            }
        }

        let mut events: PerfEventArray<_> = PerfEventArray::try_from(
            bpf.take_map("EVENTS")
                .ok_or_else(|| io::Error::other("the object has no EVENTS map"))?,
        )
        .map_err(|e| io::Error::other(format!("EVENTS is not a perf array: {e}")))?;

        let mut buffers = Vec::new();
        for cpu in aya::util::online_cpus().map_err(|(_, e)| io::Error::other(e.to_string()))? {
            let buf = events
                .open(cpu, None)
                .map_err(|e| io::Error::other(format!("opening the ring for cpu {cpu}: {e}")))?;
            buffers.push(buf);
        }
        if buffers.is_empty() {
            return Err(io::Error::other(
                "no per-CPU ring could be opened, so nothing would ever be read",
            ));
        }

        Ok(Self {
            _bpf: bpf,
            buffers,
            stitch: Vec::with_capacity(size_of::<TlsRecord>()),
            lost: 0,
        })
    }

    /// Records the kernel dropped because this reader fell behind.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Drain every ring once, sending what arrives. Returns packets sent.
    pub fn drain_once(&mut self, tx: &PacketTx, ordinal: &mut u64) -> usize {
        let mut sent = 0;
        let mut lost = 0;
        let stitch = &mut self.stitch;
        for buf in &mut self.buffers {
            // Nothing queued on this CPU is the common case: these probes fire
            // per write, and a quiet trunk writes rarely.
            if !buf.readable() {
                continue;
            }
            buf.for_each(|event| {
                let (s, l) = take_event(event, stitch, ordinal, tx);
                sent += s;
                lost += l;
            });
        }
        self.lost += lost;
        sent
    }
}

/// What one ring event contributes: `(packets sent, records lost)`.
///
/// Pulled out of [`BpfReader::drain_once`] because the ring it iterates is an
/// `aya` map that only a loaded program can open, while this -- the part that
/// decides what a sample becomes -- needs nothing but the event.
fn take_event(
    event: PerfEvent<'_>,
    stitch: &mut Vec<u8>,
    ordinal: &mut u64,
    tx: &PacketTx,
) -> (usize, u64) {
    match event {
        PerfEvent::Lost { count } => (0, count),
        PerfEvent::Sample { head, tail } => {
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

/// Run the BPF capture source to completion.
///
/// Mirrors the contract every other capture function follows: attach, signal
/// readiness once actually attached, then loop until shutdown.
///
/// **Readiness is signaled after the programs are attached, not before.** The
/// launch sequence waits on that signal before dropping privileges, and loading
/// BPF needs them.
///
/// # Errors
///
/// Propagates an attach failure after reporting it on `ready_tx`, so the caller
/// exits with a named reason rather than capturing nothing in silence.
pub fn capture_bpf(
    targets: &[crate::capture::UprobeTarget],
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> anyhow::Result<()> {
    capture_bpf_with(PROGRAM, targets, tx, ready_tx)
}

/// [`capture_bpf`], with the compiled object as an argument -- for the same
/// reason as [`BpfReader::attach_program`].
fn capture_bpf_with(
    program: &[u8],
    targets: &[crate::capture::UprobeTarget],
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> anyhow::Result<()> {
    let attach: Vec<Target> = targets
        .iter()
        .map(|t| Target {
            library: std::path::PathBuf::from(&t.library),
            symbol: t.symbol.clone(),
        })
        .collect();
    let described = attach
        .iter()
        .map(|t| format!("{}:{}", t.library.display(), t.symbol))
        .collect::<Vec<_>>()
        .join(", ");

    let mut reader = match BpfReader::attach_program(program, &attach) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("BPF capture on [{described}] failed: {e}");
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(msg.clone()));
            }
            anyhow::bail!(msg);
        }
    };
    tracing::info!(
        "BPF capture attached to {} librar{} [{described}] plus tcp_sendmsg. \
         Dialogs carry real addresses when a write and its send paired on one \
         thread, and none at all when they did not.",
        attach.len(),
        if attach.len() == 1 { "y" } else { "ies" }
    );
    if let Some(tx) = ready_tx {
        let _ = tx.send(Ok(()));
    }

    let mut ordinal = 0u64;
    while !crate::signals::shutdown_requested() {
        if reader.drain_once(&tx, &mut ordinal) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let lost = reader.lost();
    if lost > 0 {
        tracing::warn!(
            "BPF capture: the kernel dropped {lost} record(s) because this reader \
             fell behind; those messages are missing from the capture"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The host half, minus the kernel.
    //!
    //! Loading the programs needs `CAP_BPF`, a BTF-carrying kernel and a build
    //! with `bpf-linker`; the development host has none of the three and CI's
    //! coverage run has neither of the first two. So what is pinned here is
    //! everything around the load: the refusal a program-less build must give,
    //! the failure contract of the capture entry point, the aligned copy the
    //! ELF parser needs, and what one ring event turns into. `attach_program`
    //! and `capture_bpf_with` take the object as an argument precisely so an
    //! empty one can be handed in on every build -- a test that called
    //! `attach` on a build that HAS the programs would try to load them.
    use super::*;
    use crate::capture::channel::packet_channel;
    use sipnab_bpf_types::FLAG_HAS_TUPLE;

    const INVITE: &[u8] = b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: x\r\n\r\n";

    fn target(library: &str) -> Target {
        Target {
            library: std::path::PathBuf::from(library),
            symbol: "SSL_write".to_string(),
        }
    }

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
        let err = BpfReader::attach_program(&[], &[target("/lib/libssl.so.3")])
            .err()
            .expect("no programs, no capture")
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
        let (tx, _rx) = packet_channel(16);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);

        let err = capture_bpf_with(&[], &targets, tx, Some(ready_tx))
            .expect_err("a program-less build cannot capture")
            .to_string();

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
        let (tx, _rx) = packet_channel(16);
        let err = capture_bpf_with(&[], &[], tx, None)
            .expect_err("still refused")
            .to_string();
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
        let got = take_event(PerfEvent::Lost { count: 5 }, &mut stitch, &mut ordinal, &tx);
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
            PerfEvent::Sample {
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
            PerfEvent::Sample { head, tail },
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
            PerfEvent::Sample {
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
            PerfEvent::Sample {
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
