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
//! # It is not the default, deliberately
//!
//! It needs BTF, and a kernel without `CONFIG_DEBUG_INFO_BTF` has none — the
//! development host is one such machine. A backend that is unavailable on the
//! box its authors use is a backend nobody tests, so the tracefs reader stays
//! the default and this is chosen explicitly.
//!
//! # The one thing it adds, and the one thing it must not fake
//!
//! A record arrives with [`FLAG_HAS_TUPLE`] set or clear. Set, the addresses
//! were read out of the socket the plaintext actually went out on, and the
//! packet carries them. Clear, the pairing did not hold — a write the library
//! buffered rather than sent — and the packet is built exactly as the tracefs
//! backend builds one: no addresses, port zero, the process named instead.
//! Filling in a plausible peer for the second case would make the first case
//! worthless, because nothing downstream could tell them apart.

use std::io;

use aya::maps::{Array, MapData, PerfEventArray};
use aya::programs::{KProbe, UProbe};
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use sipnab_bpf_types::{SockOffsets, TlsRecord};

use super::bpf_record::decode;
use super::btf::Btf;
use super::reader::Target;
use crate::capture::channel::PacketTx;

/// TLS runs over TCP; that is not in doubt even when the addresses are.
const IP_PROTO_TCP: u8 = 6;

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
fn aligned_program() -> (Vec<u64>, usize) {
    let words = PROGRAM.len().div_ceil(size_of::<u64>());
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` owns `words * 8` initialised bytes, and a `u64` slice may
    // be viewed as bytes — the reverse direction is the one that needs care.
    let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), words * 8) };
    bytes[..PROGRAM.len()].copy_from_slice(PROGRAM);
    (buf, PROGRAM.len())
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
    /// Scratch buffers reused across reads, one set per ring.
    scratch: Vec<Vec<BytesMut>>,
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
        let offsets = Btf::from_sys_fs()
            .and_then(|btf| btf.sock_offsets())
            .map_err(|e| {
                io::Error::other(format!(
                    "the BPF backend needs this kernel's BTF to locate the socket \
                     addresses, and could not read it: {e}. The tracefs backend \
                     works without BTF but cannot report addresses"
                ))
            })?;

        let (aligned, len) = aligned_program();
        // SAFETY: `aligned` holds at least `len` initialised bytes, and a
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
                prog.attach(Some(t.symbol.as_str()), 0, &t.library, None)
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
        let mut scratch = Vec::new();
        for cpu in aya::util::online_cpus().map_err(|(_, e)| io::Error::other(e.to_string()))? {
            let buf = events
                .open(cpu, None)
                .map_err(|e| io::Error::other(format!("opening the ring for cpu {cpu}: {e}")))?;
            buffers.push(buf);
            // Built one at a time rather than with `vec![buf; 8]`: cloning a
            // `BytesMut` copies its CONTENTS, not its capacity, so the clones
            // would each have room for nothing — and `read_events` into a
            // zero-capacity buffer reads no events and reports no error, which
            // is silence indistinguishable from a quiet trunk.
            scratch.push(
                (0..8)
                    .map(|_| BytesMut::with_capacity(size_of::<TlsRecord>()))
                    .collect(),
            );
        }
        if buffers.is_empty() {
            return Err(io::Error::other(
                "no per-CPU ring could be opened, so nothing would ever be read",
            ));
        }

        Ok(Self {
            _bpf: bpf,
            buffers,
            scratch,
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
        for (i, buf) in self.buffers.iter_mut().enumerate() {
            // Nothing queued on this CPU is the common case: these probes fire
            // per write, and a quiet trunk writes rarely.
            if !buf.readable() {
                continue;
            }
            let Ok(events) = buf.read_events(&mut self.scratch[i]) else {
                continue;
            };
            self.lost += events.lost as u64;
            for slot in self.scratch[i].iter().take(events.read) {
                let Some(packet) = decode(slot, *ordinal) else {
                    continue;
                };
                if tx.send(packet).is_ok() {
                    *ordinal += 1;
                    sent += 1;
                }
            }
        }
        sent
    }
}

/// Run the BPF capture source to completion.
///
/// Mirrors the contract every other capture function follows: attach, signal
/// readiness once actually attached, then loop until shutdown.
///
/// **Readiness is signalled after the programs are attached, not before.** The
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

    let mut reader = match BpfReader::attach(&attach) {
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
