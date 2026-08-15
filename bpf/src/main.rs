// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel half of sipnab's BPF capture backend.
//!
//! Two programs and one rule. A uprobe on the TLS library's write function sees
//! **plaintext but no socket**; a kprobe on `tcp_sendmsg` sees **the socket but
//! only ciphertext**. Neither is enough alone, and tracefs cannot join them
//! because it has no map to carry a value from one hook to the other. That join
//! is the whole reason this crate exists.
//!
//! # How the two are paired
//!
//! By **thread**, and only by thread. A TLS library encrypts on the calling
//! thread and sends on the same one, back to back, so the `tcp_sendmsg` that
//! immediately follows an `SSL_write` on thread T is that write's send. The
//! uprobe parks the plaintext under its thread id; the kprobe picks it up,
//! stamps the addresses on it, and submits it.
//!
//! # What happens when the pairing does not hold
//!
//! It is submitted **without a tuple**, never with a guessed one. If a second
//! write arrives on a thread that still has one parked — a write the TLS library
//! buffered rather than sent — the parked record goes out first with no
//! addresses attached, and the new one takes its place. So a message is never
//! lost to a missing send, and never wears a peer that belonged to a different
//! socket. The host reads [`FLAG_HAS_TUPLE`] and reports accordingly.
//!
//! # Why the struct offsets arrive at runtime
//!
//! `aya-ebpf` here has no CO-RE read helpers, so offsets compiled into this
//! program would be right on one kernel and silently wrong on the next —
//! reading whatever lives at that offset and reporting it as an address. The
//! host resolves them from the running kernel's own BTF and writes them into
//! [`OFFSETS`] before attaching. Until that happens `valid` is zero and this
//! program does not read a socket at all.

#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_buf,
};
use aya_ebpf::macros::{kprobe, map, uprobe};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerfEventArray};
use aya_ebpf::programs::ProbeContext;
use sipnab_bpf_types::{
    FAMILY_IPV4, FAMILY_IPV6, FLAG_HAS_TUPLE, FLAG_TRUNCATED, MAX_PAYLOAD, SockOffsets, TlsRecord,
};

/// Struct offsets the host resolved from BTF. One entry, index 0.
#[map]
static OFFSETS: Array<SockOffsets> = Array::with_max_entries(1, 0);

/// Plaintext parked by a thread's `SSL_write`, waiting for its `tcp_sendmsg`.
///
/// Keyed by thread id, which is the only thing that ties the two hooks
/// together. 4096 threads is far above any SIP proxy's worker count, and an
/// entry that is never claimed is replaced by that thread's next write rather
/// than accumulating.
#[map]
static PENDING: HashMap<u32, TlsRecord> = HashMap::with_max_entries(4096, 0);

/// Scratch space for building a record.
///
/// A `TlsRecord` is far larger than BPF's 512-byte stack, so it cannot be a
/// local. One per CPU, so two CPUs building records at once do not share.
#[map]
static SCRATCH: PerCpuArray<TlsRecord> = PerCpuArray::with_max_entries(1, 0);

/// Finished records, on their way to the host.
#[map]
static EVENTS: PerfEventArray<TlsRecord> = PerfEventArray::new(0);

/// SIP request methods and the response prefix, matched in kernel space.
///
/// The same fifteen tokens the tracefs backend filters on, for the same reason:
/// these probes fire on every write of every process that maps the library, so
/// dropping non-SIP traffic here is what makes the feature affordable rather
/// than an optimisation. A non-SIP write never costs a ring slot or a wakeup.
const SIP_TOKENS: [&[u8]; 15] = [
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"OPTIONS", b"REGISTER", b"PRACK", b"SUBSCRIBE",
    b"NOTIFY", b"PUBLISH", b"INFO", b"REFER", b"MESSAGE", b"UPDATE", b"SIP/2.0",
];

/// Whether `buf` starts with a SIP start-line token.
///
/// Bounded loops with constant limits, because the verifier rejects anything it
/// cannot prove terminates.
fn looks_like_sip(buf: &[u8; MAX_PAYLOAD], len: usize) -> bool {
    let mut i = 0;
    while i < SIP_TOKENS.len() {
        let tok = SIP_TOKENS[i];
        if tok.len() <= len {
            let mut j = 0;
            let mut hit = true;
            while j < tok.len() {
                if buf[j] != tok[j] {
                    hit = false;
                    break;
                }
                j += 1;
            }
            if hit {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `SSL_write(ssl, buf, num)` / `wolfSSL_write(ssl, buf, num)`.
///
/// Park the plaintext under this thread. The socket is not visible from here —
/// that is the entire problem this backend exists to solve.
#[uprobe]
pub fn sipnab_tls_write(ctx: ProbeContext) -> u32 {
    match try_tls_write(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_tls_write(ctx: &ProbeContext) -> Result<(), ()> {
    // Second and third arguments: the buffer and the length it was given.
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;
    if num <= 0 {
        // Ordinary, not a fault: TLS libraries call the write path with
        // nothing to send, and it was the majority of the first traces.
        return Err(());
    }
    let len = num as usize;
    let copy = if len > MAX_PAYLOAD { MAX_PAYLOAD } else { len };

    let slot = SCRATCH.get_ptr_mut(0).ok_or(())?;
    // SAFETY: per-CPU scratch, one entry, and this is the only writer on this
    // CPU for the duration of this program.
    let rec = unsafe { &mut *slot };

    let pid_tgid = bpf_get_current_pid_tgid();
    rec.pid = (pid_tgid >> 32) as u32;
    rec.tid = pid_tgid as u32;
    rec.len = num as u32;
    rec.flags = if len > MAX_PAYLOAD { FLAG_TRUNCATED } else { 0 };
    rec.family = 0;
    rec.sport = 0;
    rec.dport = 0;
    rec.saddr = [0u8; 16];
    rec.daddr = [0u8; 16];
    rec.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // SAFETY: reading userspace memory the application just handed the TLS
    // library. `bpf_probe_read_user_buf` faults safely and returns an error
    // rather than trapping if the pointer is bad.
    unsafe {
        bpf_probe_read_user_buf(buf, &mut rec.data[..copy]).map_err(|_| ())?;
    }

    if !looks_like_sip(&rec.data, copy) {
        return Err(());
    }

    // A record already parked for this thread means the previous write was
    // never followed by a send. Submit it now, with no addresses, rather than
    // dropping it or letting the next send stamp the wrong socket on it.
    if let Some(stale) = unsafe { PENDING.get(&rec.tid) } {
        EVENTS.output(ctx, stale, 0);
    }
    PENDING.insert(&rec.tid, rec, 0).map_err(|_| ())?;
    Ok(())
}

/// `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`.
///
/// Claim this thread's parked plaintext and stamp the socket on it.
#[kprobe]
pub fn sipnab_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<(), ()> {
    let tid = bpf_get_current_pid_tgid() as u32;
    // Nothing parked means this send carried something other than the
    // plaintext we are following. Far and away the common case: this hook
    // fires for every TCP send on the box.
    let parked = unsafe { PENDING.get(&tid) }.ok_or(())?;

    let slot = SCRATCH.get_ptr_mut(0).ok_or(())?;
    // SAFETY: as above — per-CPU, single writer.
    let rec = unsafe { &mut *slot };
    *rec = *parked;

    let off = OFFSETS.get(0).ok_or(())?;
    let sk: *const u8 = ctx.arg(0).ok_or(())?;
    // `valid` is zero until the host has resolved every offset from BTF. Zero
    // is itself a legal offset, so without this the program would read the
    // start of the struct and report it as an address.
    if off.valid != 0 && !sk.is_null() {
        stamp_socket(rec, sk, off);
    }

    EVENTS.output(ctx, rec, 0);
    let _ = PENDING.remove(&tid);
    Ok(())
}

/// Read the 5-tuple out of `struct sock` at the host-supplied offsets.
fn stamp_socket(rec: &mut TlsRecord, sk: *const u8, off: &SockOffsets) {
    // SAFETY: every read is a `bpf_probe_read_kernel`, which faults safely and
    // returns an error rather than trapping. The offsets came from the running
    // kernel's own BTF, so they name real members of this struct.
    unsafe {
        let Ok(family) = bpf_probe_read_kernel::<u16>(sk.add(off.family as usize).cast()) else {
            return;
        };
        // Kernel keeps the local port in host order and the remote in network
        // order. Both are reported host-order, so only one is swapped.
        let sport = bpf_probe_read_kernel::<u16>(sk.add(off.sport as usize).cast()).unwrap_or(0);
        let dport = bpf_probe_read_kernel::<u16>(sk.add(off.dport as usize).cast()).unwrap_or(0);

        match family {
            FAMILY_IPV4 => {
                let Ok(s) = bpf_probe_read_kernel::<u32>(sk.add(off.saddr4 as usize).cast()) else {
                    return;
                };
                let Ok(d) = bpf_probe_read_kernel::<u32>(sk.add(off.daddr4 as usize).cast()) else {
                    return;
                };
                // Kernel holds these in network order; the host expects the
                // same byte order it would have read off the wire.
                rec.saddr[..4].copy_from_slice(&s.to_ne_bytes());
                rec.daddr[..4].copy_from_slice(&d.to_ne_bytes());
            }
            FAMILY_IPV6 => {
                let Ok(s) = bpf_probe_read_kernel::<[u8; 16]>(sk.add(off.saddr6 as usize).cast())
                else {
                    return;
                };
                let Ok(d) = bpf_probe_read_kernel::<[u8; 16]>(sk.add(off.daddr6 as usize).cast())
                else {
                    return;
                };
                rec.saddr = s;
                rec.daddr = d;
            }
            // A family sipnab does not carry. Leave the record tuple-less
            // rather than reporting an address it cannot name.
            _ => return,
        }

        rec.family = family;
        rec.sport = sport;
        rec.dport = u16::from_be(dport);
        rec.flags |= FLAG_HAS_TUPLE;
    }
}

/// Required by the target, and unreachable: this program has no panics to
/// unwind and the verifier would reject one.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The license the kernel checks before permitting the helpers this uses.
///
/// The kernel refuses `bpf_probe_read_kernel` to a program that does not
/// declare a GPL-compatible license. sipnab is MIT OR Apache-2.0, and this
/// declaration selects the Dual MIT/GPL option for this object only — a
/// dual-licensing choice the project already grants, not a change to sipnab's
/// terms.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
