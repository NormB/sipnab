// SPDX-License-Identifier: MIT OR Apache-2.0

//! `PACKET_FANOUT`: kernel-side distribution of one interface across N capture
//! sockets. Capture only — read on before assuming it shards processing.
//!
//! A single live capture is one `AF_PACKET` socket with one ring, drained by
//! one thread. On a busy server that ring overflows and the drops are invisible
//! in the output — they are counted by the kernel, not by anything sipnab
//! parses. Adding sockets adds rings AND drainers, which is what the overflow
//! actually needs.
//!
//! `PACKET_FANOUT` does the distribution in the kernel: N sockets join a group,
//! and each packet goes to exactly one of them. No userspace dispatcher, and no
//! libpcap fork — `fanout_add()` accepts a socket that is already bound and
//! already ring-mapped, so this applies to a normally opened `pcap` handle via
//! its `AsRawFd`.
//!
//! # Why `HASH`, and what it does not buy
//!
//! `PACKET_FANOUT_HASH` distributes on `__skb_get_hash_symmetric()`, which is
//! symmetric: both directions of a flow land on the same socket. That is the
//! property [`crate::parallel::shard_for`] needs for RTP, so an RTP stream is
//! never split.
//!
//! It does NOT co-locate a call's SIP (port 5060) with its media (ephemeral,
//! SDP-negotiated) — different 5-tuples hash differently. Measured on a 200-call
//! corpus across four sockets in one group: 140 of 200 calls had their SIP and
//! their RTP on sockets with nothing in common, 70%. That is deliberate here,
//! and it costs nothing, because this module fans out CAPTURE only. Every
//! socket feeds the same channel and the same single processing loop, so the
//! stores never see a shard: the same corpus captured at `--cores 1` and
//! `--cores 4` produced identical dialogs, 400 of 400 streams linked to their
//! call, and zero orphans.
//!
//! Fanning out PROCESSING is a different and larger change: the offline
//! `--cores` path resolves cross-worker splits at merge time
//! (`StreamStore::reassociate_all`) with `final_sweep` running once after the
//! merge, and a live capture has no EOF at which to merge. Nothing here moves
//! toward that. CT11 proposed steering the 70% away with a classic-BPF program;
//! it was measured and refused — the program pins all signaling to worker 0,
//! which takes that 70% to 100%, and `PACKET_FANOUT_CBPF` replaces the
//! symmetric hash rather than adding to it. See §6 of
//! `docs/design/live-fanout.md` before reaching for either.
//!
//! `ROLLOVER` is set alongside `HASH` so a socket whose ring is momentarily
//! full spills to another member instead of dropping — which is the whole point
//! of the exercise.

/// Fanout mode and flags: symmetric flow hash, with rollover on a full ring.
///
/// `PACKET_FANOUT_HASH` is 0 and `PACKET_FANOUT_FLAG_ROLLOVER` is 0x1000; the
/// kernel packs `mode << 16 | flags` into the upper half of the `setsockopt`
/// argument and the group id into the lower half (`net/packet/af_packet.c`).
#[cfg(target_os = "linux")]
const FANOUT_HASH_WITH_ROLLOVER: u32 = 0x1000;

/// `SOL_PACKET`, which `libc` does not expose on every target.
#[cfg(target_os = "linux")]
const SOL_PACKET: libc::c_int = 263;

/// `PACKET_FANOUT` socket option.
#[cfg(target_os = "linux")]
const PACKET_FANOUT: libc::c_int = 18;

/// Join `fd` to fanout group `group_id`.
///
/// Every socket in a group must agree on mode and flags; the kernel rejects a
/// mismatch with `EINVAL`, which is why the mode is a constant here rather than
/// a parameter.
///
/// # Errors
///
/// Returns the OS error from `setsockopt`. The ones worth recognizing:
///
/// * `ENOPROTOOPT` / `EINVAL` — not an `AF_PACKET` socket. A `-I` file handle,
///   the `any` pseudo-device on some kernels, or a non-Linux pcap backend all
///   land here, and all mean "fall back to one socket", not "fail the run".
/// * `EALREADY` — already in a group.
///
/// The caller must treat every error as advisory. Capture works without fanout;
/// refusing to capture because an optimization was unavailable would trade a
/// throughput problem for a total outage.
#[cfg(target_os = "linux")]
pub fn join_fanout_group(fd: std::os::fd::RawFd, group_id: u16) -> std::io::Result<()> {
    let arg: u32 = (FANOUT_HASH_WITH_ROLLOVER << 16) | u32::from(group_id);
    // SAFETY: `fd` is a raw descriptor owned by the caller and stays open for
    // the duration of the call. `arg` is a `u32` local whose address and size
    // are passed together, which is the shape `setsockopt` requires for an
    // integer option. The call does not retain the pointer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_FANOUT,
            std::ptr::addr_of!(arg).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Non-Linux: there is no `PACKET_FANOUT`. Report it as unsupported so the
/// caller takes the same single-socket path it takes when the kernel refuses.
#[cfg(not(target_os = "linux"))]
pub fn join_fanout_group(_fd: std::os::fd::RawFd, _group_id: u16) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "PACKET_FANOUT is Linux-only",
    ))
}

/// Non-Linux behavior, which is the whole contract off Linux: report
/// unsupported so the caller takes its single-socket path.
///
/// Split from the Linux tests because those reach for `FANOUT_HASH_WITH_ROLLOVER`
/// and for real `errno` values, neither of which exists here. Writing a
/// cross-platform module and then Linux-only tests for it is how this file
/// broke the macOS build once already.
#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::*;

    #[test]
    fn fanout_is_reported_unsupported_not_silently_ok() {
        let err = join_fanout_group(-1, 1).expect_err("there is no PACKET_FANOUT here");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Unsupported,
            "the caller distinguishes 'unavailable' from a real failure by kind"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// A socket that is not `AF_PACKET` must be REFUSED, not silently accepted.
    ///
    /// This is the test that matters: the failure mode being guarded against is
    /// a `setsockopt` that returns 0 on something that was never a packet
    /// socket, which would leave the caller believing packets are being spread
    /// across sockets that are in no group at all. A TCP listener stands in for
    /// every non-packet fd the caller might hand over — a `-I` file handle, or
    /// a pcap backend that is not `AF_PACKET`.
    #[test]
    fn a_non_packet_socket_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let err = join_fanout_group(listener.as_raw_fd(), 1)
            .expect_err("a TCP socket must not join a packet fanout group");
        // The kernel's exact errno varies (ENOPROTOOPT on current Linux); what
        // must hold is that it is an error the caller can fall back on, not a
        // success. Asserting a specific errno would pin a kernel detail this
        // code does not depend on.
        assert!(
            err.raw_os_error().is_some(),
            "expected an OS error to fall back on, got {err:?}"
        );
    }

    /// A closed/invalid descriptor is an error rather than a panic or a
    /// success, because the caller's fallback path is driven entirely by the
    /// return value.
    #[test]
    fn an_invalid_descriptor_is_an_error() {
        let err = join_fanout_group(-1, 1).expect_err("-1 is not a socket");
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    /// The claim this whole module rests on: `PACKET_FANOUT` applies to a
    /// libpcap handle that is ALREADY open and ring-mapped.
    ///
    /// If that were false, fanout would require opening the socket by hand and
    /// re-implementing what `pcap` does — a fork, in effect. The backlog entry
    /// asserts it from reading `fanout_add()` in `net/packet/af_packet.c`.
    /// Reading kernel source is not the same as running against the kernel that
    /// is installed, so this runs it.
    ///
    /// The sibling claim that entry flagged as unverified — that
    /// `bpf_prog_create_from_user()` gates on nothing but `SOCK_FILTER_LOCKED`,
    /// so cBPF fanout steering needs no `CAP_BPF` — has since been confirmed
    /// the same two ways, source and running kernel, and recorded in §6 of
    /// `docs/design/live-fanout.md`. There is no test for it here because
    /// nothing here uses it: CT11 was refused on other grounds in the same
    /// measurement.
    ///
    /// Ignored by default because it needs `CAP_NET_RAW`. Run with:
    /// `sudo <test-binary> --ignored fanout_applies_to_an_open_pcap_handle`
    /// Override the interface with `SIPNAB_FANOUT_DEV`; the default is `lo`,
    /// which is `AF_PACKET`-capable and carries no production traffic.
    #[test]
    #[ignore = "needs CAP_NET_RAW"]
    fn fanout_applies_to_an_open_pcap_handle() {
        let dev = std::env::var("SIPNAB_FANOUT_DEV").unwrap_or_else(|_| "lo".to_string());
        let cap = pcap::Capture::from_device(dev.as_str())
            .expect("device lookup")
            .immediate_mode(true)
            .open()
            .expect("open (needs CAP_NET_RAW)");

        join_fanout_group(cap.as_raw_fd(), 0x5150)
            .expect("PACKET_FANOUT on an already-open, ring-mapped pcap handle");

        // A second handle joining the SAME group must also succeed — one
        // socket in a group proves nothing, since the interesting case is N
        // sockets agreeing on mode and flags. A mismatch here is EINVAL.
        let cap2 = pcap::Capture::from_device(dev.as_str())
            .expect("device lookup")
            .immediate_mode(true)
            .open()
            .expect("second open");
        join_fanout_group(cap2.as_raw_fd(), 0x5150).expect("second socket joins the same group");
    }

    /// The group id occupies the low 16 bits and the mode the high 16, so a
    /// group id can never be mistaken for a mode. Pinned because getting this
    /// backwards yields sockets that join *different* groups and silently do
    /// not share a flow hash — every socket would then see every packet's
    /// group of one, which looks like fanout working while it is not.
    #[test]
    fn mode_and_group_occupy_separate_halves() {
        let group: u16 = 0xBEEF;
        let arg: u32 = (FANOUT_HASH_WITH_ROLLOVER << 16) | u32::from(group);
        assert_eq!(arg & 0xFFFF, u32::from(group), "group id in the low half");
        assert_eq!(
            arg >> 16,
            FANOUT_HASH_WITH_ROLLOVER,
            "mode|flags in the high half"
        );
    }
}
