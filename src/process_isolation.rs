// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process isolation for the one part of sipnab that transmits (D16).
//!
//! `--kill-scanner` answers a detected scanner with a real SIP response on a
//! real socket. The worker that does it runs as a process of its own:
//! [`spawn_scanner_kill_worker`] re-executes this binary as the
//! [`worker_process`], hands it every descriptor it may send through, and
//! closes its own copies. The process that parses captured traffic — libpcap,
//! the parsers, TLS key material, bearer tokens — then holds no kill-path send
//! socket, and a bug reached from a packet cannot reach one.
//!
//! # The capability model
//!
//! [`TransmitPermit`] is a zero-sized proof that only the transmit guard can
//! construct, and a token cannot cross a pipe: a worker that re-derived one
//! from an argument would be deciding its own permission. So the permit never
//! leaves this process. The worker's capability is the set of descriptors it
//! inherits, and every one of them is created here under a permit —
//! [`RawKillSocket::open`] and the two ephemeral UDP sockets bound in
//! [`spawn_scanner_kill_worker`]. The worker never calls `socket()`; holding
//! no descriptor it refuses every request, so "no permit" and "no descriptor"
//! are one refusal. It holds no secret either: it starts with an emptied
//! environment apart from a short allowlist, so a bearer token or signing key
//! the parent read from its environment stays behind.
//!
//! # What the boundary does not cover
//!
//! Stated because an isolation claim nobody can bound is one nobody can rely
//! on. The parsing process can still open an ordinary UDP socket, as any
//! process of its user can; what it no longer holds is the kill path's
//! sockets, and in particular the raw, source-spoofing one. On a run started
//! as root that socket needs `CAP_NET_RAW`, which the parsing process gives up
//! at the privilege drop (and keeps under `--no-priv-drop`). A run installed with `--setup-caps` is not root and
//! keeps its file capabilities for the whole run, so there the parsing process
//! could still open a raw socket of its own; shedding those after the capture
//! opens is not done here. The worker runs without a syscall filter of its
//! own, and without the parent's chroot and Landlock domain, both of which it
//! is started before.
//!
//! # The capture thread never waits on this module
//!
//! Isolation is only isolation if the isolated worker cannot stall the thread
//! that feeds it. The capture loop offers kill requests *while holding the
//! dialog and stream write locks*, so a wait here is a wait for packet
//! processing and for every reader of those stores — the REST API, the TUI
//! and every MCP tool. [`ScannerKillHandle::send_kill`] therefore only ever
//! OFFERS a request to a bounded queue. The pipe write that can block belongs
//! to a forwarding thread, the pipe read to a reader thread, and a stopped or
//! wedged worker backs up into a full queue and a counted, logged drop
//! ([`KillCounts`]) rather than into the capture thread.
//!
//! It used to be the other way round. The worker, then a thread, published
//! each outcome with a blocking send onto a 256-slot channel that nothing in
//! production drained; it stalled on outcome 257, stopped draining requests,
//! the request queue filled behind it, and the capture thread blocked forever
//! handing over the next one. `--kill-scanner` on busy traffic therefore froze
//! the capture and the whole MCP surface, permanently, after about 512
//! detections.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender, TrySendError};
use serde::{Deserialize, Serialize};

use crate::security::transmit_guard::TransmitPermit;

pub mod worker_process;

/// `IPV6_HDRINCL` socket option (Linux ≥4.5) — not exposed by the `libc`
/// crate, so we name the kernel constant directly.
#[cfg(target_os = "linux")]
const IPV6_HDRINCL: libc::c_int = 36;

/// Raw sockets (`IP_HDRINCL` / `IPV6_HDRINCL`) for source-spoofed
/// scanner-kill responses.
///
/// Must be opened during the privileged window (before `drop_privileges`),
/// since they need `CAP_NET_RAW`; they are then moved into the worker thread
/// and remain usable after the drop. Linux-only — on other platforms `open`
/// returns an error and the worker falls back to the ephemeral UDP send. Each
/// family is opened best-effort: a host without an IPv6 stack still spoofs
/// IPv4, and vice-versa.
pub struct RawKillSocket {
    /// Raw IPv4 send socket (`IP_HDRINCL`); `None` if that family failed to open.
    #[cfg(target_os = "linux")]
    fd_v4: Option<std::os::fd::OwnedFd>,
    /// Raw IPv6 send socket; `None` if that family failed to open.
    #[cfg(target_os = "linux")]
    fd_v6: Option<std::os::fd::OwnedFd>,
}

impl RawKillSocket {
    /// Open a raw `SOCK_RAW`/`IPPROTO_RAW` socket for `domain`. `IPPROTO_RAW`
    /// already implies header inclusion (we supply the full IP header). For
    /// IPv4 we still set `IP_HDRINCL` explicitly (`hdrincl`); for IPv6 the
    /// `IPPROTO_RAW` socket includes the header implicitly and setting
    /// `IPV6_HDRINCL` is unnecessary and rejected on some kernels, so it is
    /// applied best-effort and its failure is ignored.
    #[cfg(target_os = "linux")]
    fn open_family(
        domain: libc::c_int,
        hdrincl: Option<(libc::c_int, libc::c_int)>,
        hdrincl_required: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        // SAFETY: raw syscall; the returned fd is immediately adopted by an
        // OwnedFd so it is closed exactly once on drop.
        let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid, owned descriptor from socket() above;
        // adopting it here gives it a single owner that closes it on drop.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        if let Some((level, name)) = hdrincl {
            let one: libc::c_int = 1;
            // SAFETY: fd is valid; &one outlives the call.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    std::ptr::addr_of!(one).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 && hdrincl_required {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(owned)
    }

    /// Open the raw IPv4 and IPv6 send sockets. Requires `CAP_NET_RAW`; call
    /// before dropping privileges. Succeeds if at least one family opens; the
    /// IPv4 error is surfaced when both fail (the common permission case).
    ///
    /// Takes a [`TransmitPermit`] because this creates a descriptor the kill
    /// worker process will send through, and the worker's only capability is
    /// the descriptors it inherits: a run reading a capture file has no permit,
    /// so it cannot create one to hand over. See
    /// [`crate::security::transmit_guard`].
    #[cfg(target_os = "linux")]
    pub fn open(_permit: &TransmitPermit) -> std::io::Result<Self> {
        let v4 = Self::open_family(
            libc::AF_INET,
            Some((libc::IPPROTO_IP, libc::IP_HDRINCL)),
            true,
        );
        // IPPROTO_RAW already includes the IPv6 header; IPV6_HDRINCL is a
        // best-effort belt-and-braces (ignored if the kernel rejects it).
        let v6 = Self::open_family(
            libc::AF_INET6,
            Some((libc::IPPROTO_IPV6, IPV6_HDRINCL)),
            false,
        );
        match (v4, v6) {
            (Ok(a), b) => Ok(Self {
                fd_v4: Some(a),
                fd_v6: b.ok(),
            }),
            (Err(_), Ok(b)) => Ok(Self {
                fd_v4: None,
                fd_v6: Some(b),
            }),
            // Both failed — report the IPv4 error (usually EPERM).
            (Err(e4), Err(_)) => Err(e4),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_permit: &TransmitPermit) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket kill-response spoofing is only supported on Linux",
        ))
    }

    /// Give up both descriptors, to hand them to the worker process.
    #[cfg(target_os = "linux")]
    fn into_fds(self) -> (Option<std::os::fd::OwnedFd>, Option<std::os::fd::OwnedFd>) {
        (self.fd_v4, self.fd_v6)
    }

    /// No raw socket exists off Linux, so there is nothing to give up.
    #[cfg(not(target_os = "linux"))]
    fn into_fds(self) -> (Option<std::os::fd::OwnedFd>, Option<std::os::fd::OwnedFd>) {
        (None, None)
    }

    /// Wrap descriptors the worker process inherited.
    ///
    /// The only constructor besides [`Self::open`], and it creates nothing: it
    /// adopts sockets a parent holding a [`TransmitPermit`] opened and placed
    /// at the worker's fixed slots, after the worker has checked each one's
    /// family and type.
    #[cfg(target_os = "linux")]
    fn from_inherited(
        fd_v4: Option<std::os::fd::OwnedFd>,
        fd_v6: Option<std::os::fd::OwnedFd>,
    ) -> Self {
        Self { fd_v4, fd_v6 }
    }

    /// Off Linux nothing sends through a raw socket, so an inherited one is
    /// dropped (and closed) rather than wrapped.
    #[cfg(not(target_os = "linux"))]
    fn from_inherited(
        _fd_v4: Option<std::os::fd::OwnedFd>,
        _fd_v6: Option<std::os::fd::OwnedFd>,
    ) -> Self {
        Self {}
    }

    /// Send a pre-built IPv4 datagram (its own IP header carries the spoofed
    /// source) to `dst`. The kernel routes on `dst`; the datagram's L3/L4
    /// headers are ours.
    ///
    /// Takes no permit: holding the socket IS the capability. Only
    /// [`Self::open`] creates one, and it demands a [`TransmitPermit`]; the
    /// kill worker process holds one only because a parent with a permit
    /// opened it and handed it over.
    #[cfg(target_os = "linux")]
    fn send_to_v4(&self, packet: &[u8], dst: SocketAddrV4) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.fd_v4.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Unsupported, "no IPv4 raw socket")
        })?;
        // SAFETY: sockaddr_in is a plain-old-data C struct; an all-zero bit
        // pattern is a valid (unspecified) value that we fully populate below.
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = dst.port().to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(dst.ip().octets());
        // SAFETY: fd is valid; packet slice and sockaddr outlive the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::addr_of!(sa).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Send a pre-built IPv6 datagram (its own IPv6 header carries the spoofed
    /// source) to `dst`. Needs no permit for the reason [`Self::send_to_v4`]
    /// gives.
    #[cfg(target_os = "linux")]
    fn send_to_v6(&self, packet: &[u8], dst: std::net::SocketAddrV6) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.fd_v6.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Unsupported, "no IPv6 raw socket")
        })?;
        // SAFETY: sockaddr_in6 is a plain-old-data C struct; an all-zero bit
        // pattern is a valid value that we fully populate below.
        let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        // Raw IPv6 sockets require sin6_port == 0 (the real dest port lives in
        // our own UDP header); a nonzero value here yields EINVAL.
        sa.sin6_port = 0;
        sa.sin6_addr.s6_addr = dst.ip().octets();
        // SAFETY: fd is valid; packet slice and sockaddr outlive the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::addr_of!(sa).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_to_v4(&self, _packet: &[u8], _dst: SocketAddrV4) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn send_to_v6(&self, _packet: &[u8], _dst: std::net::SocketAddrV6) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
    }
}

/// An ephemeral UDP send socket for scanner-kill responses.
///
/// A newtype around `UdpSocket` whose purpose is to make the permit mandatory
/// where the socket is CREATED: [`Self::bind`] demands a [`TransmitPermit`],
/// so a run reading a capture file cannot make one. The parent binds these and
/// hands them to the kill worker process, which never calls `socket()` itself
/// -- so the unprivileged fallback is an inherited capability exactly as the
/// raw socket is, rather than something the worker could conjure. See
/// [`crate::security::transmit_guard`].
struct KillUdpSocket(UdpSocket);

impl KillUdpSocket {
    /// Bind an ephemeral send socket, or `None` when that family is
    /// unavailable (e.g. a host with no IPv6 stack).
    fn bind(_permit: &TransmitPermit, addr: (IpAddr, u16)) -> Option<Self> {
        UdpSocket::bind(addr).ok().map(Self)
    }

    /// Send `buf` to `dst`. No permit: holding the socket is the capability,
    /// and only a holder of a permit could have bound it.
    fn send_to(&self, buf: &[u8], dst: (IpAddr, u16)) -> std::io::Result<usize> {
        self.0.send_to(buf, dst)
    }
}

/// Scanner-kill responses put on the wire, per path.
///
/// A type rather than two bare statics so a test can book into its own and
/// assert exact counts; the process-global instance, [`KILL_SENT`], is the one
/// the metrics exporter reads.
#[derive(Debug, Default)]
struct SendCounters {
    /// Responses sent through the source-spoofed raw socket.
    raw: AtomicU64,
    /// Responses sent from sipnab's own ephemeral UDP port.
    ephemeral: AtomicU64,
}

impl SendCounters {
    /// Zeroed counters, usable in a `static`.
    const fn new() -> Self {
        Self {
            raw: AtomicU64::new(0),
            ephemeral: AtomicU64::new(0),
        }
    }

    /// Count one response sent through `path`.
    fn bump(&self, path: SendPath) {
        let counter = match path {
            SendPath::Raw => &self.raw,
            SendPath::Ephemeral => &self.ephemeral,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// `(raw, ephemeral)`.
    fn read(&self) -> (u64, u64) {
        (
            self.raw.load(Ordering::Relaxed),
            self.ephemeral.load(Ordering::Relaxed),
        )
    }
}

/// The process-global send counters behind `sipnab_kill_responses_sent_total`.
///
/// They live in the PARENT. The worker process that does the sending reports
/// which path each response took ([`KillResponse::Sent`]), and the parent books
/// it here; counters bumped inside the worker would be counting in a process
/// the metrics exporter cannot see.
static KILL_SENT: SendCounters = SendCounters::new();

/// Scanner-kill responses sent, as `(raw, ephemeral)`, for the metrics
/// exporter. Process-global and monotonic.
pub fn kill_responses_sent() -> (u64, u64) {
    KILL_SENT.read()
}

/// Which socket a kill response left through.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SendPath {
    /// The raw socket, with the victim's address and port forged as source.
    Raw,
    /// sipnab's own ephemeral UDP port, unspoofed.
    Ephemeral,
}

/// Message types sent from the main thread to the scanner-kill worker.
#[derive(Debug, Serialize, Deserialize)]
pub enum KillRequest {
    /// Request to send a SIP response to a scanner.
    SendResponse {
        /// Destination IP address (the scanner).
        dst_addr: IpAddr,
        /// Destination transport port (the scanner's source port).
        dst_port: u16,
        /// Spoof source: the victim IP the scanner targeted. Used as the
        /// forged source when raw-socket spoofing is active; ignored by the
        /// ephemeral fallback.
        src_addr: IpAddr,
        /// Spoof source port: the victim port the scanner targeted.
        src_port: u16,
        /// Pre-built SIP response bytes to inject.
        response_bytes: Vec<u8>,
    },
    /// Gracefully shut down the worker thread.
    Shutdown,
}

/// Response from the scanner-kill worker back to the main thread.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KillResponse {
    /// Response was successfully transmitted to the scanner over UDP.
    Sent {
        /// Which socket it left through. Carried back because the per-path
        /// counters live in the parent, and without it they stop moving.
        path: SendPath,
    },
    /// Request was dropped due to rate limiting.
    RateLimited,
    /// Request was rejected for a policy reason.
    Rejected {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// An error occurred processing the request.
    Error {
        /// Error description.
        message: String,
    },
}

/// What the scanner-kill defense actually did, as a snapshot.
///
/// This is the *ledger*: every request the worker took a decision on is
/// counted here, and it is complete whether or not anybody is reading the
/// per-event stream behind [`ScannerKillHandle::try_recv_response`]. Getting
/// that the wrong way round is the whole of the defect this type exists to
/// close — outcomes used to live only in a bounded channel nothing drained,
/// so they were both invisible and, once 256 of them had piled up, fatal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KillCounts {
    /// Responses the worker put on the wire.
    pub sent: u64,
    /// Requests suppressed by the global or per-destination rate limiter.
    pub rate_limited: u64,
    /// Requests refused on policy grounds: a broadcast/multicast destination
    /// or an empty response body.
    pub rejected: u64,
    /// Requests that reached a socket and failed there.
    pub errored: u64,
    /// Kill requests the capture thread could not hand over because the
    /// worker's queue was full, and which were therefore dropped.
    ///
    /// Dropping is deliberate: the capture thread holds the dialog and stream
    /// write locks while it offers a request, so waiting there stops the
    /// capture and every reader of those locks. A nonzero value means the
    /// responder fell behind a flood, not that anything is broken — under a
    /// flood almost every queued request would have been rate-limited anyway.
    pub dropped_requests: u64,
    /// Outcomes that did not fit on the observation channel because nothing
    /// was draining it.
    ///
    /// They are still counted in the four class totals above; only the
    /// per-event stream lost them.
    pub unobserved_outcomes: u64,
    /// Requests [`ScannerKillHandle::send_kill`] accepted and handed towards
    /// the worker process.
    pub accepted: u64,
    /// Accepted requests that will never have an outcome because the worker
    /// process is gone -- it died, or was killed at shutdown with requests
    /// still in flight. Zero while the worker is alive: until then a request
    /// without an outcome is in flight, not lost.
    pub lost_to_worker_exit: u64,
}

impl KillCounts {
    /// Total requests the worker took a decision on — sent, rate-limited,
    /// rejected and errored together.
    ///
    /// Every request accepted by [`ScannerKillHandle::send_kill`] ends up in
    /// exactly one of those four classes, so this is what an accepted request
    /// count must eventually equal.
    pub fn outcomes(&self) -> u64 {
        self.sent + self.rate_limited + self.rejected + self.errored
    }

    /// Whether anything was dropped — a request the capture thread could not
    /// hand over, an outcome that did not fit on the stream, or requests lost
    /// with the worker process.
    pub fn any_dropped(&self) -> bool {
        self.dropped_requests > 0 || self.unobserved_outcomes > 0 || self.lost_to_worker_exit > 0
    }
}

/// The live counters behind [`KillCounts`], shared by the handle and the
/// worker thread.
///
/// Every mutator is a relaxed atomic add: recording an outcome must never be
/// able to block, because the thread doing the recording is the one answering
/// scanners, and the thread reading the result is the one capturing packets.
#[derive(Debug, Default)]
struct KillTally {
    /// See [`KillCounts::sent`].
    sent: AtomicU64,
    /// See [`KillCounts::rate_limited`].
    rate_limited: AtomicU64,
    /// See [`KillCounts::rejected`].
    rejected: AtomicU64,
    /// See [`KillCounts::errored`].
    errored: AtomicU64,
    /// See [`KillCounts::dropped_requests`].
    dropped_requests: AtomicU64,
    /// See [`KillCounts::unobserved_outcomes`].
    unobserved_outcomes: AtomicU64,
    /// Set the first time a request is dropped, so the operator is told once
    /// rather than once per dropped packet.
    drop_reported: AtomicBool,
    /// Set the first time an outcome does not fit on the observation channel.
    unobserved_reported: AtomicBool,
    /// See [`KillCounts::accepted`].
    accepted: AtomicU64,
    /// Set once the worker process can produce no further outcome.
    worker_gone: AtomicBool,
}

impl KillTally {
    /// Record one worker decision. Called before the outcome is offered to
    /// anyone, so an outcome is on the books even if nothing ever reads it.
    fn record(&self, outcome: &KillResponse) {
        let counter = match outcome {
            KillResponse::Sent { .. } => &self.sent,
            KillResponse::RateLimited => &self.rate_limited,
            KillResponse::Rejected { .. } => &self.rejected,
            KillResponse::Error { .. } => &self.errored,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a kill request that was dropped because the worker's queue was
    /// full, and say so once.
    fn note_dropped_request(&self) {
        self.dropped_requests.fetch_add(1, Ordering::Relaxed);
        if !self.drop_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "scanner-kill: the worker's request queue is full \
                 ({KILL_REQUEST_CAPACITY} pending) and kill responses are now \
                 being DROPPED. They are dropped rather than queued because \
                 the capture thread offers them while holding the dialog and \
                 stream locks, and waiting there would stop the capture and \
                 every reader of those locks. Detection, alerting and \
                 reporting are unaffected; the running total is logged when \
                 the worker shuts down."
            );
        }
    }

    /// Count an outcome that did not fit on the observation channel, and say
    /// so once.
    fn note_unobserved_outcome(&self) {
        self.unobserved_outcomes.fetch_add(1, Ordering::Relaxed);
        if !self.unobserved_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "scanner-kill: nothing is draining the kill-outcome channel, \
                 so individual outcomes are no longer observable through it. \
                 They are still counted — see ScannerKillHandle::counts() and \
                 the totals logged at shutdown."
            );
        }
    }

    /// Count a request accepted for the worker. Called BEFORE the request is
    /// queued, so an outcome can never be booked for a request not yet counted
    /// as accepted; [`Self::unaccept`] takes it back if the queue refused it.
    fn note_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Undo [`Self::note_accepted`] for a request the queue refused.
    fn unaccept(&self) {
        self.accepted.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record that the worker process can produce no further outcome.
    ///
    /// `Release`, paired with the `Acquire` in [`Self::snapshot`]: whoever
    /// sees the worker gone also sees every outcome booked before it went.
    fn note_worker_gone(&self) {
        self.worker_gone.store(true, Ordering::Release);
    }

    /// Take a consistent-enough snapshot for reporting. The counters are read
    /// one at a time, so a snapshot taken mid-flood may be a few events stale;
    /// it is never wrong about what has already been counted.
    ///
    /// Once the worker is gone, every accepted request without an outcome is
    /// lost: none of them can be answered now. Until then the same shortfall is
    /// in flight, and is reported as nothing.
    fn snapshot(&self) -> KillCounts {
        // Read first, so every outcome booked before the worker went is
        // visible below; `accepted` is read last, so a request accepted in the
        // race with the death lands in the lost count rather than nowhere.
        let gone = self.worker_gone.load(Ordering::Acquire);
        let mut counts = KillCounts {
            sent: self.sent.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            errored: self.errored.load(Ordering::Relaxed),
            dropped_requests: self.dropped_requests.load(Ordering::Relaxed),
            unobserved_outcomes: self.unobserved_outcomes.load(Ordering::Relaxed),
            accepted: 0,
            lost_to_worker_exit: 0,
        };
        counts.accepted = self.accepted.load(Ordering::Relaxed);
        if gone {
            counts.lost_to_worker_exit = counts.accepted.saturating_sub(counts.outcomes());
        }
        counts
    }
}

/// Book one outcome the worker process reported: its class in `tally`, and,
/// for a send, the path it took in `counters`.
fn book_outcome(tally: &KillTally, counters: &SendCounters, outcome: &KillResponse) {
    tally.record(outcome);
    if let KillResponse::Sent { path } = outcome {
        counters.bump(*path);
    }
}

/// A send descriptor the parent gave the worker process, identified by the
/// socket's inode so its absence from this process can be checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandedOver {
    /// The descriptor's name on the worker's command line (`udp4`, `raw4`, ...).
    pub kind: &'static str,
    /// The socket's inode: `/proc/<pid>/fd/*` links to `socket:[<inode>]`.
    pub inode: u64,
}

/// State the handle shares with its forwarder and reader threads.
#[derive(Debug, Default)]
struct HandleShared {
    /// The authoritative record of what the worker did.
    tally: KillTally,
    /// Set the first time the defense is found dead, so it is reported once.
    defense_disabled: AtomicBool,
    /// Set by [`ScannerKillHandle::shutdown`] before it closes the request
    /// pipe, so the reader can tell an orderly exit from a death.
    shutting_down: AtomicBool,
}

impl HandleShared {
    /// Report, exactly once, that the kill defense is no longer armed.
    fn report_defense_disabled(&self) {
        if !self.defense_disabled.swap(true, Ordering::Relaxed) {
            let lost = self.tally.snapshot().lost_to_worker_exit;
            tracing::error!(
                "the scanner-kill worker process is gone (it exited, was \
                 killed, or stopped answering); the --kill-scanner defense is \
                 DISABLED for the rest of this run -- scanners will be \
                 detected but no longer answered, and nothing restarts the \
                 worker. {lost} request(s) in flight were lost with it."
            );
        }
    }
}

/// How long [`ScannerKillHandle::shutdown`] waits for the worker process to
/// exit on its own before killing it.
///
/// The worker exits as soon as its request pipe closes and it has answered
/// what was queued, which takes milliseconds. The bound exists for a worker
/// that is wedged or stopped, and it is what keeps shutdown from waiting on
/// one forever.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle for the main thread to communicate with the scanner-kill worker
/// process.
///
/// Sending a `KillRequest` offers it to a forwarding thread that writes it to
/// the worker's request pipe; a reader thread turns the worker's responses
/// into the tally and the outcome stream. Call `shutdown` to stop the worker.
///
/// # Why nothing here blocks
///
/// The thread that calls [`Self::send_kill`] is the capture thread, and it
/// calls it while holding the dialog and stream write locks. Anything that
/// blocks it therefore stops packet processing *and* every consumer of those
/// stores — the REST API, the TUI and the whole MCP surface, not just the
/// kill path. So the request queue is offered to, never waited on: the pipe
/// write that CAN block belongs to the forwarding thread, and a stopped or
/// wedged worker backs up into a full queue and counted drops, never into the
/// capture thread. See [`KillCounts`].
pub struct ScannerKillHandle {
    /// Channel to queue kill requests for the forwarding thread. `None` after
    /// [`Self::shutdown`], which drops the sender so the forwarder drains,
    /// closes the worker's request pipe, and exits.
    tx: Option<Sender<KillRequest>>,
    /// Best-effort channel of per-request outcomes, fed by the reader thread.
    resp_rx: Receiver<KillResponse>,
    /// Writes queued requests to the worker's request pipe; taken on shutdown.
    forwarder: Option<std::thread::JoinHandle<()>>,
    /// Reads the worker's responses into the tally; taken on shutdown.
    reader: Option<std::thread::JoinHandle<()>>,
    /// The worker process. `None` once reaped, and in the in-process tests
    /// that drive the pipes without one.
    child: Arc<parking_lot::Mutex<Option<std::process::Child>>>,
    /// Counters and flags shared with the two threads.
    shared: Arc<HandleShared>,
    /// The send descriptors the worker was given and this process closed.
    handed_over: Vec<HandedOver>,
}

impl ScannerKillHandle {
    /// Wire a handle to a worker's two pipes.
    ///
    /// # Arguments
    ///
    /// * `requests` — the write end of the worker's request pipe.
    /// * `responses` — the read end of the worker's response pipe.
    /// * `child` — the worker process, reaped by [`Self::shutdown`]. `None`
    ///   only in tests that serve the pipes from a thread.
    /// * `handed_over` — what the worker was given, for [`Self::handed_over`].
    ///
    /// # Errors
    ///
    /// A thread could not be started. The child, if any, is killed and reaped
    /// before the error is returned, so a failed attach leaves nothing behind.
    fn attach<W, R>(
        requests: W,
        responses: R,
        child: Option<std::process::Child>,
        handed_over: Vec<HandedOver>,
    ) -> std::io::Result<Self>
    where
        W: std::io::Write + Send + 'static,
        R: std::io::Read + Send + 'static,
    {
        let (tx, rx) = crossbeam_channel::bounded::<KillRequest>(KILL_REQUEST_CAPACITY);
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(KILL_OUTCOME_CAPACITY);
        let shared = Arc::new(HandleShared::default());
        let child = Arc::new(parking_lot::Mutex::new(child));

        let started = std::thread::Builder::new()
            .name("scanner-kill-fwd".to_string())
            .spawn({
                let shared = Arc::clone(&shared);
                move || forward_requests(&rx, requests, &shared)
            })
            .and_then(|forwarder| {
                std::thread::Builder::new()
                    .name("scanner-kill-rx".to_string())
                    .spawn({
                        let shared = Arc::clone(&shared);
                        let child = Arc::clone(&child);
                        move || read_outcomes(responses, &resp_tx, &shared, &child)
                    })
                    .map(|reader| (forwarder, reader))
            });
        let (forwarder, reader) = match started {
            Ok(threads) => threads,
            Err(e) => {
                // The forwarder, if it started, exits when `tx` drops below.
                if let Some(mut c) = child.lock().take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return Err(e);
            }
        };

        Ok(Self {
            tx: Some(tx),
            resp_rx,
            forwarder: Some(forwarder),
            reader: Some(reader),
            child,
            shared,
            handed_over,
        })
    }

    /// Offer a kill request to the worker. Never blocks.
    ///
    /// Returns `Ok(())` if the request was queued. The outcome is recorded in
    /// [`Self::counts`] and, best-effort, published on the channel behind
    /// [`Self::try_recv_response`].
    ///
    /// # Errors
    ///
    /// * `TrySendError::Full` — the worker is behind and the request was
    ///   dropped. Counted in [`KillCounts::dropped_requests`] and warned about
    ///   once. The alternative, waiting, wedges the capture thread and
    ///   everything reading the stores it has locked.
    /// * `TrySendError::Disconnected` — the worker process is gone (it
    ///   exited, was killed, or stopped answering) or has already been shut
    ///   down. An error is logged once and [`Self::defense_disabled`] reports
    ///   `true` from then on: the kill defense is gone for the rest of the run.
    pub fn send_kill(&self, request: KillRequest) -> Result<(), TrySendError<KillRequest>> {
        let Some(tx) = self.tx.as_ref() else {
            self.shared.report_defense_disabled();
            return Err(TrySendError::Disconnected(request));
        };
        if self.shared.tally.worker_gone.load(Ordering::Acquire) {
            self.shared.report_defense_disabled();
            return Err(TrySendError::Disconnected(request));
        }
        // Only a send is an obligation the ledger has to close; a `Shutdown`
        // never produces an outcome.
        let counted = matches!(request, KillRequest::SendResponse { .. });
        if counted {
            self.shared.tally.note_accepted();
        }
        match tx.try_send(request) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(request)) => {
                if counted {
                    self.shared.tally.unaccept();
                }
                self.shared.tally.note_dropped_request();
                Err(TrySendError::Full(request))
            }
            Err(TrySendError::Disconnected(request)) => {
                if counted {
                    self.shared.tally.unaccept();
                }
                self.shared.report_defense_disabled();
                Err(TrySendError::Disconnected(request))
            }
        }
    }

    /// Whether the worker process is still running.
    pub fn is_alive(&self) -> bool {
        let mut child = self.child.lock();
        match child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            // No process to ask: in-process tests, or already reaped. The
            // reader's end of stream is then the only evidence there is.
            None => self.reader.is_some() && !self.shared.tally.worker_gone.load(Ordering::Acquire),
        }
    }

    /// Whether the kill defense has been marked dead (the worker process went
    /// away, or a send was refused because it had). Once true, stays true.
    pub fn defense_disabled(&self) -> bool {
        self.shared.defense_disabled.load(Ordering::Relaxed)
    }

    /// What this worker has done so far: sends, suppressions, refusals,
    /// failures, and anything dropped or lost.
    ///
    /// This is the reachable form of the kill outcome. It does not depend on
    /// anybody polling [`Self::try_recv_response`], which is exactly why it
    /// exists.
    pub fn counts(&self) -> KillCounts {
        self.shared.tally.snapshot()
    }

    /// The send descriptors the worker process was given, which this process
    /// closed after the spawn.
    ///
    /// Reported so the claim can be checked rather than trusted: none of these
    /// inodes appears among this process's open descriptors.
    pub fn handed_over(&self) -> &[HandedOver] {
        &self.handed_over
    }

    /// The worker's process id, while it has not been reaped.
    pub fn worker_pid(&self) -> Option<u32> {
        self.child.lock().as_ref().map(std::process::Child::id)
    }

    /// Try to receive one outcome from the worker (non-blocking).
    ///
    /// Best-effort: this is a stream of individual outcomes for a caller that
    /// wants them as they happen, and outcomes that did not fit while nobody
    /// was draining it are missing from it (counted in
    /// [`KillCounts::unobserved_outcomes`]). [`Self::counts`] is the complete
    /// record; use this only when the individual events matter.
    pub fn try_recv_response(&self) -> Option<KillResponse> {
        self.resp_rx.try_recv().ok()
    }

    /// Stop the worker process, reap it, and log what the defense did.
    ///
    /// Closes the request pipe (after a best-effort `Shutdown`), gives the
    /// worker five seconds (`SHUTDOWN_GRACE`) to answer what is queued and
    /// exit, and kills it if it has not. Always reaps. Idempotent.
    pub fn shutdown(&mut self) {
        self.shared.shutting_down.store(true, Ordering::Release);
        // Ask the worker to stop, then DROP the sender. The ask is
        // best-effort — the queue may be full, and waiting for a slot is the
        // blocking this type exists to avoid — so the sender being dropped is
        // what actually guarantees an exit: the forwarder drains what is
        // queued, closes the pipe, and the worker reads end of stream.
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(KillRequest::Shutdown);
        }
        let child = self.child.lock().take();
        if let Some(mut child) = child {
            reap_within(&mut child, SHUTDOWN_GRACE);
        }
        if let Some(forwarder) = self.forwarder.take()
            && forwarder.join().is_err()
        {
            tracing::error!("the scanner-kill forwarding thread panicked");
        }
        if let Some(reader) = self.reader.take() {
            if reader.join().is_err() {
                tracing::error!("the scanner-kill reader thread panicked");
            }
            self.log_totals();
        }
    }

    /// Log what the kill defense did over the run. Warns when anything was
    /// dropped or lost, so a flood that outran the responder, or a worker that
    /// died, is visible without anyone having asked for counters.
    fn log_totals(&self) {
        let counts = self.counts();
        if counts.any_dropped() {
            tracing::warn!(
                "Scanner-kill totals: {} sent, {} rate-limited, {} rejected, \
                 {} failed; {} request(s) dropped because the worker was \
                 behind, {} lost with the worker process, {} outcome(s) \
                 unobserved because nothing was reading the outcome channel",
                counts.sent,
                counts.rate_limited,
                counts.rejected,
                counts.errored,
                counts.dropped_requests,
                counts.lost_to_worker_exit,
                counts.unobserved_outcomes,
            );
        } else {
            tracing::info!(
                "Scanner-kill totals: {} sent, {} rate-limited, {} rejected, {} failed",
                counts.sent,
                counts.rate_limited,
                counts.rejected,
                counts.errored,
            );
        }
    }
}

impl Drop for ScannerKillHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Write queued requests to the worker until the queue is closed or the pipe
/// breaks, then close the pipe.
///
/// The one place a write to the worker can block, which is why it is a thread
/// of its own: a stopped worker fills the pipe, this thread waits, the queue
/// in front of it fills, and the capture thread's offers are refused and
/// counted instead of waited on.
fn forward_requests<W: std::io::Write>(
    queue: &Receiver<KillRequest>,
    mut to_worker: W,
    shared: &HandleShared,
) {
    for request in queue.iter() {
        match wire::write_frame(&mut to_worker, &request) {
            Ok(()) => {}
            // A request that cannot be framed is refused by the writer before
            // a byte is written, so the pipe is intact. Book it as the error it
            // is, or the ledger would carry it as in flight for ever.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                if matches!(request, KillRequest::SendResponse { .. }) {
                    shared.tally.record(&KillResponse::Error {
                        message: format!("request could not be framed for the worker: {e}"),
                    });
                }
            }
            // The worker is gone. The reader sees the same death on the other
            // pipe and reports it; queued requests are counted as lost there.
            Err(e) => {
                tracing::debug!("scanner-kill request pipe closed: {e}");
                break;
            }
        }
    }
    // Dropping `to_worker` closes the pipe: end of stream is how the worker
    // learns to stop.
}

/// Read the worker's responses until it closes its end, booking each one,
/// then record that the worker can produce nothing more.
fn read_outcomes<R: std::io::Read>(
    mut from_worker: R,
    stream: &Sender<KillResponse>,
    shared: &HandleShared,
    child: &parking_lot::Mutex<Option<std::process::Child>>,
) {
    loop {
        match wire::read_frame::<_, KillResponse>(&mut from_worker) {
            Ok(Some(outcome)) => {
                book_outcome(&shared.tally, &KILL_SENT, &outcome);
                // Offer, never wait: nothing in production drains the
                // stream, and the tally above is the record.
                if let Err(TrySendError::Full(_)) = stream.try_send(outcome) {
                    shared.tally.note_unobserved_outcome();
                }
            }
            Ok(None) => break,
            Err(e) => {
                // A worker that speaks garbage is broken, and one that is
                // still running would go on sending without being heard. End
                // it; shutdown reaps it.
                tracing::error!("the scanner-kill worker sent an unreadable response ({e})");
                if let Some(c) = child.lock().as_mut() {
                    let _ = c.kill();
                }
                break;
            }
        }
    }
    // Nothing more can be booked, so what is still unanswered is lost.
    shared.tally.note_worker_gone();
    // An orderly shutdown closes this pipe too; only an end nobody asked for
    // is a death, and it is said once, loudly, because the defense is now off
    // and nothing restarts it.
    if !shared.shutting_down.load(Ordering::Acquire) {
        shared.report_defense_disabled();
    }
}

/// Wait up to `grace` for `child` to exit, then kill it. Always reaps.
fn reap_within(child: &mut std::process::Child, grace: std::time::Duration) {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            _ => break,
        }
    }
    tracing::warn!(
        "the scanner-kill worker process did not exit within {}s of shutdown; killing it",
        grace.as_secs()
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// Fixed-window rate limiter for scanner-kill responses.
///
/// Limits the number of responses sent per second to prevent the kill
/// mechanism from becoming an amplification vector. Counts within a
/// one-second window and resets the count when the window rolls over (a
/// fixed-window counter, not a continuously-refilling token bucket).
struct RateLimiter {
    /// Maximum responses permitted per one-second window.
    max_per_second: u32,
    /// Responses sent so far in the current window.
    count_this_window: u32,
    /// When the current window began; the window rolls over one second later.
    window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given maximum requests per second.
    fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            count_this_window: 0,
            window_start: Instant::now(),
        }
    }

    /// Check whether a request is allowed. Returns `true` if under the limit.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.count_this_window = 0;
            self.window_start = now;
        }
        if self.count_this_window < self.max_per_second {
            self.count_this_window += 1;
            true
        } else {
            false
        }
    }
}

/// Per-destination IP rate limiter to prevent amplification attacks.
///
/// Limits the number of responses to any single destination IP to
/// `MAX_PER_DST_PER_MINUTE` within a fixed (tumbling) one-minute window: the
/// per-IP counter and window start are reset the first time `allow` is called
/// 60s or more after the window began, not continuously as a sliding window
/// would.
struct PerDstRateLimiter {
    /// Map of destination IP to (window start, count).
    buckets: HashMap<IpAddr, (Instant, u32)>,
    /// When the O(n) sweep last ran, so it is amortized to at most once per
    /// second instead of on every send (the same pattern as the HEP replay
    /// cache's `HmacNonceCache::should_prune`). `None` until the first sweep.
    last_cleanup: Option<Instant>,
}

/// Responses this process may aim at any single destination IP per minute.
///
/// Fixed on purpose, and deliberately the one bound on the kill path that no
/// operator knob reaches. The kill path answers packets whose source address
/// the sender chose, so an attacker picks the destination; three is enough for
/// a genuine scanner to see that sipnab refused it, and few enough that the
/// answer is never worth eliciting.
///
/// Raising it multiplies exactly the amplification factor an attacker gets for
/// free. `--kill-rate-limit` cannot bound that, because it caps responses per
/// second across ALL destinations and says nothing about how they concentrate:
/// one forged source address collects every response the global cap allows.
/// Lowering it to zero stops the kill path answering anything while the flag
/// still reports itself as armed, which hides a dead mitigation behind a
/// configuration that looks live.
///
/// An operator who wants a wider blast radius raises `--kill-rate-limit`,
/// which buys more DISTINCT destinations per second. Nothing buys more packets
/// per destination, and a knob that did would hand the attacker the multiplier
/// directly.
const MAX_PER_DST_PER_MINUTE: u32 = 3;

impl PerDstRateLimiter {
    /// Create an empty per-destination limiter (no buckets yet).
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            last_cleanup: None,
        }
    }

    /// Check whether a response to `dst` is allowed. Returns `true` if under limit.
    fn allow(&mut self, dst: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.buckets.entry(dst).or_insert((now, 0));

        // Reset window if more than 60 seconds have passed
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 0);
        }

        if entry.1 < MAX_PER_DST_PER_MINUTE {
            entry.1 += 1;
            true
        } else {
            false
        }
    }

    /// Remove entries older than 2 minutes to prevent memory growth. O(n) in
    /// the number of tracked destinations; call via [`Self::cleanup_if_due`]
    /// so it is not paid on every send.
    fn cleanup(&mut self, now: Instant) {
        self.buckets
            .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 120);
    }

    /// Run [`Self::cleanup`] at most once per second. Amortizing is
    /// behavior-preserving: eviction only bounds memory — an entry that
    /// outlives its 60s window is still reset by the window check in
    /// [`Self::allow`], so a not-yet-swept stale bucket never over-limits or
    /// under-limits a destination. The first call always sweeps.
    fn cleanup_if_due(&mut self, now: Instant) {
        match self.last_cleanup {
            Some(prev) if now.duration_since(prev).as_secs() < 1 => {}
            _ => {
                self.last_cleanup = Some(now);
                self.cleanup(now);
            }
        }
    }
}

/// The scanner-kill decision loop, run inside the worker process.
///
/// Receives `KillRequest`s via channel, validates them, applies rate
/// limiting (both global and per-destination-IP), and transmits the SIP
/// response to the scanner.
///
/// It runs in [`worker_process`], a process of its own whose two pump threads
/// feed this channel from the request pipe and drain the outcome channel into
/// the response pipe. The sockets below are the descriptors that process
/// inherited: it never creates one, so it can send only through what a parent
/// holding a [`TransmitPermit`] gave it.
///
/// Without a raw socket the response leaves from an ephemeral source port on
/// `sock_v4`/`sock_v6`, not from the SIP listener port the scanner originally
/// targeted — sipnab is a passive sniffer and does not own that socket.
/// Scanners that key on the SIP transaction (Call-ID / branch / CSeq /
/// To-tag) accept it regardless.
struct ScannerKillWorker {
    /// Inbound channel of kill requests, fed from the request pipe.
    rx: Receiver<KillRequest>,
    /// Outbound channel of per-request outcomes, drained into the response
    /// pipe. Waited on, unlike everything in the parent: see [`Self::run`].
    resp_tx: Sender<KillResponse>,
    /// Global responses-per-second limiter.
    rate_limiter: RateLimiter,
    /// Per-destination-IP limiter (amplification mitigation).
    per_dst_limiter: PerDstRateLimiter,
    /// UDP socket for IPv4 destinations (bound to `0.0.0.0:0` by the
    /// parent); `None` if the parent could not bind one.
    sock_v4: Option<KillUdpSocket>,
    /// UDP socket for IPv6 destinations (bound to `[::]:0` by the parent);
    /// `None` if the parent could not bind one.
    sock_v6: Option<KillUdpSocket>,
    /// Raw sockets for source-spoofed responses, opened by the parent while
    /// privileged. `None` → the ephemeral UDP send is used.
    raw_sock: Option<RawKillSocket>,
}

impl ScannerKillWorker {
    /// Run the worker loop until a `Shutdown` request is received or the
    /// channel disconnects.
    fn run(mut self) {
        tracing::info!(
            "Scanner-kill worker started (rate limit: {}/sec)",
            self.rate_limiter.max_per_second
        );

        loop {
            let request = match self.rx.recv() {
                Ok(req) => req,
                Err(_) => {
                    tracing::debug!("Scanner-kill channel disconnected, worker exiting");
                    break;
                }
            };

            match request {
                KillRequest::Shutdown => {
                    tracing::info!("Scanner-kill worker shutting down");
                    break;
                }
                KillRequest::SendResponse {
                    dst_addr,
                    dst_port,
                    src_addr,
                    src_port,
                    response_bytes,
                } => {
                    let response =
                        self.process_send(dst_addr, dst_port, src_addr, src_port, &response_bytes);
                    // Waited on, deliberately, and safely. The parent books
                    // an outcome only when it arrives, so an outcome dropped
                    // here would be a request the parent's ledger carries as
                    // in flight for ever. Waiting cannot reach the capture
                    // thread: the pump draining this channel feeds a pipe the
                    // parent's reader thread always drains, and the parent's
                    // capture thread only ever OFFERS requests (see
                    // `ScannerKillHandle::send_kill`). When this thread was
                    // the parent's own, the same wait was the wedge that froze
                    // capture after ~512 detections; across a process
                    // boundary and a forwarding thread it is backpressure.
                    if self.resp_tx.send(response).is_err() {
                        tracing::debug!("Scanner-kill outcome channel closed, worker exiting");
                        break;
                    }
                }
            }
        }
    }

    /// Validate and process a single send request.
    fn process_send(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: IpAddr,
        src_port: u16,
        response_bytes: &[u8],
    ) -> KillResponse {
        // Reject broadcast addresses
        if is_broadcast_or_multicast(dst_addr) {
            let reason = format!("rejected broadcast/multicast destination: {dst_addr}");
            tracing::warn!("Scanner-kill: {reason}");
            return KillResponse::Rejected { reason };
        }

        // Reject empty responses
        if response_bytes.is_empty() {
            return KillResponse::Rejected {
                reason: "empty response bytes".to_string(),
            };
        }

        // Apply global rate limit
        if !self.rate_limiter.allow() {
            tracing::debug!("Scanner-kill: rate limited response to {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Apply per-destination-IP rate limit (M6: amplification mitigation)
        if !self.per_dst_limiter.allow(dst_addr) {
            tracing::debug!("Scanner-kill: per-destination rate limited for {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Periodic cleanup of per-dst limiter (amortized to once per second so
        // the O(n) sweep is not paid on every send).
        self.per_dst_limiter.cleanup_if_due(Instant::now());

        // Prefer a source-spoofed raw send when a raw socket is available. The
        // forged source is the victim ip:port the scanner targeted, so the
        // reply appears to come from the SIP listener rather than sipnab's
        // ephemeral port. Build the datagram for the matching address family
        // (mixed families never occur — src and dst come from one packet) and
        // fall back to the plain UDP send on any failure.
        if let Some(raw) = self.raw_sock.as_ref() {
            let spoofed: Option<std::io::Result<usize>> = match (dst_addr, src_addr) {
                (IpAddr::V4(dst_v4), IpAddr::V4(src_v4)) => {
                    let dst = SocketAddrV4::new(dst_v4, dst_port);
                    let src = SocketAddrV4::new(src_v4, src_port);
                    crate::security::kill_packet::build_ipv4_udp(src, dst, response_bytes)
                        .map(|pkt| raw.send_to_v4(&pkt, dst))
                }
                (IpAddr::V6(dst_v6), IpAddr::V6(src_v6)) => {
                    let dst = std::net::SocketAddrV6::new(dst_v6, dst_port, 0, 0);
                    let src = std::net::SocketAddrV6::new(src_v6, src_port, 0, 0);
                    crate::security::kill_packet::build_ipv6_udp(src, dst, response_bytes)
                        .map(|pkt| raw.send_to_v6(&pkt, dst))
                }
                _ => None,
            };
            match spoofed {
                Some(Ok(_)) => {
                    tracing::info!(
                        "Scanner-kill: sent {} byte spoofed response to {dst_addr}:{dst_port} (source {src_addr}:{src_port})",
                        response_bytes.len(),
                    );
                    return KillResponse::Sent {
                        path: SendPath::Raw,
                    };
                }
                Some(Err(e)) => {
                    // Raw send failed at runtime; fall through to the ephemeral
                    // path rather than dropping the response.
                    tracing::warn!(
                        "Scanner-kill: spoofed send to {dst_addr}:{dst_port} failed ({e}); falling back to ephemeral source"
                    );
                }
                None => {}
            }
        }

        // Ephemeral fallback: plain UDP send from our own source port.
        let sock = match dst_addr {
            IpAddr::V4(_) => self.sock_v4.as_ref(),
            IpAddr::V6(_) => self.sock_v6.as_ref(),
        };
        let Some(sock) = sock else {
            let message = format!("no UDP socket available for {dst_addr}");
            tracing::error!("Scanner-kill: {message}");
            return KillResponse::Error { message };
        };
        match sock.send_to(response_bytes, (dst_addr, dst_port)) {
            Ok(n) => {
                tracing::info!("Scanner-kill: sent {n} byte response to {dst_addr}:{dst_port}");
                KillResponse::Sent {
                    path: SendPath::Ephemeral,
                }
            }
            Err(e) => {
                let message = format!("send to {dst_addr}:{dst_port} failed: {e}");
                tracing::warn!("Scanner-kill: {message}");
                KillResponse::Error { message }
            }
        }
    }
}

/// Check whether an IP address is broadcast or multicast.
fn is_broadcast_or_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Default rate limit for scanner-kill responses (per second).
const DEFAULT_RATE_LIMIT: u32 = 10;

/// How many kill requests may be in flight to the worker before further ones
/// are dropped rather than made to wait.
///
/// The depth only has to cover a burst: the worker's per-request cost is a
/// rate-limit check plus, for the few that pass it, one `sendto`. Anything
/// deeper than a burst is a queue of responses to scanner packets that are
/// already stale by the time they would be sent.
const KILL_REQUEST_CAPACITY: usize = 256;

/// How many outcomes may be waiting on the observation channel before further
/// ones are counted-but-not-streamed.
const KILL_OUTCOME_CAPACITY: usize = 256;

/// How to start the scanner-kill worker process.
#[derive(Debug, Clone)]
pub struct KillWorkerSpawn {
    /// The sipnab executable to run as the worker. A run passes its own
    /// executable ([`Self::from_current_exe`]); tests pass the binary cargo
    /// built, because their own executable is a test harness.
    pub program: std::path::PathBuf,
    /// Maximum responses per second across all destinations; `None` for the
    /// built-in default of 10.
    pub rate_limit: Option<u32>,
    /// The account the worker becomes if it starts as root; `None` for
    /// `nobody`. The worker never keeps root, whatever the parent does.
    pub run_as: Option<String>,
    /// Default tracing filter for the worker's stderr. `SIPNAB_LOG`, which
    /// the worker inherits, still takes precedence, exactly as in the parent.
    pub log_level: String,
}

impl KillWorkerSpawn {
    /// Run the worker from the executable this process was started from.
    ///
    /// # Errors
    ///
    /// The executable's path cannot be read (`/proc/self/exe` on Linux).
    pub fn from_current_exe(
        rate_limit: Option<u32>,
        run_as: Option<String>,
        log_level: &str,
    ) -> std::io::Result<Self> {
        Ok(Self {
            program: std::env::current_exe()?,
            rate_limit,
            run_as,
            log_level: log_level.to_string(),
        })
    }
}

/// The worker's command line for `spawn`, given which descriptors it gets.
///
/// Separate from [`spawn_scanner_kill_worker`] so the flags-to-worker wiring
/// can be driven without starting a process.
pub(crate) fn worker_args(
    spawn: &KillWorkerSpawn,
    send_fds: worker_process::FdPlan,
) -> worker_process::WorkerArgs {
    worker_process::WorkerArgs {
        rate_limit: spawn.rate_limit.unwrap_or(DEFAULT_RATE_LIMIT),
        send_fds,
        run_as: spawn.run_as.clone().unwrap_or_else(|| "nobody".to_string()),
        log_level: spawn.log_level.clone(),
    }
}

/// The variables the worker process may inherit from this one's environment.
///
/// An allowlist, because the environment is where secrets arrive:
/// `--api-key`, `--api-signing-key`, `--mcp-signing-key`, `--hep-auth` and the
/// MCP token all read one. The worker needs none of them, and a process that
/// holds no secret cannot leak one. What crosses is what running the same
/// binary the same way needs, and nothing that could be a credential:
///
/// * `SIPNAB_LOG` — the worker's log filter, as in the parent;
/// * `NO_COLOR`, `RUST_BACKTRACE` — how it logs and how it reports a panic;
/// * `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH` — where the dynamic loader found
///   this binary's libraries (libpcap) when the parent started; without them a
///   non-standard install would start the parent and then fail the worker;
/// * `LLVM_PROFILE_FILE` and the sanitizer option variables — so an
///   instrumented build's worker writes its coverage and honors the same
///   sanitizer settings as the run that started it.
const WORKER_ENV: &[&str] = &[
    "SIPNAB_LOG",
    "NO_COLOR",
    "RUST_BACKTRACE",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LLVM_PROFILE_FILE",
    "ASAN_OPTIONS",
    "LSAN_OPTIONS",
    "MSAN_OPTIONS",
    "TSAN_OPTIONS",
    "UBSAN_OPTIONS",
];

/// The environment variables the worker process is started with: those of
/// `vars` that [`WORKER_ENV`] names, and no others.
fn worker_environment(
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.into_iter()
        .filter(|(name, _)| WORKER_ENV.iter().any(|allowed| name == allowed))
        .collect()
}

/// The inode of the socket behind `fd`.
///
/// Read from a transient duplicate, so the caller's descriptor is untouched.
fn socket_inode(fd: &std::os::fd::OwnedFd) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::File::from(fd.try_clone()?).metadata()?.ino())
}

/// Start the scanner-kill worker process and return a handle to it.
///
/// The worker is this program re-executed with [`worker_process::KILL_WORKER_ARG`]
/// as its first argument: a process of its own, so a bug reached from a
/// packet in this one cannot reach the sockets it sends through. It inherits
/// exactly the send descriptors created here — the raw sockets in `raw_sock`
/// and two ephemeral UDP sockets bound now — at fixed numbers, and never
/// creates one itself. **This process closes its copies before returning**,
/// so after the spawn the process parsing captured traffic holds no kill-path
/// send socket at all. [`ScannerKillHandle::handed_over`] names them so that
/// can be checked.
///
/// # Arguments
///
/// * `spawn` — which executable, the rate limit, and who the worker becomes.
/// * `raw_sock` — raw sockets for source-spoofed responses, opened during the
///   privileged window. `None` → only the ephemeral UDP send is available.
/// * `permit` — proof, obtained from the capture source, that this run watches
///   a live source. Every descriptor handed to the worker is created under it,
///   so a run reading a capture file has nothing to hand over: see
///   [`crate::security::transmit_guard`].
///
/// # Errors
///
/// The worker process or one of the two threads serving it could not be
/// started. No fallback runs the worker in this process instead: that would
/// silently restore the exposure this function exists to remove.
pub fn spawn_scanner_kill_worker(
    spawn: &KillWorkerSpawn,
    raw_sock: Option<RawKillSocket>,
    permit: TransmitPermit,
) -> Result<ScannerKillHandle, std::io::Error> {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use worker_process::{FdPlan, KILL_WORKER_ARG, Placement, SendFd};

    // Bind the ephemeral send sockets here, under the permit, rather than in
    // the worker: the worker never calls socket(), so the unprivileged
    // fallback is an inherited capability exactly as the raw socket is. Either
    // family may be unavailable (e.g. no IPv6 stack); a destination whose
    // family has no socket is reported as an error at send time.
    let udp_v4 = KillUdpSocket::bind(&permit, (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let udp_v6 = KillUdpSocket::bind(&permit, (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
    if udp_v4.is_none() && udp_v6.is_none() {
        tracing::error!(
            "Scanner-kill: could not bind any UDP send socket; responses without a \
             raw socket will error"
        );
    }

    let mut descriptors: Vec<(SendFd, OwnedFd)> = Vec::with_capacity(4);
    if let Some(raw) = raw_sock {
        let (v4, v6) = raw.into_fds();
        descriptors.extend(v4.map(|fd| (SendFd::RawV4, fd)));
        descriptors.extend(v6.map(|fd| (SendFd::RawV6, fd)));
    }
    descriptors.extend(udp_v4.map(|s| (SendFd::UdpV4, OwnedFd::from(s.0))));
    descriptors.extend(udp_v6.map(|s| (SendFd::UdpV6, OwnedFd::from(s.0))));

    let handed_over = descriptors
        .iter()
        .map(|(kind, fd)| {
            Ok(HandedOver {
                kind: kind.name(),
                inode: socket_inode(fd)?,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let placement = Placement::plan(
        &descriptors
            .iter()
            .map(|(kind, fd)| (*kind, fd.as_raw_fd()))
            .collect::<Vec<_>>(),
    );
    let args = worker_args(
        spawn,
        FdPlan::new(descriptors.iter().map(|(kind, _)| *kind)),
    );

    let mut command = std::process::Command::new(&spawn.program);
    command
        .arg(KILL_WORKER_ARG)
        .args(args.to_args())
        .env_clear()
        .envs(worker_environment(std::env::vars_os()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    // SAFETY: the closure runs in the forked child between fork and exec,
    // where only async-signal-safe calls are sound because another thread may
    // have held a lock at the fork. It calls fcntl, dup2, close, getrlimit and
    // the close_range syscall, all async-signal-safe; it allocates nothing and
    // takes no lock; and `placement` is a plain `Copy` value captured by move,
    // so the closure reads only memory initialized before the fork. The raw
    // descriptors it names are owned by `descriptors`, which outlives the
    // spawn below, so each is open when the child duplicates it.
    unsafe {
        command.pre_exec(move || {
            // Lift every source above the slot range first, so no dup2 below
            // can overwrite a source that has not been placed yet.
            let mut lifted: [libc::c_int; 4] = [-1; 4];
            for (i, (source, _)) in placement.moves[..placement.len].iter().enumerate() {
                let fd = libc::fcntl(
                    *source,
                    libc::F_DUPFD_CLOEXEC,
                    worker_process::FIRST_FREE_FD,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                lifted[i] = fd;
            }
            // Place each at its slot. dup2 leaves the new descriptor without
            // close-on-exec, which is what carries it across the exec.
            for (i, (_, slot)) in placement.moves[..placement.len].iter().enumerate() {
                if libc::dup2(lifted[i], *slot) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // A slot the plan leaves empty must not carry whatever this
            // process happened to have open at that number.
            for slot in placement.vacant {
                if slot >= 0 {
                    libc::close(slot);
                }
            }
            // Everything above the slots closes at exec: the worker inherits
            // stdio and its send descriptors and nothing else, not even a
            // descriptor some C library opened without close-on-exec. Marked
            // rather than closed so the standard library's own exec-error
            // pipe survives until the exec it reports on.
            #[cfg(target_os = "linux")]
            let swept = {
                libc::syscall(
                    libc::SYS_close_range,
                    worker_process::FIRST_FREE_FD as libc::c_uint,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) == 0
            };
            #[cfg(not(target_os = "linux"))]
            let swept = false;
            if !swept {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let top = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                    libc::c_int::try_from(limit.rlim_cur.min(1 << 20)).unwrap_or(1 << 20)
                } else {
                    1 << 16
                };
                for fd in worker_process::FIRST_FREE_FD..top {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    // THE step. The worker has its own copies now; this process closes every
    // one of its own, so from here on the process that parses captured traffic
    // holds no kill-path send socket. `tests/scanner_kill_process_test.rs`
    // checks it by inode against `/proc/self/fd`.
    drop(descriptors);

    let (Some(requests), Some(responses)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(
            "the worker process started without its pipes",
        ));
    };
    ScannerKillHandle::attach(requests, responses, Some(child), handed_over)
}

// ── The wire between two processes ───────────────────────────────────

/// Framing for [`KillRequest`] and [`KillResponse`] across a pipe.
///
/// The `Serialize`/`Deserialize` derives on those two types were in this file
/// from the day D16 was specified, and for a long time nothing used them: the
/// worker was a thread, and a request crossed a crossbeam channel as a Rust
/// value. They were the only thing that came of an IPC design nobody built.
///
/// This is that wire, and it is deliberately the smallest one that works. Four
/// bytes of big-endian length, then that many bytes of JSON. No handshake, no
/// version negotiation, no framing library: both ends are the same binary at
/// the same commit, spawned by each other, so a version mismatch is not a
/// state either side can reach.
///
/// **The length prefix is checked before anything is allocated.** A reader that
/// trusts a length field allocates whatever the writer says, and the writer of
/// this pipe is the sipnab that spawned the reader — but so is a debugger, a
/// misdirected file descriptor, and whatever a future refactor connects. A
/// bound costs one comparison and removes the whole class.
///
/// # Who speaks it
///
/// Four parties, two per process. In the parent, the forwarding thread writes
/// requests and the reader thread reads responses (both in
/// [`ScannerKillHandle`]); in the [`worker_process`], one pump reads requests
/// onto the decision loop's channel and the other writes its outcomes back.
/// What crosses is a request and an outcome, never a permission: the permit
/// stays in the parent, and the worker's capability is the descriptors it
/// inherited — see the module documentation.
pub mod wire {
    use std::io::{self, Read, Write};

    use serde::Serialize;
    use serde::de::DeserializeOwned;

    /// Largest frame either side writes or accepts.
    ///
    /// A kill response carries a SIP message, bounded by the largest UDP
    /// payload an IPv4 datagram can hold — about 64 KiB. `serde_json` renders
    /// a byte vector as an array of decimal numbers, so the worst case is
    /// roughly four times that. One mebibyte is comfortably above it and far
    /// below anything worth allocating on a bad length field.
    pub const MAX_FRAME_BYTES: usize = 1 << 20;

    /// Write one message as a length-prefixed JSON frame.
    ///
    /// # Arguments
    ///
    /// * `to` — the pipe half this end owns.
    /// * `msg` — the message to send.
    ///
    /// # Errors
    ///
    /// The underlying write's error, or `InvalidData` when the encoded message
    /// exceeds [`MAX_FRAME_BYTES`] — refused here rather than written, so the
    /// reader never meets a frame it is required to reject.
    pub fn write_frame<W: Write, T: Serialize>(to: &mut W, msg: &T) -> io::Result<()> {
        // `InvalidData`, not `Other`: a message that will not encode is a fact
        // about the message, and a caller has to be able to tell it from the
        // pipe having broken underneath.
        let body =
            serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "message encodes to {} bytes, over the {MAX_FRAME_BYTES}-byte frame limit",
                    body.len()
                ),
            ));
        }
        // One write for the pair. Two writes can interleave with another
        // writer's, and a length that arrives without its body is a reader
        // blocked forever on bytes nobody will send.
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
        frame.extend_from_slice(&body);
        to.write_all(&frame)?;
        to.flush()
    }

    /// Read one length-prefixed JSON frame.
    ///
    /// # Arguments
    ///
    /// * `from` — the pipe half this end owns.
    ///
    /// # Returns
    ///
    /// `Ok(None)` at a CLEAN end of stream — the peer closed between frames,
    /// which is how a shutdown looks and is not an error. `Ok(Some(msg))` for
    /// a complete frame.
    ///
    /// # Errors
    ///
    /// `UnexpectedEof` when the stream ends inside a frame, which is a peer
    /// that died mid-write and must not read as an orderly close.
    /// `InvalidData` for a length over [`MAX_FRAME_BYTES`] or a body that is
    /// not the expected message.
    pub fn read_frame<R: Read, T: DeserializeOwned>(from: &mut R) -> io::Result<Option<T>> {
        let mut len = [0u8; 4];
        match read_exact_or_eof(from, &mut len)? {
            // Nothing at all: the peer closed between frames.
            0 => return Ok(None),
            4 => {}
            n => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("stream ended after {n} of 4 length bytes"),
                ));
            }
        }
        let want = u32::from_be_bytes(len) as usize;
        // Checked BEFORE the allocation, which is the whole reason the bound
        // exists. `with_capacity(want)` on an unchecked length is a reader
        // that lets its writer decide how much memory it uses.
        if want > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame claims {want} bytes, over the {MAX_FRAME_BYTES}-byte limit"),
            ));
        }
        let mut body = vec![0u8; want];
        let got = read_exact_or_eof(from, &mut body)?;
        if got != want {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("stream ended after {got} of {want} body bytes"),
            ));
        }
        // Same reasoning as the writer: a body that is not this message is
        // invalid data, and a reader that reports it as `Other` gives its
        // caller no way to distinguish a corrupt frame from a dead pipe.
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Fill `buf`, returning how many bytes arrived before end of stream.
    ///
    /// `Read::read_exact` cannot express "nothing arrived, which is fine" and
    /// "half a frame arrived, which is not" as different answers — both are
    /// `UnexpectedEof`. Between frames those are the difference between a
    /// clean shutdown and a dead peer.
    fn read_exact_or_eof<R: Read>(from: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match from.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }
}

#[cfg(test)]
mod wire_tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::wire::{MAX_FRAME_BYTES, read_frame, write_frame};
    use super::{KillRequest, KillResponse};

    /// A request with every field populated, so a round trip proves the whole
    /// message rather than the discriminant.
    fn a_request(payload: Vec<u8>) -> KillRequest {
        KillRequest::SendResponse {
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            dst_port: 5060,
            src_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 5061,
            response_bytes: payload,
        }
    }

    /// Both directions of the protocol survive the wire.
    #[test]
    fn a_request_and_a_response_round_trip() {
        let mut pipe = Vec::new();
        let sent = a_request(b"SIP/2.0 403 Forbidden\r\n\r\n".to_vec());
        write_frame(&mut pipe, &sent).expect("write");
        let back: KillRequest = read_frame(&mut Cursor::new(&pipe))
            .expect("read")
            .expect("a frame was written");
        assert_eq!(format!("{back:?}"), format!("{sent:?}"));

        let mut pipe = Vec::new();
        let sent = KillResponse::Rejected {
            reason: "broadcast destination".to_string(),
        };
        write_frame(&mut pipe, &sent).expect("write");
        let back: KillResponse = read_frame(&mut Cursor::new(&pipe))
            .expect("read")
            .expect("a frame was written");
        assert_eq!(back, sent);
    }

    /// Frames are read in order, one call each. A reader that consumed the
    /// whole pipe would lose every message after the first.
    #[test]
    fn frames_are_read_one_at_a_time_and_in_order() {
        let mut pipe = Vec::new();
        for reason in ["first", "second", "third"] {
            write_frame(
                &mut pipe,
                &KillResponse::Rejected {
                    reason: reason.to_string(),
                },
            )
            .expect("write");
        }
        let mut cursor = Cursor::new(&pipe);
        let mut seen = Vec::new();
        while let Some(msg) = read_frame::<_, KillResponse>(&mut cursor).expect("read") {
            match msg {
                KillResponse::Rejected { reason } => seen.push(reason),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(seen, vec!["first", "second", "third"]);
    }

    /// A peer that closed BETWEEN frames is a shutdown, not a fault.
    #[test]
    fn a_clean_close_reads_as_no_message() {
        let empty: Vec<u8> = Vec::new();
        let got: Option<KillResponse> =
            read_frame(&mut Cursor::new(&empty)).expect("a clean close is not an error");
        assert!(got.is_none());
    }

    /// A peer that died mid-frame is a fault, and must not read as a shutdown.
    ///
    /// Both halves of a frame are truncated, because the length prefix and the
    /// body end in different code paths and only one of them was written
    /// first.
    #[test]
    fn a_truncated_frame_is_an_error_and_not_a_close() {
        let mut whole = Vec::new();
        write_frame(&mut whole, &a_request(vec![0u8; 64])).expect("write");

        for cut in [1usize, 2, 3, 5, whole.len() - 1] {
            let err = read_frame::<_, KillRequest>(&mut Cursor::new(&whole[..cut]))
                .expect_err("a partial frame must not read as a clean close");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "cut at {cut}: {err}"
            );
        }
    }

    /// An absurd length prefix is refused before anything is allocated.
    ///
    /// THE reason the bound exists. A reader that trusts the field allocates
    /// whatever the writer says: four bytes of `0xFF` are four gibibytes.
    #[test]
    fn an_oversized_length_is_refused_without_allocating() {
        // Length prefix only. If the reader allocated first and then read, it
        // would ask for 4 GiB before discovering there is no body at all.
        let hostile = u32::MAX.to_be_bytes().to_vec();
        let err = read_frame::<_, KillRequest>(&mut Cursor::new(&hostile))
            .expect_err("4 GiB must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(&MAX_FRAME_BYTES.to_string()),
            "the refusal must name the limit it applied: {err}"
        );

        // And one byte over the limit, which is the boundary rather than the
        // absurdity.
        let over = u32::try_from(MAX_FRAME_BYTES + 1).expect("fits");
        let err = read_frame::<_, KillRequest>(&mut Cursor::new(&over.to_be_bytes().to_vec()))
            .expect_err("one byte over the limit must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A well-framed body that is not the expected message is a fault.
    #[test]
    fn a_well_framed_body_that_is_not_the_message_is_refused() {
        let body = b"{\"not\":\"a kill request\"}";
        let mut pipe = u32::try_from(body.len())
            .expect("fits")
            .to_be_bytes()
            .to_vec();
        pipe.extend_from_slice(body);
        let err = read_frame::<_, KillRequest>(&mut Cursor::new(&pipe))
            .expect_err("the frame is well formed and its contents are not");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// The largest message the sender can legitimately produce fits.
    ///
    /// A kill response carries a SIP message, bounded by the largest payload
    /// an IPv4 UDP datagram can hold. `serde_json` writes a byte vector as
    /// decimal numbers, so this is the case the frame limit was sized for --
    /// and the one a limit chosen by eye would have cut in half.
    #[test]
    fn the_largest_legitimate_payload_still_fits_a_frame() {
        let widest = u16::MAX as usize - 20 - 8;
        let mut pipe = Vec::new();
        write_frame(&mut pipe, &a_request(vec![0xFFu8; widest]))
            .expect("the widest legal SIP payload must fit one frame");
        assert!(
            pipe.len() > widest,
            "the encoding cannot be smaller than the bytes it carries"
        );
        let back: KillRequest = read_frame(&mut Cursor::new(&pipe))
            .expect("read")
            .expect("a frame was written");
        match back {
            KillRequest::SendResponse { response_bytes, .. } => {
                assert_eq!(response_bytes.len(), widest);
                assert!(response_bytes.iter().all(|b| *b == 0xFF));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A message too large to frame is refused by the WRITER.
    ///
    /// The paired half of the reader's limit. Written, it would produce a
    /// frame the reader is required to reject -- a message that leaves one
    /// process and can never enter the other, discovered at the far end.
    #[test]
    fn a_message_over_the_limit_is_refused_before_it_is_written() {
        let mut pipe = Vec::new();
        let err = write_frame(&mut pipe, &a_request(vec![0u8; MAX_FRAME_BYTES]))
            .expect_err("a byte vector this wide cannot encode inside one frame");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            pipe.is_empty(),
            "the refusal must write nothing, or the reader meets half a frame"
        );
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Scanner-kill tests: the worker's decisions (source-spoofed and
    //! ephemeral sends, rate limiting, broadcast/multicast rejection, verbatim
    //! delivery), the parent's handle driven over real pipes against a peer
    //! served from a thread, and the ledger. Raw-socket spoof tests self-skip
    //! without `CAP_NET_RAW`. Everything that transmits sends only to a UDP
    //! listener bound on loopback by the test itself.
    //!
    //! The worker PROCESS -- the exec, the inherited descriptors, the parent
    //! closing its copies, a killed or stopped worker -- is driven in
    //! `tests/scanner_kill_process_test.rs`, which can name the `sipnab`
    //! binary cargo built. This file's executable is a test harness, so it
    //! cannot be re-executed as the worker.
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use worker_process::{SendSockets, refuse_all, serve};

    /// A transmit permit standing for a live capture.
    ///
    /// These tests create send sockets, so they must declare a live source
    /// exactly as a real run does — there is no back door, which is the point
    /// of the guard. Every send below goes to loopback only.
    fn live_permit() -> TransmitPermit {
        TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
            device: "lo".to_string(),
        })
        .expect("a live source must grant a transmit permit")
    }

    /// A worker reading a capture file cannot be spawned: the permit its
    /// constructor requires does not exist for a file source, and neither do
    /// the send descriptors it would inherit. This is the compile-time half of
    /// the offline-transmit guard, asserted here as the runtime fact it
    /// derives from.
    #[test]
    fn a_file_source_yields_no_permit_so_no_worker_can_be_spawned() {
        let file = crate::capture::CaptureSource::File {
            paths: vec![std::path::PathBuf::from("/tmp/evidence.pcap")],
        };
        assert!(
            TransmitPermit::for_source(&file).is_none(),
            "spawn_scanner_kill_worker, RawKillSocket::open and \
             KillUdpSocket::bind all take a TransmitPermit, so a None here \
             means no send descriptor can exist on a file run"
        );
    }

    /// The IPv4 loopback address (test destination/source shorthand).
    fn localhost_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A minimal valid SIP 200 OK response body for kill-send tests.
    fn sample_response() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
    }

    /// A kill request aimed at `dst`.
    fn request_to(dst: IpAddr, dst_port: u16, response_bytes: Vec<u8>) -> KillRequest {
        KillRequest::SendResponse {
            dst_addr: dst,
            dst_port,
            src_addr: localhost_v4(),
            src_port: 5060,
            response_bytes,
        }
    }

    /// A UDP listener on 127.0.0.1 — the only thing any test here sends to.
    fn loopback_listener() -> (std::net::UdpSocket, u16) {
        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();
        (listener, port)
    }

    /// An ephemeral IPv4 send socket, bound under a live permit as the parent
    /// binds the ones it hands to the worker.
    fn udp_v4_sender() -> KillUdpSocket {
        KillUdpSocket::bind(&live_permit(), (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .expect("an IPv4 socket binds")
    }

    /// Poll until `f` yields a value or `deadline` expires — replaces fixed
    /// sleeps (fast when fast, CI-tolerant).
    fn within<T>(deadline: std::time::Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        let start = Instant::now();
        loop {
            if let Some(v) = f() {
                return Some(v);
            }
            if start.elapsed() > deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }

    // ── The handle, over real pipes, against a peer served from a thread ──

    /// A handle wired to `peer`, which serves the other ends of two real
    /// pipes from a thread of its own.
    ///
    /// The same `attach` the spawn uses, minus the process: what the handle
    /// does with a worker's pipes does not depend on what is at the far end.
    fn handle_over_pipes(
        peer: impl FnOnce(std::io::PipeReader, std::io::PipeWriter) + Send + 'static,
    ) -> ScannerKillHandle {
        let (req_r, req_w) = std::io::pipe().expect("request pipe");
        let (resp_r, resp_w) = std::io::pipe().expect("response pipe");
        std::thread::Builder::new()
            .name("kill-peer-test".to_string())
            .spawn(move || peer(req_r, resp_w))
            .expect("spawn peer");
        ScannerKillHandle::attach(req_w, resp_r, None, Vec::new()).expect("attach")
    }

    /// A peer that reads nothing until released, then hangs up — a worker
    /// that has stopped.
    ///
    /// Returned with a guard whose drop releases it. Declare the guard AFTER
    /// the handle: locals drop in reverse order, so the peer lets go before
    /// the handle's own drop joins a forwarder that is blocked writing to it.
    /// A failing assertion therefore fails the test instead of hanging it.
    fn stalled_peer() -> (
        impl FnOnce(std::io::PipeReader, std::io::PipeWriter) + Send + 'static,
        Release,
    ) {
        let (tx, rx) = crossbeam_channel::bounded::<()>(1);
        let peer = move |req: std::io::PipeReader, resp: std::io::PipeWriter| {
            let _ = rx.recv();
            drop((req, resp));
        };
        (peer, Release(tx))
    }

    /// Releases a [`stalled_peer`] when dropped.
    struct Release(Sender<()>);

    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }

    /// A request goes out through the parent's pipe, the worker loop sends
    /// it, and the outcome comes back booked with the path it took.
    #[test]
    fn handle_send_and_receive() {
        let (listener, port) = loopback_listener();
        let sockets = SendSockets {
            raw: None,
            udp_v4: Some(udp_v4_sender()),
            udp_v6: None,
        };
        let mut handle = handle_over_pipes(move |req, resp| {
            serve(req, resp, 10, sockets).expect("serve");
        });

        handle
            .send_kill(request_to(localhost_v4(), port, sample_response()))
            .expect("send should succeed");

        let mut buf = [0u8; 2048];
        let (n, _) = listener.recv_from(&mut buf).expect("the datagram arrives");
        assert_eq!(&buf[..n], &sample_response()[..]);
        let resp = within(std::time::Duration::from_secs(5), || {
            handle.try_recv_response()
        });
        assert_eq!(
            resp,
            Some(KillResponse::Sent {
                path: SendPath::Ephemeral
            })
        );
        let counts = handle.counts();
        assert_eq!((counts.accepted, counts.sent), (1, 1), "{counts:?}");

        handle.shutdown();
    }

    /// With a 10/sec limit, 15 requests (to distinct dst IPs) yield exactly 10
    /// admitted and 5 `RateLimited`.
    ///
    /// Nothing is transmitted: the worker holds no socket, so each admitted
    /// request reaches the send stage and reports that it had nothing to send
    /// on. That is the observation — the limiter is consulted before any
    /// socket is.
    #[test]
    fn rate_limiter_enforces_limit() {
        let (worker, tx, resp_rx) = socketless_worker(None, 10);
        for i in 0..15u8 {
            let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i.wrapping_add(1)));
            tx.send(request_to(dst, 5060, sample_response()))
                .expect("queue has room");
        }
        drop(tx);
        worker.run();

        let outcomes: Vec<KillResponse> = resp_rx.try_iter().collect();
        let admitted = outcomes
            .iter()
            .filter(|o| matches!(o, KillResponse::Error { .. }))
            .count();
        let limited = outcomes
            .iter()
            .filter(|o| matches!(o, KillResponse::RateLimited))
            .count();
        assert_eq!(admitted, 10, "should admit exactly 10 in one window");
        assert_eq!(limited, 5, "should rate-limit the remaining 5");
    }

    /// What the decision loop answers for one request, holding no socket.
    ///
    /// The four refusals below are decided before any socket is consulted, so
    /// a socketless worker gives the same answer a real one would.
    fn decide(dst: IpAddr, body: &[u8]) -> KillResponse {
        let (mut worker, _tx, _rx) = socketless_worker(None, 10);
        worker.process_send(dst, 5060, localhost_v4(), 5060, body)
    }

    /// A broadcast destination is rejected.
    #[test]
    fn broadcast_address_rejected() {
        let outcome = decide(IpAddr::V4(Ipv4Addr::BROADCAST), &sample_response());
        assert!(
            matches!(outcome, KillResponse::Rejected { .. }),
            "broadcast should be rejected, got {outcome:?}"
        );
    }

    /// An IPv4 multicast destination is rejected.
    #[test]
    fn multicast_v4_rejected() {
        // 224.0.0.1 is multicast
        let outcome = decide(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), &sample_response());
        assert!(
            matches!(outcome, KillResponse::Rejected { .. }),
            "multicast should be rejected, got {outcome:?}"
        );
    }

    /// An IPv6 multicast destination is rejected.
    #[test]
    fn multicast_v6_rejected() {
        // ff02::1 is IPv6 multicast
        let multicast_v6 = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        let outcome = decide(multicast_v6, &sample_response());
        assert!(
            matches!(outcome, KillResponse::Rejected { .. }),
            "IPv6 multicast should be rejected, got {outcome:?}"
        );
    }

    /// An empty response body is rejected.
    #[test]
    fn empty_response_rejected() {
        let outcome = decide(localhost_v4(), &[]);
        assert!(
            matches!(outcome, KillResponse::Rejected { .. }),
            "empty response should be rejected, got {outcome:?}"
        );
    }

    /// A request pipe the worker never drains: the forwarder's first write
    /// parks until `release` is dropped, and says on `parked` that it has.
    ///
    /// A real pipe to a peer that reads nothing is NOT this. Until the
    /// forwarder is actually blocked in a write, the pipe still has room, and
    /// the forwarder can take one more request off the queue after the queue
    /// first reports full. That freed a slot under the pre-commit hook's load
    /// on 2026-09-22 and one of the "must be refused" offers was accepted.
    struct ParkedWriter {
        parked: Sender<()>,
        release: crossbeam_channel::Receiver<()>,
    }

    impl std::io::Write for ParkedWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.parked.try_send(());
            let _ = self.release.recv();
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A request the worker has no room for is counted, not silently dropped.
    ///
    /// Trading a hang for silent loss is the same defect wearing a different
    /// hat, so the refusal has to leave a mark. Deterministic because the
    /// forwarder is parked holding the first request BEFORE the queue is
    /// filled ([`ParkedWriter`]): nothing can drain the queue after that, so it
    /// fills and stays full, and the two offers that follow are refused and
    /// counted -- as backpressure, not as a death.
    #[test]
    fn a_refused_request_is_counted_not_silently_dropped() {
        let (parked_tx, parked_rx) = crossbeam_channel::bounded::<()>(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
        let (resp_r, resp_w) = std::io::pipe().expect("response pipe");
        let writer = ParkedWriter {
            parked: parked_tx,
            release: release_rx,
        };
        let handle =
            Arc::new(ScannerKillHandle::attach(writer, resp_r, None, Vec::new()).expect("attach"));
        // Dropped before the handle (reverse declaration order), so the parked
        // forwarder and the response reader both let go before its drop joins
        // them, and a failing assertion fails instead of hanging.
        let _release = Release(release_tx);
        let _responses = resp_w;

        handle
            .send_kill(request_to(localhost_v4(), 59_996, sample_response()))
            .expect("an empty queue has room");
        parked_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the forwarder must take the first request and park writing it");

        // Offered from another thread behind a timeout: if `send_kill` ever
        // waits for a slot again, that wait is the capture thread's, so this
        // must fail rather than hang the suite.
        let offerer = Arc::clone(&handle);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<(u64, usize)>(1);
        std::thread::Builder::new()
            .name("kill-offer-test".to_string())
            .spawn(move || {
                // Fill the queue behind the parked forwarder until the first
                // refusal...
                let mut before = 0u64;
                loop {
                    match offerer.send_kill(request_to(localhost_v4(), 59_996, sample_response())) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => break,
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                before += offerer.counts().dropped_requests;
                // ...then two more offers, both of which must be refused.
                let mut refused = 0usize;
                for _ in 0..2 {
                    let result =
                        offerer.send_kill(request_to(localhost_v4(), 59_996, sample_response()));
                    if matches!(result, Err(TrySendError::Full(_))) {
                        refused += 1;
                    }
                }
                let _ = done_tx.send((before, refused));
            })
            .expect("spawn offer thread");

        let (before, refused) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "send_kill waited for a slot on a full queue instead of \
                 refusing — in production that wait is the capture thread's, \
                 taken while it holds the dialog and stream write locks",
            );
        assert_eq!(before, 1, "the first refusal is counted");
        assert_eq!(
            refused, 2,
            "a full queue stays full, so the next two must be refused as Full, \
             not reported as a dead worker"
        );

        let counts = handle.counts();
        assert_eq!(
            counts.dropped_requests, 3,
            "every refusal must be counted: {counts:?}"
        );
        assert!(
            counts.any_dropped(),
            "a dropped kill response must be visible: {counts:?}"
        );
        assert!(
            !handle.defense_disabled(),
            "a full queue is backpressure, not a dead worker — the defense is \
             still armed"
        );
    }

    /// `shutdown` closes the pipe, the peer sees end of stream and exits, and
    /// shutdown returns.
    #[test]
    fn shutdown_exits_cleanly() {
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        let mut handle = handle_over_pipes(move |req, resp| {
            refuse_all(req, resp, "test").expect("clean end of stream");
            let _ = done_tx.send(());
        });
        handle.shutdown();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the peer must see end of stream when the handle shuts down");
    }

    /// The worker actually puts the response bytes on the wire (a real UDP
    /// listener receives them), not merely logs them, and says it used the
    /// ephemeral path.
    #[test]
    fn process_send_actually_transmits_over_udp() {
        let (listener, port) = loopback_listener();
        let (mut worker, _tx, _rx) = socketless_worker(None, 10);
        worker.sock_v4 = Some(udp_v4_sender());
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        let outcome = worker.process_send(localhost_v4(), port, localhost_v4(), 5060, &payload);
        assert_eq!(
            outcome,
            KillResponse::Sent {
                path: SendPath::Ephemeral
            }
        );

        let mut buf = [0u8; 2048];
        let (n, _from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the kill packet");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "listener must receive the exact response bytes"
        );
    }

    /// Response bytes with embedded NUL and high bytes are delivered verbatim.
    #[test]
    fn transmits_response_bytes_verbatim_including_nul() {
        let (listener, port) = loopback_listener();
        let (mut worker, _tx, _rx) = socketless_worker(None, 10);
        worker.sock_v4 = Some(udp_v4_sender());
        let payload = vec![
            0x00u8, 0xff, b'S', b'I', b'P', b'\\', 0x0d, 0x0a, 0x00, 0x80, 0x7f,
        ];
        let _ = worker.process_send(localhost_v4(), port, localhost_v4(), 5060, &payload);

        let mut buf = [0u8; 2048];
        let (n, _from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the kill packet");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "binary response bytes must be delivered byte-for-byte"
        );
    }

    /// The per-destination limiter's O(n) sweep is amortized to at most once
    /// per second: a second `cleanup_if_due` within the same 1s window is a
    /// no-op (it does not sweep), while a call ≥1s later sweeps again. Uses an
    /// injected monotonic `now` so no wall-clock sleeping is needed.
    #[test]
    fn per_dst_cleanup_is_amortized_to_once_per_second() {
        use std::time::Duration;
        let t0 = Instant::now();
        let mut lim = PerDstRateLimiter::new();
        let stale_a: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let stale_b: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

        // A bucket whose window started >120s before `now` is sweep-eligible.
        lim.buckets.insert(stale_a, (t0, 3));
        lim.cleanup_if_due(t0 + Duration::from_secs(200));
        assert!(
            !lim.buckets.contains_key(&stale_a),
            "first due cleanup must sweep the stale bucket"
        );

        // A second call <1s after the last sweep must NOT sweep — proof the
        // O(n) work is amortized, not paid every call.
        lim.buckets.insert(stale_b, (t0, 3));
        lim.cleanup_if_due(t0 + Duration::from_secs(200) + Duration::from_millis(500));
        assert!(
            lim.buckets.contains_key(&stale_b),
            "cleanup within the same 1s window must be skipped (amortized)"
        );

        // ≥1s after the last sweep it runs again and prunes the stale bucket.
        lim.cleanup_if_due(t0 + Duration::from_secs(202));
        assert!(
            !lim.buckets.contains_key(&stale_b),
            "cleanup must run again once ≥1s has elapsed"
        );
    }

    /// The per-destination cap answers one destination three times a minute
    /// and refuses the fourth.
    ///
    /// Written with literal counts rather than with `MAX_PER_DST_PER_MINUTE`,
    /// so raising the constant fails HERE instead of quietly widening the
    /// amplification an attacker gets for free. The kill path answers packets
    /// whose source address the sender chose, so this destination is the
    /// attacker's pick; `--kill-rate-limit` caps responses per second across
    /// ALL destinations and cannot bound how they concentrate on one.
    #[test]
    fn the_per_destination_cap_answers_three_times_and_refuses_the_fourth() {
        let mut lim = PerDstRateLimiter::new();
        let victim: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        for attempt in 1..=3 {
            assert!(
                lim.allow(victim),
                "response {attempt} of 3 must be allowed; if this fails \
                 MAX_PER_DST_PER_MINUTE dropped below 3 and a genuine scanner \
                 never sees enough refusals to notice one"
            );
        }
        assert!(
            !lim.allow(victim),
            "a 4th response to one destination inside a minute must be \
             refused; if this fails MAX_PER_DST_PER_MINUTE was raised, and \
             sipnab now amplifies harder at whichever victim an attacker \
             forges as the source address"
        );

        let bystander: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        assert!(
            lim.allow(bystander),
            "the cap is per destination, so a different destination must keep \
             its own budget"
        );
    }

    /// Source-spoofed raw send: the datagram must arrive at the listener with
    /// the **forged victim** source ip:port, not sipnab's own. Requires
    /// `CAP_NET_RAW`; skipped (not failed) when the raw socket can't be opened,
    /// so unprivileged CI stays green. Run under sudo to exercise it.
    #[test]
    fn spoofed_send_forges_source_ip_and_port() {
        let raw = match RawKillSocket::open(&live_permit()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping spoof test: raw socket unavailable ({e})");
                return;
            }
        };
        let (listener, port) = loopback_listener();

        // Forge the source as a distinctive loopback "victim" the scanner
        // would have targeted.
        let victim_ip = Ipv4Addr::new(127, 0, 0, 9);
        let victim_port = 5060u16;

        let (mut worker, _tx, _rx) = socketless_worker(Some(raw), 10);
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        let outcome = worker.process_send(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            IpAddr::V4(victim_ip),
            victim_port,
            &payload,
        );
        assert_eq!(
            outcome,
            KillResponse::Sent {
                path: SendPath::Raw
            }
        );

        let mut buf = [0u8; 2048];
        let (n, from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the spoofed packet");
        assert_eq!(&buf[..n], &payload[..], "payload delivered verbatim");
        assert_eq!(
            from.ip(),
            IpAddr::V4(victim_ip),
            "source IP must be the forged victim, not sipnab's"
        );
        assert_eq!(
            from.port(),
            victim_port,
            "source port must be the forged victim port"
        );
    }

    /// IPv6 source-spoofed raw send: the datagram must arrive at a `::1`
    /// listener with the **forged** source port (an ephemeral send would show a
    /// random port). Requires `CAP_NET_RAW`; skipped when unprivileged.
    #[test]
    fn spoofed_send_forges_source_over_ipv6() {
        let raw = match RawKillSocket::open(&live_permit()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping v6 spoof test: raw socket unavailable ({e})");
                return;
            }
        };

        let listener = match std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping v6 spoof test: no IPv6 loopback ({e})");
                return;
            }
        };
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        // Forge a distinctive source port; the address is ::1 (the only v6
        // loopback that delivers), so the port is the discriminating field.
        let victim_port = 5060u16;

        let (mut worker, _tx, _rx) = socketless_worker(Some(raw), 10);
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        let _ = worker.process_send(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            port,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            victim_port,
            &payload,
        );

        let mut buf = [0u8; 2048];
        let (n, from) = match listener.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                // Some environments block raw v6 loopback injection; treat as a
                // skip rather than a hard failure (the builder is unit-tested).
                eprintln!("skipping v6 spoof test: no packet received ({e})");
                return;
            }
        };
        assert_eq!(&buf[..n], &payload[..], "payload delivered verbatim");
        assert_eq!(from.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST), "source is ::1");
        assert_eq!(
            from.port(),
            victim_port,
            "source port must be the forged victim port, not an ephemeral one"
        );
    }

    /// The `RateLimiter` allows exactly `max_per_second` then denies.
    #[test]
    fn rate_limiter_unit_allows_within_limit() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow(), "6th request should be rejected");
    }

    /// A handle whose peer is serving reports alive and not disabled; after
    /// shutdown it is gone.
    #[test]
    fn is_alive_true_for_running_worker() {
        let mut handle = handle_over_pipes(|req, resp| {
            let _ = refuse_all(req, resp, "test");
        });
        assert!(handle.is_alive(), "a serving worker must be alive");
        assert!(!handle.defense_disabled());
        handle.shutdown();
        assert!(!handle.is_alive(), "after shutdown the worker is gone");
    }

    /// A worker that goes away is detected from its end of the pipe: the
    /// defense is marked disabled, a later send fails rather than vanishing,
    /// and what was in flight is counted as lost.
    #[test]
    fn a_dead_worker_disables_the_defense_and_counts_what_was_in_flight() {
        let (peer, release) = stalled_peer();
        let handle = handle_over_pipes(peer);
        for _ in 0..3 {
            handle
                .send_kill(request_to(localhost_v4(), 9, sample_response()))
                .expect("a live worker's queue has room");
        }
        // The peer dies holding three unanswered requests.
        drop(release);

        let dead = within(std::time::Duration::from_secs(10), || {
            handle.defense_disabled().then(|| handle.counts())
        })
        .expect(
            "the worker's end of stream must disable the defense on its own, \
             without waiting for a send to fail",
        );
        assert_eq!(dead.accepted, 3);
        assert_eq!(
            dead.lost_to_worker_exit, 3,
            "every accepted request without an outcome is lost with the worker: {dead:?}"
        );
        assert!(!handle.is_alive(), "a dead worker must report not-alive");

        let result = handle.send_kill(request_to(localhost_v4(), 9, sample_response()));
        assert!(
            matches!(result, Err(TrySendError::Disconnected(_))),
            "a send to a dead worker must fail, not vanish: {result:?}"
        );
        let after = handle.counts();
        assert_eq!(
            after.accepted, 3,
            "a refused send is not accepted, so the ledger still closes: {after:?}"
        );
    }

    /// A kill flood must never block the thread that reports the kill, even
    /// when the worker has stopped reading altogether.
    ///
    /// `send_kill` is called from the packet loop while it holds the dialog
    /// and stream write locks, so anything that blocks it stops the capture
    /// AND every reader of those stores — the REST API, the TUI, and every
    /// MCP tool, not just the kill one.
    ///
    /// The peer here reads nothing, so the request pipe fills, the forwarder
    /// blocks writing to it, and the queue in front of the forwarder fills
    /// behind it. The flood is sized well past both. The producer runs on its
    /// own thread and reports back, so the assertion is a timeout and a
    /// regression fails instead of hanging CI.
    #[test]
    fn a_kill_flood_never_blocks_the_sender() {
        let (peer, release) = stalled_peer();
        let handle = Arc::new(handle_over_pipes(peer));
        let _release = release;
        // A request frame is ~200 bytes, so a 64 KiB pipe holds a few hundred
        // of them; the queue holds KILL_REQUEST_CAPACITY more.
        let flood = 8 * KILL_REQUEST_CAPACITY + 2_000;
        let producer = Arc::clone(&handle);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<(usize, usize)>(1);
        std::thread::Builder::new()
            .name("kill-flood".to_string())
            .spawn(move || {
                let (mut accepted, mut refused) = (0usize, 0usize);
                for _ in 0..flood {
                    match producer.send_kill(request_to(localhost_v4(), 59_999, sample_response()))
                    {
                        Ok(()) => accepted += 1,
                        Err(TrySendError::Full(_)) => refused += 1,
                        Err(TrySendError::Disconnected(_)) => {}
                    }
                }
                let _ = done_tx.send((accepted, refused));
            })
            .expect("spawn flood producer");

        let (accepted, refused) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| {
                panic!(
                    "send_kill blocked: {flood} kill requests to a stopped worker did \
                     not return in 10s. In production that producer is the capture \
                     loop, holding the dialog and stream write locks, so the capture \
                     and every MCP tool stop with it."
                )
            });
        assert!(accepted > 0, "the flood must actually reach the queue");
        assert!(refused > 0, "a stopped worker must fill the queue");
        let counts = handle.counts();
        assert_eq!(
            counts.dropped_requests, refused as u64,
            "every refusal must be counted, not silently dropped: {counts:?}"
        );
        assert_eq!(
            accepted as u64 + counts.dropped_requests,
            flood as u64,
            "every offered request must be either accepted or counted as \
             dropped; accepted={accepted} counts={counts:?}"
        );
        assert!(
            !handle.defense_disabled(),
            "a full queue is backpressure, not a dead worker — the defense is \
             still armed"
        );
    }

    /// Outcomes stay reachable when the observation channel overflows.
    ///
    /// The channel is a convenience stream; the tally is the record. Feeding
    /// twice the channel's capacity through a worker nobody is listening to
    /// must leave every outcome counted, with the exact shortfall attributed
    /// to the stream rather than lost.
    #[test]
    fn outcomes_are_counted_even_when_nothing_reads_the_stream() {
        let total = 2 * KILL_OUTCOME_CAPACITY;
        let mut handle = handle_over_pipes(|req, resp| {
            let _ = refuse_all(req, resp, "test");
        });
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        // Retry a full queue rather than giving up, so all `total` requests
        // reach the worker and the arithmetic below is exact.
        for i in 0..total {
            loop {
                match handle.send_kill(request_to(localhost_v4(), 59_998, sample_response())) {
                    Ok(()) => break,
                    Err(TrySendError::Full(_)) => {
                        assert!(
                            Instant::now() < deadline,
                            "the worker stopped draining requests after {i} of {total}"
                        );
                        std::thread::yield_now();
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        panic!("worker died after {i} of {total} requests")
                    }
                }
            }
        }

        // Waited for rather than sampled once: the reader books an outcome
        // and notes its unobservability as two relaxed atomic adds.
        let unobserved_expected = (total - KILL_OUTCOME_CAPACITY) as u64;
        let counts = within(std::time::Duration::from_secs(20), || {
            let c = handle.counts();
            (c.outcomes() == total as u64 && c.unobserved_outcomes == unobserved_expected)
                .then_some(c)
        })
        .unwrap_or_else(|| {
            panic!(
                "the ledger never reconciled: expected {total} outcomes with \
                 {unobserved_expected} unobserved, got {:?}",
                handle.counts()
            )
        });
        assert!(
            counts.any_dropped(),
            "an overflowing stream must be visible, not silent: {counts:?}"
        );
        assert_eq!(counts.rejected, total as u64);
        handle.shutdown();
    }

    /// `shutdown` returns even when the request queue is full.
    ///
    /// The queue can still be full when the run ends, and the `Shutdown`
    /// message then does not fit. Shutdown must not wait for a slot (that is
    /// the blocking this type exists to avoid), so it drops the sender: the
    /// forwarder drains what is queued, closes the pipe, and the worker exits.
    #[test]
    fn shutdown_returns_even_when_the_request_queue_is_full() {
        let mut handle = handle_over_pipes(|req, resp| {
            // Not draining yet, so the queue is still full when shutdown asks.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = refuse_all(req, resp, "test");
        });
        while handle
            .send_kill(request_to(localhost_v4(), 59_997, sample_response()))
            .is_ok()
        {}

        let (done_tx, done_rx) = crossbeam_channel::bounded::<KillCounts>(1);
        std::thread::Builder::new()
            .name("kill-shutdown-test".to_string())
            .spawn(move || {
                handle.shutdown();
                let _ = done_tx.send(handle.counts());
            })
            .expect("spawn shutdown thread");

        let counts = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "shutdown blocked with a full request queue: the forwarder never \
                 saw a disconnect",
            );
        assert_eq!(
            counts.accepted,
            counts.outcomes() + counts.lost_to_worker_exit,
            "every accepted request is accounted for once the worker is gone: {counts:?}"
        );
    }

    /// `is_broadcast_or_multicast` classifies broadcast/multicast vs unicast.
    #[test]
    fn broadcast_multicast_detection() {
        assert!(is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 1
        ))));
        assert!(is_broadcast_or_multicast(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(!is_broadcast_or_multicast(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    // ── Routing and bookkeeping, with nothing able to transmit ───────────
    //
    // The raw half needs CAP_NET_RAW to open a socket and the ephemeral half
    // puts a datagram on the wire, so neither SEND is exercised below. What
    // is exercised is everything around the sends -- which path a request
    // takes, what a failure falls back to, and what is booked -- with every
    // socket absent, so a request that reached a send would have nowhere to
    // go and would say so.

    /// A worker with no UDP sockets and an optional raw one.
    ///
    /// The outcome channel is roomy because the worker WAITS to publish (see
    /// `ScannerKillWorker::run`) and these tests collect outcomes only after
    /// `run` returns.
    fn socketless_worker(
        raw_sock: Option<RawKillSocket>,
        rate: u32,
    ) -> (
        ScannerKillWorker,
        Sender<KillRequest>,
        Receiver<KillResponse>,
    ) {
        let (tx, rx) = crossbeam_channel::bounded(64);
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(64);
        let worker = ScannerKillWorker {
            rx,
            resp_tx,
            rate_limiter: RateLimiter::new(rate),
            per_dst_limiter: PerDstRateLimiter::new(),
            sock_v4: None,
            sock_v6: None,
            raw_sock,
        };
        (worker, tx, resp_rx)
    }

    /// A documentation-range address: nothing is ever sent to it, because no
    /// socket exists for anything to be sent on.
    fn test_net_v4(host: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))
    }

    #[cfg(target_os = "linux")]
    fn test_net_v6(host: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, host))
    }

    /// A raw socket lacking the family asked for refuses by name. It is the
    /// same refusal a runtime send failure produces, and it is what sends the
    /// request down the fallback path.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_raw_socket_without_the_family_refuses_rather_than_sending() {
        let raw = RawKillSocket {
            fd_v4: None,
            fd_v6: None,
        };
        let v4 = raw
            .send_to_v4(b"x", SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 5060))
            .expect_err("no IPv4 raw socket");
        assert_eq!(v4.kind(), std::io::ErrorKind::Unsupported);
        assert!(v4.to_string().contains("no IPv4 raw socket"), "{v4}");
        let v6 = raw
            .send_to_v6(
                b"x",
                std::net::SocketAddrV6::new(
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    5060,
                    0,
                    0,
                ),
            )
            .expect_err("no IPv6 raw socket");
        assert!(v6.to_string().contains("no IPv6 raw socket"), "{v6}");
    }

    /// A spoofed send that fails falls through to the ephemeral path rather
    /// than dropping the response -- and with no UDP socket either, the
    /// outcome says there was nothing to send on, which is how this test sees
    /// that the fallback was taken.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_spoofed_send_falls_back_to_the_ephemeral_path() {
        for (dst, src) in [
            (test_net_v4(10), test_net_v4(20)),
            (test_net_v6(10), test_net_v6(20)),
        ] {
            let raw = RawKillSocket {
                fd_v4: None,
                fd_v6: None,
            };
            let (mut worker, _tx, _rx) = socketless_worker(Some(raw), 100);
            let outcome = worker.process_send(dst, 5060, src, 5060, &sample_response());
            assert_eq!(
                outcome,
                KillResponse::Error {
                    message: format!("no UDP socket available for {dst}")
                },
                "the raw failure must reach the ephemeral path for {dst}"
            );
        }
    }

    /// Mixed families never occur from one packet, but if they did there is
    /// no datagram to spoof. That is not a failure: the ephemeral path takes
    /// the request.
    #[cfg(target_os = "linux")]
    #[test]
    fn mixed_address_families_skip_spoofing_and_take_the_ephemeral_path() {
        let raw = RawKillSocket {
            fd_v4: None,
            fd_v6: None,
        };
        let (mut worker, _tx, _rx) = socketless_worker(Some(raw), 100);
        let dst = test_net_v4(11);
        let outcome = worker.process_send(dst, 5060, test_net_v6(21), 5060, &sample_response());
        assert_eq!(
            outcome,
            KillResponse::Error {
                message: format!("no UDP socket available for {dst}")
            }
        );
    }

    /// A request the worker could not send on any socket is published as an
    /// error -- an outcome the parent books, not a silent drop.
    #[test]
    fn an_unsendable_request_is_published_as_an_error() {
        let (worker, tx, resp_rx) = socketless_worker(None, 100);
        tx.send(request_to(test_net_v4(12), 5060, sample_response()))
            .expect("queue has room");
        drop(tx);
        worker.run();
        assert!(matches!(resp_rx.try_recv(), Ok(KillResponse::Error { .. })));
        assert!(resp_rx.try_recv().is_err(), "exactly one outcome");
    }

    /// The worker returns once nothing can reach it: a disconnected request
    /// channel is an exit, not a spin and not a hang.
    #[test]
    fn the_worker_exits_when_no_sender_can_reach_it() {
        let (worker, tx, _rx) = socketless_worker(None, 100);
        drop(tx);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        std::thread::Builder::new()
            .name("kill-worker-disconnect-test".to_string())
            .spawn(move || {
                worker.run();
                let _ = done_tx.send(());
            })
            .expect("spawn");
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the worker must return when its channel disconnects");
    }

    /// Each outcome class has its own counter, and the derived totals agree.
    #[test]
    fn every_outcome_class_is_booked_in_its_own_counter() {
        let tally = KillTally::default();
        tally.record(&KillResponse::Sent {
            path: SendPath::Ephemeral,
        });
        for _ in 0..2 {
            tally.record(&KillResponse::RateLimited);
        }
        tally.record(&KillResponse::Rejected {
            reason: "broadcast".to_string(),
        });
        for _ in 0..3 {
            tally.record(&KillResponse::Error {
                message: "no socket".to_string(),
            });
        }
        let c = tally.snapshot();
        assert_eq!(
            (c.sent, c.rate_limited, c.rejected, c.errored),
            (1, 2, 1, 3)
        );
        assert_eq!(c.outcomes(), 7);
        assert!(!c.any_dropped());

        tally.note_unobserved_outcome();
        let c = tally.snapshot();
        assert_eq!(c.unobserved_outcomes, 1);
        assert!(c.any_dropped());
        assert_eq!(
            c.outcomes(),
            7,
            "an outcome nobody watched is still one outcome, not two"
        );
    }

    /// A `Sent` outcome moves the counter for the path it reports, and only
    /// that one.
    ///
    /// The counters the metrics exporter reads live in the parent, and the
    /// parent only learns the path from the outcome. Booked into counters of
    /// the test's own, so the counts are exact rather than "at least".
    #[test]
    fn a_sent_outcome_moves_the_counter_for_its_own_path() {
        let tally = KillTally::default();
        let counters = SendCounters::new();
        book_outcome(
            &tally,
            &counters,
            &KillResponse::Sent {
                path: SendPath::Raw,
            },
        );
        assert_eq!(counters.read(), (1, 0), "a spoofed send is counted as raw");
        book_outcome(
            &tally,
            &counters,
            &KillResponse::Sent {
                path: SendPath::Ephemeral,
            },
        );
        assert_eq!(
            counters.read(),
            (1, 1),
            "an ephemeral send is counted as ephemeral, and not as raw"
        );
        book_outcome(&tally, &counters, &KillResponse::RateLimited);
        assert_eq!(counters.read(), (1, 1), "only a send moves a send counter");
        let c = tally.snapshot();
        assert_eq!(
            (c.sent, c.rate_limited),
            (2, 1),
            "and the class is booked too"
        );
    }

    /// Every accepted request ends in exactly one class, or is lost with the
    /// worker — never both, never neither.
    ///
    /// While the worker lives, an accepted request without an outcome is IN
    /// FLIGHT, and reporting it as lost would be wrong. Once the worker is
    /// gone it can never have an outcome, and reporting it as nothing at all
    /// would be the silent loss this ledger exists to rule out.
    #[test]
    fn every_accepted_request_ends_in_one_class_or_is_lost_with_the_worker() {
        let tally = KillTally::default();
        for _ in 0..6 {
            tally.note_accepted();
        }
        tally.note_accepted();
        tally.unaccept();
        for outcome in [
            KillResponse::Sent {
                path: SendPath::Ephemeral,
            },
            KillResponse::RateLimited,
            KillResponse::Rejected {
                reason: "broadcast".to_string(),
            },
            KillResponse::Error {
                message: "no socket".to_string(),
            },
        ] {
            book_outcome(&tally, &SendCounters::new(), &outcome);
        }

        let live = tally.snapshot();
        assert_eq!(
            live.accepted, 6,
            "a request the queue refused is un-accepted"
        );
        assert_eq!(live.outcomes(), 4);
        assert_eq!(
            live.lost_to_worker_exit, 0,
            "two requests are in flight, not lost, while the worker lives"
        );

        tally.note_worker_gone();
        let dead = tally.snapshot();
        assert_eq!(dead.lost_to_worker_exit, 2, "{dead:?}");
        assert_eq!(
            dead.accepted,
            dead.outcomes() + dead.lost_to_worker_exit,
            "the ledger closes: {dead:?}"
        );
        assert!(
            dead.any_dropped(),
            "requests lost with the worker must be visible: {dead:?}"
        );
    }

    /// Once shut down, the handle refuses further requests and reports the
    /// defense as disabled from then on -- a kill after shutdown must not
    /// vanish as though it had been queued.
    #[test]
    fn a_kill_offered_after_shutdown_is_refused_and_disables_the_defense() {
        let mut handle = handle_over_pipes(|req, resp| {
            let _ = refuse_all(req, resp, "test");
        });
        handle.shutdown();
        assert!(
            !handle.defense_disabled(),
            "an orderly stop is not a failure"
        );

        let err = handle
            .send_kill(KillRequest::Shutdown)
            .expect_err("no worker is left to take it");
        assert!(matches!(
            err,
            TrySendError::Disconnected(KillRequest::Shutdown)
        ));
        assert!(handle.defense_disabled());
        assert!(handle.send_kill(KillRequest::Shutdown).is_err());
        assert!(handle.defense_disabled(), "and it stays disabled");
    }

    /// The global limit is per one-second window: once the window rolls over
    /// the count starts again, and the new window is itself limited.
    #[test]
    fn the_global_limit_resets_when_its_window_rolls_over() {
        let mut lim = RateLimiter::new(1);
        assert!(lim.allow());
        assert!(!lim.allow(), "one per window");
        lim.window_start = Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .expect("the clock has run for two seconds");
        assert!(lim.allow(), "a new window admits again");
        assert!(!lim.allow(), "and is limited in turn");
    }

    /// A destination's allowance returns after its minute, counting from one.
    #[test]
    fn a_destinations_allowance_returns_after_its_minute() {
        let mut lim = PerDstRateLimiter::new();
        let dst = test_net_v4(30);
        for _ in 0..MAX_PER_DST_PER_MINUTE {
            assert!(lim.allow(dst));
        }
        assert!(!lim.allow(dst), "capped within the minute");

        let a_minute_ago = Instant::now()
            .checked_sub(std::time::Duration::from_secs(61))
            .expect("the clock has run for a minute");
        lim.buckets
            .insert(dst, (a_minute_ago, MAX_PER_DST_PER_MINUTE));
        assert!(lim.allow(dst), "a new minute admits again");
        assert_eq!(lim.buckets[&dst].1, 1, "counting from one");
    }

    /// A read interrupted by a signal is retried, never reported as a failure
    /// or mistaken for the end of the stream.
    #[test]
    fn an_interrupted_read_is_retried_rather_than_reported() {
        use std::io::Read;
        struct InterruptedOnce {
            interrupted: bool,
            inner: std::io::Cursor<Vec<u8>>,
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.inner.read(buf)
            }
        }
        let mut pipe = Vec::new();
        wire::write_frame(&mut pipe, &KillResponse::RateLimited).expect("encode");
        let mut from = InterruptedOnce {
            interrupted: false,
            inner: std::io::Cursor::new(pipe),
        };
        assert_eq!(
            wire::read_frame::<_, KillResponse>(&mut from).expect("retried"),
            Some(KillResponse::RateLimited)
        );
        assert!(from.interrupted, "the interruption really happened");
    }

    /// Any other read error is the pipe failing, and is returned as it is --
    /// not read as the clean close a `None` would mean.
    #[test]
    fn a_failing_read_is_an_error_not_a_clean_close() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        let err = wire::read_frame::<_, KillResponse>(&mut Broken).expect_err("a dead pipe");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// A request too large to frame is booked as an error, so the ledger
    /// still closes.
    ///
    /// The writer refuses it before a byte is written, so the pipe survives,
    /// but no outcome will ever come back for it. Without the booking it would
    /// sit in the ledger as "in flight" for the rest of the run.
    #[test]
    fn a_request_too_large_to_frame_is_booked_as_an_error() {
        let mut handle = handle_over_pipes(|req, resp| {
            let _ = refuse_all(req, resp, "test");
        });
        handle
            .send_kill(request_to(
                localhost_v4(),
                9,
                vec![0u8; wire::MAX_FRAME_BYTES],
            ))
            .expect("accepted: the size is only found when it is framed");
        handle
            .send_kill(request_to(localhost_v4(), 9, sample_response()))
            .expect("the pipe is still usable after the refusal");

        let counts = within(std::time::Duration::from_secs(10), || {
            let c = handle.counts();
            (c.outcomes() == 2).then_some(c)
        })
        .unwrap_or_else(|| panic!("the ledger never closed: {:?}", handle.counts()));
        assert_eq!(
            (counts.accepted, counts.errored, counts.rejected),
            (2, 1, 1),
            "{counts:?}"
        );
        handle.shutdown();
    }

    /// Only the worker's own few variables cross to it; the parent's bearer
    /// tokens and signing keys stay behind.
    ///
    /// `--api-key`, `--api-signing-key`, `--mcp-signing-key`, `--hep-auth` and
    /// the MCP token can all arrive through the environment. The worker needs
    /// none of them, and a process holding no secret cannot leak one.
    #[test]
    fn the_worker_inherits_only_its_own_environment_variables() {
        let parent: Vec<(std::ffi::OsString, std::ffi::OsString)> = [
            "SIPNAB_API_KEY",
            "SIPNAB_API_SIGNING_KEY",
            "SIPNAB_MCP_SIGNING_KEY",
            "SIPNAB_HEP_AUTH",
            "SIPNAB_MCP_TOKEN",
            "HOME",
            "PATH",
            "SIPNAB_LOG",
            "LLVM_PROFILE_FILE",
            "NO_COLOR",
            "RUST_BACKTRACE",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "TSAN_OPTIONS",
        ]
        .into_iter()
        .map(|name| (name.into(), "fixture".into()))
        .collect();
        let mut kept: Vec<std::ffi::OsString> = worker_environment(parent)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                "LD_LIBRARY_PATH",
                "LLVM_PROFILE_FILE",
                "NO_COLOR",
                "RUST_BACKTRACE",
                "SIPNAB_LOG",
                "TSAN_OPTIONS",
            ]
            .map(std::ffi::OsString::from)
            .to_vec(),
            "what starting and logging the same binary needs, and no credential; \
             LD_PRELOAD stays behind too, since nothing the worker runs needs it"
        );
    }
}
