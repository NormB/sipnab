// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanner-kill worker process: the half of `--kill-scanner` that sends.
//!
//! This is the sipnab binary started by a parent run with [`KILL_WORKER_ARG`]
//! as its first argument. `main` hands it to [`run_if_requested`] before the
//! command line is parsed, so no combination of ordinary flags reaches it. It
//! then:
//!
//! 1. reads its own arguments (`WorkerArgs`): the rate limit, which fixed
//!    descriptors it was given, who to become, and how loudly to log;
//! 2. adopts each promised descriptor from its fixed slot (`SendFd::slot`),
//!    after checking it is a socket of the promised family and type, and
//!    refuses to start if one is missing or wrong;
//! 3. gives up everything else: root (to the parent's target user, or
//!    `nobody` — never root, whatever the parent does), every capability,
//!    the ability to regain either through exec (`PR_SET_NO_NEW_PRIVS`), and
//!    dumpability, so no other process of the same user can take its
//!    descriptors. It was started with an emptied environment too: only a
//!    short allowlist of logging and loader variables crosses, so a bearer
//!    token or signing key the parent read from its environment never
//!    reaches it;
//! 4. runs the scanner-kill decision loop unchanged — validation, the global
//!    and per-destination rate limits, broadcast/multicast refusal,
//!    raw-then-ephemeral send — between two pump threads that carry
//!    [`super::wire`] frames on stdin and stdout. End of stdin is shutdown.
//!
//! It never calls `socket()`. Holding no descriptor it answers every request
//! with a refusal (`refusal`): the parent can only create a descriptor while
//! holding a [`TransmitPermit`](crate::security::transmit_guard::TransmitPermit),
//! so "no descriptor" and "no permit" are the same refusal.
//!
//! The parent's side — creating the descriptors, placing them, and closing its
//! own copies — is [`super::spawn_scanner_kill_worker`].

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::fd::RawFd;

use super::{
    KILL_OUTCOME_CAPACITY, KILL_REQUEST_CAPACITY, KillRequest, KillResponse, KillUdpSocket,
    PerDstRateLimiter, RateLimiter, RawKillSocket, ScannerKillWorker, wire,
};

/// The first argument that selects the kill worker instead of the normal CLI.
pub const KILL_WORKER_ARG: &str = "--internal-kill-worker";

/// The first descriptor number above the fixed slots.
pub(crate) const FIRST_FREE_FD: RawFd = 7;

/// A send descriptor the worker process can inherit, each at a fixed number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SendFd {
    /// Raw IPv4 socket (`IP_HDRINCL`), for source-spoofed responses.
    RawV4,
    /// Raw IPv6 socket, for source-spoofed responses.
    RawV6,
    /// Ephemeral IPv4 UDP socket, the unspoofed fallback.
    UdpV4,
    /// Ephemeral IPv6 UDP socket, the unspoofed fallback.
    UdpV6,
}

impl SendFd {
    /// Every kind, in slot order.
    pub(crate) const ALL: [SendFd; 4] = [Self::RawV4, Self::RawV6, Self::UdpV4, Self::UdpV6];

    /// The descriptor number this kind occupies in the worker process.
    ///
    /// Fixed, and part of the contract between the two processes: the parent
    /// places each descriptor here and the worker adopts it from here.
    pub(crate) fn slot(self) -> RawFd {
        match self {
            Self::RawV4 => 3,
            Self::RawV6 => 4,
            Self::UdpV4 => 5,
            Self::UdpV6 => 6,
        }
    }

    /// The name this kind has on the worker's command line.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RawV4 => "raw4",
            Self::RawV6 => "raw6",
            Self::UdpV4 => "udp4",
            Self::UdpV6 => "udp6",
        }
    }

    /// The kind a command-line name stands for.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// Which send descriptors the worker process receives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FdPlan {
    /// Indexed by `SendFd as usize`.
    present: [bool; 4],
}

impl FdPlan {
    /// A plan holding exactly `kinds`.
    pub(crate) fn new(kinds: impl IntoIterator<Item = SendFd>) -> Self {
        let mut plan = Self::default();
        for kind in kinds {
            plan.present[kind as usize] = true;
        }
        plan
    }

    /// Whether the plan hands over `kind`.
    pub(crate) fn contains(&self, kind: SendFd) -> bool {
        self.present[kind as usize]
    }

    /// Whether the plan hands over nothing at all.
    pub(crate) fn is_empty(&self) -> bool {
        !self.present.iter().any(|p| *p)
    }

    /// The `--send-fds` value: the names in slot order, comma-separated, or
    /// `none`. Spelled out when empty so a missing value can never read as a
    /// plan.
    pub(crate) fn render(&self) -> String {
        if self.is_empty() {
            return "none".to_string();
        }
        SendFd::ALL
            .into_iter()
            .filter(|k| self.contains(*k))
            .map(SendFd::name)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Read a `--send-fds` value back.
    ///
    /// # Errors
    ///
    /// Anything [`Self::render`] never writes: an empty value, an unknown or
    /// repeated name, or `none` beside a name.
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        if value == "none" {
            return Ok(Self::default());
        }
        let mut plan = Self::default();
        for name in value.split(',') {
            let kind = SendFd::from_name(name)
                .ok_or_else(|| format!("--send-fds: unknown descriptor {name:?} in {value:?}"))?;
            if plan.contains(kind) {
                return Err(format!("--send-fds: {name} named twice in {value:?}"));
            }
            plan.present[kind as usize] = true;
        }
        Ok(plan)
    }
}

/// Everything the worker process is told on its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkerArgs {
    /// Responses per second across all destinations.
    pub(crate) rate_limit: u32,
    /// Which fixed descriptors are present.
    pub(crate) send_fds: FdPlan,
    /// The account to become if the worker starts as root.
    pub(crate) run_as: String,
    /// Default tracing filter for the worker's stderr.
    pub(crate) log_level: String,
}

impl WorkerArgs {
    /// The arguments that follow [`KILL_WORKER_ARG`].
    pub(crate) fn to_args(&self) -> Vec<String> {
        vec![
            "--rate-limit".to_string(),
            self.rate_limit.to_string(),
            "--send-fds".to_string(),
            self.send_fds.render(),
            "--run-as".to_string(),
            self.run_as.clone(),
            "--log-level".to_string(),
            self.log_level.clone(),
        ]
    }

    /// Read the arguments that follow [`KILL_WORKER_ARG`].
    ///
    /// Strict: every flag exactly once, each with a value, nothing else. A
    /// default here would be a rate limit or a descriptor nobody chose.
    ///
    /// # Errors
    ///
    /// A missing, repeated, unknown or valueless flag, or a value that does
    /// not parse. The message names the flag.
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        let mut rate_limit = None;
        let mut send_fds = None;
        let mut run_as = None;
        let mut log_level = None;
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            let slot_taken = match flag.as_str() {
                "--rate-limit" => rate_limit
                    .replace(
                        value
                            .parse::<u32>()
                            .map_err(|e| format!("--rate-limit {value:?}: {e}"))?,
                    )
                    .is_some(),
                "--send-fds" => send_fds.replace(FdPlan::parse(value)?).is_some(),
                "--run-as" => run_as.replace(value.clone()).is_some(),
                "--log-level" => log_level.replace(value.clone()).is_some(),
                other => return Err(format!("unknown argument {other:?}")),
            };
            if slot_taken {
                return Err(format!("{flag} given more than once"));
            }
        }
        Ok(Self {
            rate_limit: rate_limit.ok_or("--rate-limit is required")?,
            send_fds: send_fds.ok_or("--send-fds is required")?,
            run_as: run_as.ok_or("--run-as is required")?,
            log_level: log_level.ok_or("--log-level is required")?,
        })
    }
}

/// Whether a descriptor's address family and socket type are what the plan
/// says sits in `kind`'s slot.
pub(crate) fn descriptor_matches(kind: SendFd, family: i32, sock_type: i32) -> bool {
    let (want_family, want_type) = match kind {
        SendFd::RawV4 => (libc::AF_INET, libc::SOCK_RAW),
        SendFd::RawV6 => (libc::AF_INET6, libc::SOCK_RAW),
        SendFd::UdpV4 => (libc::AF_INET, libc::SOCK_DGRAM),
        SendFd::UdpV6 => (libc::AF_INET6, libc::SOCK_DGRAM),
    };
    family == want_family && sock_type == want_type
}

/// Confirm from `/proc/self/status` text that every capability set is empty.
///
/// The effective, permitted and inheritable sets must each be present and
/// zero; the ambient set, where the kernel reports one, must be zero too. The
/// bounding set is a ceiling on what could ever be gained, not a holding, and
/// is not checked.
///
/// # Errors
///
/// A set is missing from the text, unreadable, or not zero. The message
/// names it.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "only the Linux capability clear reads it back; its tests run everywhere"
    )
)]
pub(crate) fn caps_all_clear(status: &str) -> Result<(), String> {
    let set = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
    };
    for (name, required) in [
        ("CapInh", true),
        ("CapPrm", true),
        ("CapEff", true),
        ("CapAmb", false),
    ] {
        match set(name) {
            None if required => return Err(format!("{name} is missing from the status")),
            None => {}
            Some(hex) => match u64::from_str_radix(hex, 16) {
                Ok(0) => {}
                Ok(bits) => return Err(format!("{name} still holds {bits:#x}")),
                Err(e) => return Err(format!("{name} {hex:?} is unreadable: {e}")),
            },
        }
    }
    Ok(())
}

/// Where each inherited descriptor goes: `(source fd in the parent, slot in
/// the worker)`, plus the slots in the fixed range the plan leaves empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Placement {
    /// `(source, slot)` pairs; only the first `len` are meaningful.
    pub(crate) moves: [(RawFd, RawFd); 4],
    /// How many entries of `moves` are in use.
    pub(crate) len: usize,
    /// Slots in the fixed range that nothing is placed in; `-1` is unused.
    pub(crate) vacant: [RawFd; 4],
}

impl Placement {
    /// Plan the moves for `sources`, a list of `(kind, source fd)`.
    pub(crate) fn plan(sources: &[(SendFd, RawFd)]) -> Self {
        let mut placement = Self {
            moves: [(-1, -1); 4],
            len: 0,
            vacant: [-1; 4],
        };
        for kind in SendFd::ALL {
            match sources.iter().find(|(k, _)| *k == kind) {
                Some((_, source)) if placement.len < placement.moves.len() => {
                    placement.moves[placement.len] = (*source, kind.slot());
                    placement.len += 1;
                }
                _ => placement.vacant[kind as usize] = kind.slot(),
            }
        }
        placement
    }
}

/// The send descriptors the worker process holds, as sockets it can use.
#[derive(Default)]
pub(crate) struct SendSockets {
    /// Raw sockets for source-spoofed responses.
    pub(super) raw: Option<RawKillSocket>,
    /// Ephemeral IPv4 UDP socket.
    pub(super) udp_v4: Option<KillUdpSocket>,
    /// Ephemeral IPv6 UDP socket.
    pub(super) udp_v6: Option<KillUdpSocket>,
}

impl SendSockets {
    /// Whether there is nothing at all to send through.
    fn is_empty(&self) -> bool {
        self.raw.is_none() && self.udp_v4.is_none() && self.udp_v6.is_none()
    }
}

/// Run the kill worker over `requests` and `responses` until the request
/// stream ends or a `Shutdown` arrives.
///
/// Two pump threads adapt the unchanged decision loop to the pipes: one reads
/// request frames onto the worker's channel, the other writes its outcomes as
/// response frames. The worker itself runs on the calling thread.
///
/// # Errors
///
/// A pump thread could not be started.
pub(crate) fn serve<R, W>(
    requests: R,
    responses: W,
    rate_limit: u32,
    sockets: SendSockets,
) -> std::io::Result<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (req_tx, req_rx) = crossbeam_channel::bounded(KILL_REQUEST_CAPACITY);
    let (resp_tx, resp_rx) = crossbeam_channel::bounded(KILL_OUTCOME_CAPACITY);
    let worker = worker_for(rate_limit, sockets, req_rx, resp_tx);
    std::thread::Builder::new()
        .name("kill-worker-in".to_string())
        .spawn(move || pump_requests(requests, &req_tx))?;
    let writer = std::thread::Builder::new()
        .name("kill-worker-out".to_string())
        .spawn(move || pump_outcomes(&resp_rx, responses))?;
    worker.run();
    // The worker has returned and dropped its outcome sender, so the writer
    // drains what is left and ends. Waited for, so no outcome is lost to the
    // process exiting under it. The request pump is not waited for: after a
    // `Shutdown` it may still be parked on a read that ends with the process.
    let _ = writer.join();
    Ok(())
}

/// The decision loop, built exactly as the worker process builds it.
fn worker_for(
    rate_limit: u32,
    sockets: SendSockets,
    requests: crossbeam_channel::Receiver<KillRequest>,
    outcomes: crossbeam_channel::Sender<KillResponse>,
) -> ScannerKillWorker {
    ScannerKillWorker {
        rx: requests,
        resp_tx: outcomes,
        rate_limiter: RateLimiter::new(rate_limit),
        per_dst_limiter: PerDstRateLimiter::new(),
        sock_v4: sockets.udp_v4,
        sock_v6: sockets.udp_v6,
        raw_sock: sockets.raw,
    }
}

/// What the decision loop a worker started with `argv` decides for
/// `requests`, holding no socket.
///
/// `argv` goes through the worker's own parser, so a flag the parent renders
/// wrongly, or the worker reads wrongly, shows up here. Nothing is sent: an
/// admitted request reports that it had nothing to send on.
#[cfg(test)]
pub(crate) fn decisions_for_argv(argv: &[String], requests: Vec<KillRequest>) -> Vec<KillResponse> {
    let args = WorkerArgs::parse(argv).expect("the parent's argv parses");
    let (req_tx, req_rx) = crossbeam_channel::unbounded();
    let (resp_tx, resp_rx) = crossbeam_channel::unbounded();
    for request in requests {
        req_tx.send(request).expect("unbounded");
    }
    drop(req_tx);
    worker_for(args.rate_limit, SendSockets::default(), req_rx, resp_tx).run();
    resp_rx.try_iter().collect()
}

/// Read request frames onto the worker's channel until the stream ends.
fn pump_requests<R: Read>(mut requests: R, to_worker: &crossbeam_channel::Sender<KillRequest>) {
    loop {
        match wire::read_frame::<_, KillRequest>(&mut requests) {
            Ok(Some(request)) => {
                if to_worker.send(request).is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(e) => {
                tracing::error!("scanner-kill worker: unreadable request ({e}); stopping");
                return;
            }
        }
    }
}

/// Write the worker's outcomes as response frames until it stops producing
/// them.
fn pump_outcomes<W: Write>(outcomes: &crossbeam_channel::Receiver<KillResponse>, mut responses: W) {
    for outcome in outcomes.iter() {
        if let Err(e) = wire::write_frame(&mut responses, &outcome) {
            tracing::debug!("scanner-kill worker: response pipe closed ({e})");
            return;
        }
    }
}

/// Answer every request with a refusal: the worker holds nothing to send
/// through.
///
/// # Errors
///
/// The request stream is corrupt, or the response stream broke.
pub(crate) fn refuse_all<R: Read, W: Write>(
    mut requests: R,
    mut responses: W,
    reason: &str,
) -> std::io::Result<()> {
    loop {
        match wire::read_frame::<_, KillRequest>(&mut requests)? {
            None | Some(KillRequest::Shutdown) => return Ok(()),
            Some(KillRequest::SendResponse { .. }) => wire::write_frame(
                &mut responses,
                &KillResponse::Rejected {
                    reason: reason.to_string(),
                },
            )?,
        }
    }
}

/// Why a worker holding `sockets` must refuse everything, or `None` when it
/// has something to send through.
///
/// The worker never creates a socket, so an empty set is not a degraded mode
/// to work around: it is a worker with no permission to transmit. "No permit"
/// and "no descriptor" are the same refusal, because the parent can only
/// create a descriptor while holding a permit.
pub(crate) fn refusal(sockets: &SendSockets) -> Option<&'static str> {
    sockets
        .is_empty()
        .then_some("the scanner-kill worker holds no send descriptor, so it may not transmit")
}

/// The address family and socket type of the descriptor at `fd`.
///
/// # Errors
///
/// `fd` is not an open socket.
fn probe(fd: RawFd) -> std::io::Result<(i32, i32)> {
    let mut addr: libc::sockaddr_storage = zeroed_storage();
    let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut sock_type: libc::c_int = 0;
    let mut type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockname and getsockopt write at most `addr_len` and
    // `type_len` bytes into `addr` and `sock_type`, both of which live on this
    // frame for the duration of the calls and are sized by those lengths. A
    // descriptor that is not an open socket makes them fail with EBADF or
    // ENOTSOCK rather than touch memory.
    let (named, typed) = unsafe {
        (
            libc::getsockname(fd, std::ptr::addr_of_mut!(addr).cast(), &mut addr_len),
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                std::ptr::addr_of_mut!(sock_type).cast(),
                &mut type_len,
            ),
        )
    };
    if named != 0 || typed != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((i32::from(addr.ss_family), sock_type))
}

/// An all-zero `sockaddr_storage`, the documented starting value for an out
/// parameter the kernel fills.
fn zeroed_storage() -> libc::sockaddr_storage {
    // SAFETY: sockaddr_storage is a plain C struct of integers and byte
    // arrays, for which the all-zero bit pattern is a valid value.
    unsafe { std::mem::zeroed() }
}

/// Take ownership of the descriptors `plan` says the parent placed, after
/// checking each one is the kind of socket its slot promises.
///
/// # Errors
///
/// A promised slot holds no socket, or the wrong kind of one. The worker
/// refuses to start rather than wrap it: a connected stream wrapped as the
/// UDP socket would write kill responses into somebody's connection.
fn adopt(plan: &FdPlan) -> std::io::Result<SendSockets> {
    use std::os::fd::FromRawFd;
    let mut raw_v4 = None;
    let mut raw_v6 = None;
    let mut sockets = SendSockets::default();
    for kind in SendFd::ALL.into_iter().filter(|k| plan.contains(*k)) {
        let slot = kind.slot();
        let (family, sock_type) = probe(slot).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "descriptor {slot}, promised as {}, is not a socket: {e}",
                    kind.name()
                ),
            )
        })?;
        if !descriptor_matches(kind, family, sock_type) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "descriptor {slot}, promised as {}, is a socket of family {family} \
                     and type {sock_type}",
                    kind.name()
                ),
            ));
        }
        // SAFETY: `slot` was just shown to be an open socket, and nothing in
        // this process owns it: the parent placed it before the exec, this
        // process opens nothing before adopting, and each slot is adopted at
        // most once because `SendFd::ALL` names each kind once.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(slot) };
        match kind {
            SendFd::RawV4 => raw_v4 = Some(fd),
            SendFd::RawV6 => raw_v6 = Some(fd),
            SendFd::UdpV4 => sockets.udp_v4 = Some(KillUdpSocket(UdpSocket::from(fd))),
            SendFd::UdpV6 => sockets.udp_v6 = Some(KillUdpSocket(UdpSocket::from(fd))),
        }
    }
    if raw_v4.is_some() || raw_v6.is_some() {
        sockets.raw = Some(RawKillSocket::from_inherited(raw_v4, raw_v6));
    }
    Ok(sockets)
}

/// Give up everything the worker does not need: root, every capability, the
/// ability to regain either through exec, and dumpability.
///
/// # Errors
///
/// The worker could not stop being root or could not shed its capabilities.
/// Both are fatal: a worker holding either holds a transmit capability beyond
/// the descriptors it was given. Failing to set `PR_SET_NO_NEW_PRIVS` or to
/// clear dumpability is logged and tolerated, as it is in the parent.
fn harden(run_as: &str) -> Result<(), String> {
    if crate::privilege::is_root() {
        crate::privilege::drop_privileges(Some(run_as), false)
            .map_err(|e| format!("could not stop being root (target user {run_as}): {e}"))?;
        if crate::privilege::is_root() {
            return Err(format!(
                "still root after dropping to {run_as}; the kill worker never keeps root"
            ));
        }
    }
    #[cfg(target_os = "linux")]
    clear_capabilities()?;
    if let Err(e) = crate::privilege::block_privilege_escalation() {
        tracing::warn!("scanner-kill worker: could not block privilege escalation: {e}");
    }
    if let Err(e) = crate::privilege::make_undumpable() {
        tracing::warn!(
            "scanner-kill worker: could not make itself undumpable ({e}); another \
             process of the same user may be able to reach its send descriptors"
        );
    }
    Ok(())
}

/// Empty every capability set, then read `/proc/self/status` back to confirm.
///
/// A worker started by a non-root parent that still holds file capabilities
/// (the `--setup-caps` install) would otherwise inherit `CAP_NET_RAW` through
/// the exec: `PR_SET_NO_NEW_PRIVS` limits the new set to the parent's, it
/// does not empty it.
#[cfg(target_os = "linux")]
fn clear_capabilities() -> Result<(), String> {
    /// `struct __user_cap_header_struct`.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    /// `struct __user_cap_data_struct`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    /// `_LINUX_CAPABILITY_VERSION_3`: two data structs, 64 capability bits.
    const VERSION_3: u32 = 0x2008_0522;
    let mut header = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset(2) reads one header and, for version 3, exactly two data
    // structs, laid out here as the kernel declares them (repr(C), u32 and
    // int fields). Both live on this frame for the duration of the call.
    // Lowering every set to empty needs no privilege and cannot fail for lack
    // of one.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            std::ptr::addr_of_mut!(header),
            data.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(format!(
            "capset to empty failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status to confirm: {e}"))?;
    caps_all_clear(&status)
}

/// Install the worker's own tracing subscriber: stderr, `SIPNAB_LOG` first,
/// then the level the parent passed.
fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SIPNAB_LOG").unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::try_new(level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    });
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// How a descriptor in this process reads in `/proc`, for the startup line.
fn describe(fd: RawFd) -> String {
    #[cfg(target_os = "linux")]
    if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        return format!("fd{fd} {}", target.display());
    }
    format!("fd{fd}")
}

/// Every descriptor this process holds open, for the startup line.
///
/// So the claim "the worker inherits stdio and its send descriptors and
/// nothing else" is printed where it can be checked, not just asserted. The
/// directory handle used to list them is closed before they are confirmed, so
/// it is not among them. `None` where there is no `/proc`.
fn open_descriptors() -> Option<Vec<RawFd>> {
    #[cfg(target_os = "linux")]
    {
        let listed: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
            .ok()?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        let mut open: Vec<RawFd> = listed
            .into_iter()
            .filter(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok())
            .collect();
        open.sort_unstable();
        Some(open)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

/// Run the kill worker if this process was started as one.
///
/// Called first thing in `main`, before the normal command line is parsed.
/// Reached only when the FIRST argument is exactly [`KILL_WORKER_ARG`], which
/// no combination of ordinary flags produces: clap never sees it.
///
/// # Returns
///
/// `None` for an ordinary run; otherwise the exit code the worker finished
/// with.
pub fn run_if_requested() -> Option<i32> {
    let mut argv = std::env::args_os().skip(1);
    if argv.next().as_deref() != Some(std::ffi::OsStr::new(KILL_WORKER_ARG)) {
        return None;
    }
    let args: Vec<String> = argv.map(|a| a.to_string_lossy().into_owned()).collect();
    Some(worker_main(&args))
}

/// The worker process from its arguments to its exit code.
fn worker_main(args: &[String]) -> i32 {
    let args = match WorkerArgs::parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sipnab {KILL_WORKER_ARG}: {e}");
            return 2;
        }
    };
    init_tracing(&args.log_level);
    let sockets = match adopt(&args.send_fds) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("scanner-kill worker refused to start: {e}");
            return 3;
        }
    };
    if let Err(e) = harden(&args.run_as) {
        tracing::error!("scanner-kill worker refused to start: {e}");
        return 4;
    }
    let held: Vec<String> = SendFd::ALL
        .into_iter()
        .filter(|k| args.send_fds.contains(*k))
        .map(|k| format!("{}={}", k.name(), describe(k.slot())))
        .collect();
    let open = open_descriptors().map_or_else(
        || "unknown".to_string(),
        |fds| {
            fds.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        },
    );
    // Names only: a value could be a secret, and the point of listing them is
    // to show there are none worth hiding.
    let mut environment: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    environment.sort();
    tracing::info!(
        "scanner-kill worker process {} ready: {} responses/s, send descriptors [{}], \
         open descriptors [{open}], environment [{}]",
        std::process::id(),
        args.rate_limit,
        held.join(", "),
        environment.join(", ")
    );
    let result = match refusal(&sockets) {
        Some(reason) => refuse_all(std::io::stdin(), std::io::stdout(), reason),
        None => serve(
            std::io::stdin(),
            std::io::stdout(),
            args.rate_limit,
            sockets,
        ),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("scanner-kill worker stopped: {e}");
            5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind has its own fixed slot, all above stdio and none shared.
    #[test]
    fn every_send_descriptor_has_its_own_fixed_slot_above_stdio() {
        let slots: Vec<RawFd> = SendFd::ALL.iter().map(|k| k.slot()).collect();
        assert_eq!(
            slots,
            vec![3, 4, 5, 6],
            "the worker adopts these numbers, so they are the contract between \
             the two processes and must not move"
        );
    }

    /// The plan names exactly the descriptors that exist, and nothing else.
    #[test]
    fn the_plan_names_exactly_the_descriptors_that_exist() {
        let unprivileged = FdPlan::new([SendFd::UdpV4, SendFd::UdpV6]);
        assert_eq!(unprivileged.render(), "udp4,udp6");
        assert!(!unprivileged.contains(SendFd::RawV4));
        assert!(unprivileged.contains(SendFd::UdpV6));

        let spoofing = FdPlan::new([SendFd::UdpV4, SendFd::RawV4]);
        assert_eq!(
            spoofing.render(),
            "raw4,udp4",
            "rendered in slot order, whatever order the kinds arrived in"
        );

        let nothing = FdPlan::new([]);
        assert!(nothing.is_empty());
        assert_eq!(
            nothing.render(),
            "none",
            "an empty plan is spelled out, never an empty argument a parser \
             could read as missing"
        );
    }

    /// What the parent renders, the worker reads back unchanged.
    #[test]
    fn a_plan_survives_the_command_line() {
        for kinds in [
            vec![],
            vec![SendFd::UdpV4],
            vec![SendFd::RawV6, SendFd::UdpV4, SendFd::UdpV6],
            SendFd::ALL.to_vec(),
        ] {
            let plan = FdPlan::new(kinds.clone());
            assert_eq!(
                FdPlan::parse(&plan.render()),
                Ok(plan.clone()),
                "{kinds:?} did not survive render/parse"
            );
        }
    }

    /// A value the parent never writes is refused, not guessed at.
    #[test]
    fn a_send_fds_value_the_parent_never_writes_is_refused() {
        for bad in ["", "udp5", "udp4,", "udp4,udp4", "raw4,none", "UDP4"] {
            assert!(
                FdPlan::parse(bad).is_err(),
                "{bad:?} must be refused: adopting a descriptor the parent did \
                 not place would wrap whatever happens to sit at that number"
            );
        }
    }

    /// A full set of worker arguments.
    fn some_args() -> WorkerArgs {
        WorkerArgs {
            rate_limit: 7,
            send_fds: FdPlan::new([SendFd::RawV4, SendFd::UdpV6]),
            run_as: "nobody".to_string(),
            log_level: "warn".to_string(),
        }
    }

    /// The worker reads back exactly what the parent wrote.
    #[test]
    fn worker_arguments_survive_the_command_line() {
        let args = some_args();
        let rendered = args.to_args();
        assert_eq!(
            rendered,
            vec![
                "--rate-limit",
                "7",
                "--send-fds",
                "raw4,udp6",
                "--run-as",
                "nobody",
                "--log-level",
                "warn"
            ]
        );
        assert_eq!(WorkerArgs::parse(&rendered), Ok(args));
    }

    /// Every argument is required, once, and nothing else is accepted.
    ///
    /// A worker that defaulted a missing `--rate-limit` would rate-limit at
    /// some number nobody configured -- the shape the batch path's
    /// `--kill-rate-limit` test exists to catch one layer up.
    #[test]
    fn a_missing_duplicated_or_unknown_worker_argument_is_refused() {
        let full = some_args().to_args();
        for flag in ["--rate-limit", "--send-fds", "--run-as", "--log-level"] {
            let at = full.iter().position(|a| a == flag).expect("rendered");
            let mut missing = full.clone();
            missing.drain(at..at + 2);
            let err = WorkerArgs::parse(&missing).expect_err("a flag is missing");
            assert!(err.contains(flag), "the refusal must name {flag}: {err}");

            let mut twice = full.clone();
            twice.extend_from_slice(&full[at..at + 2]);
            let err = WorkerArgs::parse(&twice).expect_err("a flag is repeated");
            assert!(err.contains(flag), "the refusal must name {flag}: {err}");
        }
        let mut unknown = full.clone();
        unknown.push("--kill-scanner".to_string());
        assert!(WorkerArgs::parse(&unknown).is_err());

        let mut dangling = full.clone();
        dangling.push("--rate-limit".to_string());
        assert!(
            WorkerArgs::parse(&dangling).is_err(),
            "a flag with no value"
        );

        let mut not_a_number = full;
        let at = not_a_number
            .iter()
            .position(|a| a == "--rate-limit")
            .expect("rendered");
        not_a_number[at + 1] = "ten".to_string();
        assert!(WorkerArgs::parse(&not_a_number).is_err());
    }

    /// Only a descriptor of the family and type its slot promises is adopted.
    ///
    /// The worker wraps what sits at a slot as a send socket. Wrapping a
    /// connected TCP stream as a "UDP socket" would write kill responses into
    /// someone's connection; wrapping a UDP socket as the raw one would send a
    /// hand-built IP header as payload.
    #[test]
    fn only_a_descriptor_of_the_promised_family_and_type_is_adopted() {
        use libc::{AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM};
        let expected = [
            (SendFd::RawV4, AF_INET, SOCK_RAW),
            (SendFd::RawV6, AF_INET6, SOCK_RAW),
            (SendFd::UdpV4, AF_INET, SOCK_DGRAM),
            (SendFd::UdpV6, AF_INET6, SOCK_DGRAM),
        ];
        for (kind, family, sock_type) in expected {
            assert!(
                descriptor_matches(kind, family, sock_type),
                "{kind:?} must accept its own shape"
            );
        }
        for kind in SendFd::ALL {
            for (family, sock_type) in [
                (AF_INET, SOCK_STREAM),
                (AF_INET6, SOCK_STREAM),
                (AF_UNIX, SOCK_DGRAM),
            ] {
                assert!(
                    !descriptor_matches(kind, family, sock_type),
                    "{kind:?} must refuse family {family} type {sock_type}"
                );
            }
            for (other, family, sock_type) in expected {
                if other != kind {
                    assert!(
                        !descriptor_matches(kind, family, sock_type),
                        "{kind:?} must refuse the shape of {other:?}"
                    );
                }
            }
        }
    }

    /// Clear means every set reads zero, and a set that cannot be read is
    /// not clear.
    #[test]
    fn capabilities_are_clear_only_when_every_set_reads_zero() {
        let clear = "Name:\tsipnab\nCapInh:\t0000000000000000\n\
                     CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
                     CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        assert_eq!(
            caps_all_clear(clear),
            Ok(()),
            "the bounding set is a ceiling, not a holding, and is not required \
             to be empty"
        );

        for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let held = clear.replace(
                &format!("{set}:\t0000000000000000"),
                &format!("{set}:\t0000000000002000"),
            );
            let err = caps_all_clear(&held).expect_err("CAP_NET_RAW is held");
            assert!(err.contains(set), "the refusal must name {set}: {err}");
        }

        let unreadable = "Name:\tsipnab\nCapInh:\t0000000000000000\n";
        assert!(
            caps_all_clear(unreadable).is_err(),
            "a status with no CapEff line proves nothing about the effective set"
        );
    }

    /// Each present descriptor moves to its own slot; every other slot in the
    /// fixed range is named as vacant, so the worker cannot inherit whatever
    /// the parent happened to have open at that number.
    #[test]
    fn placement_moves_each_source_to_its_slot_and_vacates_the_rest() {
        let p = Placement::plan(&[(SendFd::UdpV4, 40), (SendFd::RawV4, 41)]);
        assert_eq!(p.len, 2);
        assert_eq!(
            &p.moves[..p.len],
            &[(41, 3), (40, 5)],
            "in slot order, each source to its own slot"
        );
        let mut vacant: Vec<RawFd> = p.vacant.iter().copied().filter(|&v| v >= 0).collect();
        vacant.sort_unstable();
        assert_eq!(vacant, vec![4, 6]);

        let none = Placement::plan(&[]);
        assert_eq!(none.len, 0);
        let mut vacant: Vec<RawFd> = none.vacant.iter().copied().filter(|&v| v >= 0).collect();
        vacant.sort_unstable();
        assert_eq!(
            vacant,
            vec![3, 4, 5, 6],
            "nothing placed, everything vacated"
        );
    }

    /// A worker holding no send descriptor refuses; one holding any does not.
    ///
    /// The worker never creates a socket, so an empty set means no permission
    /// to transmit, and the refusal says so rather than reporting a send error
    /// per request as though something had merely failed.
    #[test]
    fn a_worker_holding_no_send_descriptor_refuses_and_one_holding_any_does_not() {
        let reason = refusal(&SendSockets::default()).expect("nothing to send through");
        assert!(reason.contains("no send descriptor"), "{reason}");

        let one = SendSockets {
            udp_v4: Some(KillUdpSocket(
                UdpSocket::bind("127.0.0.1:0").expect("bind (nothing is sent)"),
            )),
            ..SendSockets::default()
        };
        assert_eq!(refusal(&one), None, "one descriptor is enough to serve");
    }

    /// The refusing worker answers every request with the refusal, in order,
    /// and stops at `Shutdown` without answering what follows it.
    #[test]
    fn a_refusing_worker_answers_each_request_and_stops_at_shutdown() {
        let request = || KillRequest::SendResponse {
            dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            dst_port: 5060,
            src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
            src_port: 5060,
            response_bytes: b"SIP/2.0 200 OK\r\n\r\n".to_vec(),
        };
        let mut input = Vec::new();
        for msg in [request(), request(), KillRequest::Shutdown, request()] {
            wire::write_frame(&mut input, &msg).expect("encode");
        }
        let mut output = Vec::new();
        refuse_all(
            std::io::Cursor::new(input),
            &mut output,
            "no descriptor here",
        )
        .expect("a clean stream");

        let mut replies = std::io::Cursor::new(output);
        let mut seen = Vec::new();
        while let Some(reply) =
            wire::read_frame::<_, KillResponse>(&mut replies).expect("well framed")
        {
            seen.push(reply);
        }
        let refused = KillResponse::Rejected {
            reason: "no descriptor here".to_string(),
        };
        assert_eq!(
            seen,
            vec![
                refused,
                KillResponse::Rejected {
                    reason: "no descriptor here".to_string()
                }
            ],
            "two requests before the Shutdown, two refusals, nothing after it"
        );
    }

    /// A worker whose response pipe is slow waits for it rather than dropping
    /// an outcome.
    ///
    /// The parent books an outcome only when it arrives, so an outcome dropped
    /// here is a request its ledger carries as in flight for ever. Waiting is
    /// safe on this side of the pipe: nothing in the parent's capture path
    /// waits on the worker. More requests than the outcome channel holds, so
    /// a worker that offered instead of waiting would lose the overflow.
    #[test]
    fn a_slow_response_pipe_delays_outcomes_and_loses_none() {
        /// A writer that blocks its first write until released.
        struct Gate {
            open: crossbeam_channel::Receiver<()>,
            opened: bool,
            out: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
        }
        impl Write for Gate {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.opened {
                    let _ = self.open.recv();
                    self.opened = true;
                }
                self.out.lock().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let total = KILL_OUTCOME_CAPACITY + KILL_REQUEST_CAPACITY + 50;
        let mut input = Vec::new();
        for i in 0..total {
            let request = KillRequest::SendResponse {
                dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::from(0xC000_0200 + i as u32)),
                dst_port: 5060,
                src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                src_port: 5060,
                response_bytes: b"SIP/2.0 200 OK\r\n\r\n".to_vec(),
            };
            wire::write_frame(&mut input, &request).expect("encode");
        }
        let (release, open) = crossbeam_channel::bounded::<()>(1);
        let out = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let gate = Gate {
            open,
            opened: false,
            out: std::sync::Arc::clone(&out),
        };
        let served = std::thread::spawn(move || {
            // No socket: every admitted request reports it had nothing to
            // send on, so nothing is transmitted. The count is what matters.
            serve(
                std::io::Cursor::new(input),
                gate,
                u32::MAX,
                SendSockets::default(),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        release.send(()).expect("release the pipe");
        served
            .join()
            .expect("serve returns")
            .expect("serve succeeds");

        let bytes = out.lock().clone();
        let mut replies = std::io::Cursor::new(bytes);
        let mut n = 0usize;
        while wire::read_frame::<_, KillResponse>(&mut replies)
            .expect("well framed")
            .is_some()
        {
            n += 1;
        }
        assert_eq!(
            n, total,
            "every request must produce exactly one outcome, however slow the pipe"
        );
    }
}
