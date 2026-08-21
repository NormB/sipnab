// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live network device capture.
//!
//! Opens a pcap handle on a network interface in promiscuous mode and sends
//! captured packets through a crossbeam channel. The capture loop respects
//! the global shutdown flag from [`crate::signals`] and applies optional BPF
//! filters, packet count limits, and duration limits.

use super::channel::PacketTx;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};

use super::CaptureConfig;
use super::packet::Packet;
use crate::signals;

/// How long [`wait_readable`] blocks before returning control to the capture
/// loop so it can re-check the shutdown flag and the count/duration limits.
///
/// pcap's own read timeout is unreliable on the Linux `any` pseudo-device and
/// some drivers (it may not fire at all when the interface is idle), so we do
/// not depend on it for liveness — we poll the capture fd ourselves with this
/// bounded interval. This is what makes `--duration` / Ctrl-C take effect even
/// when no packets are arriving.
#[cfg(unix)]
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// pcap read timeout (ms) used when immediate mode is on — the interactive
/// path, where libpcap is pinned to TPACKET_V2.
///
/// On V2 this is only the upper bound libpcap waits inside one read before
/// giving up, and immediate delivery means it rarely gets there. Kept at the
/// long-standing 100 ms.
const IMMEDIATE_READ_TIMEOUT_MS: i32 = 100;

/// pcap read timeout (ms) used when immediate mode is off — the headless path,
/// where libpcap selects TPACKET_V3.
///
/// Deliberately short, and this is the whole cost of choosing V3. libpcap
/// copies the read timeout into the ring request as `tp_retire_blk_tov`, the
/// kernel's *block retire* timer: a partially-filled block is not handed to
/// userspace until either it fills or that many milliseconds elapse. Inheriting
/// the 100 ms above would therefore have added up to 100 ms of delivery latency
/// to every packet on a link too quiet to fill a block — a real regression
/// traded for ring depth, and one nothing in the output would have shown.
///
/// 5 ms bounds that at a twentieth of the poll interval the loop already
/// tolerates when idle, while still letting a busy link batch heavily: the
/// timer only decides anything for blocks that do not fill first, and at even
/// 100k packets/s a 5 ms block holds hundreds of packets.
const BATCHED_READ_TIMEOUT_MS: i32 = 5;

/// The pcap read timeout to open with, given whether immediate mode is on.
///
/// A function rather than a literal at the call site because the two values
/// mean different things to libpcap (a read bound vs a kernel block-retire
/// timer) and the batched one is only safe while it stays small — which the
/// tests pin.
fn read_timeout_ms(immediate: bool) -> i32 {
    if immediate {
        IMMEDIATE_READ_TIMEOUT_MS
    } else {
        BATCHED_READ_TIMEOUT_MS
    }
}

/// Result of waiting for a capture fd to become readable.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitResult {
    /// Data is available; call `next_packet()`.
    Readable,
    /// The wait window elapsed with no data — re-check loop conditions.
    TimedOut,
}

/// Convert a [`Duration`](std::time::Duration) into a `poll(2)` timeout in
/// milliseconds, clamped to `[0, c_int::MAX]`.
///
/// The clamp is load-bearing: an unchecked cast of a large duration can wrap to
/// a negative value, and a negative `poll` timeout means "block forever" — the
/// exact failure mode we are fixing. We never want that, so we saturate.
#[cfg(unix)]
fn poll_timeout_millis(timeout: std::time::Duration) -> libc::c_int {
    timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
}

/// Wait up to `timeout` for `fd` to become readable.
///
/// Returns [`WaitResult::Readable`] as soon as data is available, or
/// [`WaitResult::TimedOut`] when the window elapses (or a signal interrupts the
/// call — surfacing promptly lets the loop notice a shutdown request). A closed
/// or otherwise invalid fd (`POLLNVAL`) is reported as an error rather than a
/// spurious `Readable`, which — paired with a non-blocking `next_packet()` that
/// returns nothing — would otherwise hot-spin.
#[cfg(unix)]
fn wait_readable(
    fd: std::os::unix::io::RawFd,
    timeout: std::time::Duration,
) -> std::io::Result<WaitResult> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a valid, owned pollfd for the duration of the call
    // and the count (1) matches; `poll` only writes `revents`.
    let ret = unsafe {
        libc::poll(
            &mut pfd as *mut libc::pollfd,
            1,
            poll_timeout_millis(timeout),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINTR: a signal arrived. Treat as a timeout so the loop re-checks the
        // shutdown flag immediately instead of erroring out.
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(WaitResult::TimedOut);
        }
        return Err(err);
    }
    if ret == 0 {
        return Ok(WaitResult::TimedOut);
    }
    if pfd.revents & libc::POLLNVAL != 0 {
        return Err(std::io::Error::other("poll: invalid capture fd (POLLNVAL)"));
    }
    // POLLIN, or POLLERR/POLLHUP — let next_packet() surface any real error.
    Ok(WaitResult::Readable)
}

/// Run a live capture loop on the given network device.
///
/// Opens the device with the parameters from `config`, applies any BPF filter,
/// then loops reading packets until shutdown is requested, the count limit is
/// reached, or the duration limit expires.
///
/// This function blocks and is intended to be called from a dedicated thread.
///
/// # Arguments
///
/// * `device` - interface name (`"any"` is never promiscuous).
/// * `config` - snaplen, kernel buffer size, promiscuous flag, BPF filter,
///   and count/duration limits.
/// * `tx` - channel the captured `Packet`s are sent into.
/// * `ready_tx` - optional one-shot channel: receives `Ok(())` once the
///   device is open and filtered (so the caller can drop privileges), or
///   `Err(msg)` on open/filter failure.
///
/// # Returns
///
/// `Ok(())` on shutdown, count limit, duration limit, or receiver drop.
///
/// # Errors
///
/// Fails when the device cannot be opened/activated (the message appends the
/// available-device list for non-permission failures), the BPF filter does
/// not compile, non-blocking mode cannot be set, or polling/reading the
/// capture fd hits a fatal error.
///
/// # Side effects
///
/// Opens a capture socket (promiscuous unless disabled), sends packets on
/// `tx`, signals `ready_tx`, blocks up to `POLL_INTERVAL` per idle poll,
/// checks the global shutdown flag, and logs progress via tracing.
pub fn capture_live(
    device: &str,
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<()> {
    capture_live_group(device, config, tx, ready_tx, None)
}

/// How many sockets a fanout request resolves to, and why.
///
/// Pure so the decision can be tested without a capture device: the interesting
/// cases are all "do not fan out", and each has a different reason a reader
/// needs to see in a log line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FanoutPlan {
    /// One socket, no group. `PACKET_FANOUT` was not asked for, is not
    /// available on this platform, or the kernel refused the probe.
    Solo(&'static str),
    /// `n` sockets sharing one group.
    Group(usize),
}

/// Decide the plan from the request and the platform. The kernel probe is the
/// caller's job; this answers everything knowable without touching a device.
pub(crate) fn plan_fanout(sockets: usize) -> FanoutPlan {
    if !cfg!(target_os = "linux") {
        return FanoutPlan::Solo("PACKET_FANOUT is Linux-only");
    }
    match sockets {
        0 | 1 => FanoutPlan::Solo("one socket requested"),
        n => FanoutPlan::Group(n),
    }
}

/// The frame counter this socket may keep, or `None` when it must not number
/// its frames at all.
///
/// A frame pointer is `<source>#<ordinal>`, and the source here is the DEVICE
/// NAME — one string for however many sockets `PACKET_FANOUT` opened on it.
/// Under a group, `capture_live_group` runs once per socket, so a counter per
/// socket would mint `eth0#0` from every one of them: several different frames
/// with one name. Following such a pointer returns bytes that are not the ones
/// described, which is worse than following nothing, and no `is_some()` check
/// downstream can tell the two apart.
///
/// So a grouped socket stamps nothing and `Packet::frame_ref` keeps returning
/// `None` for it — the behaviour every live capture had before stage two, which
/// is a MISSING answer rather than a wrong one. The alternative, one shared
/// atomic across the group's sockets, buys provenance for the one live mode
/// that exists to shed load, at a per-packet atomic on the contended path; it
/// has not been measured, and this repo does not upgrade a reasoned claim to a
/// measured one.
///
/// Pure so the decision is testable without a capture device, exactly as
/// [`plan_fanout`] is.
pub(crate) fn frame_counter_for(
    fanout_group: Option<u16>,
) -> Option<crate::capture::packet::FrameCounter> {
    fanout_group
        .is_none()
        .then(crate::capture::packet::FrameCounter::new)
}

/// Group id for this process.
///
/// Derived from the pid so two sipnab instances capturing the same interface do
/// not land in one group and split each other's traffic. `0` is a legal group
/// id but is also what an uninitialised value looks like, so it is mapped away.
pub(crate) fn fanout_group_id() -> u16 {
    let pid = std::process::id() as u16;
    if pid == 0 { 0xA1B2 } else { pid }
}

/// Capture from `device` across `sockets` kernel-fanned sockets.
///
/// Every socket feeds the SAME `tx`, so this widens capture only — the
/// processing loop, the stores and the sweep are untouched. See
/// [`crate::capture::fanout`] for why that boundary matters.
///
/// Falls back to a single socket, with a warning naming the reason, when the
/// platform has no `PACKET_FANOUT` or the kernel refuses the probe. The probe
/// exists so the refusal is discovered once, on a throwaway handle, rather than
/// by N capture threads each having to decide what to do about it.
pub fn capture_live_fanout(
    device: &str,
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
    sockets: usize,
) -> Result<()> {
    let group = match plan_fanout(sockets) {
        FanoutPlan::Solo(reason) => {
            if sockets > 1 {
                tracing::warn!(
                    "'{device}': capturing on one socket ({reason}); \
                     --cores {sockets} does not widen a live capture here."
                );
            }
            return capture_live(device, config, tx, ready_tx);
        }
        FanoutPlan::Group(_) => fanout_group_id(),
    };

    // Probe on a throwaway handle before committing N threads. A kernel that
    // refuses PACKET_FANOUT refuses it for every socket, and discovering that
    // once is cheaper — and far easier to report — than N threads each failing
    // separately after the ready signal has already been sent.
    if let Err(e) = probe_fanout(device, config, group) {
        tracing::warn!(
            "'{device}': the kernel refused PACKET_FANOUT ({e}); capturing on \
             one socket. Live capture will not scale past a single core here."
        );
        return capture_live(device, config, tx, ready_tx);
    }

    // -B is PER HANDLE, so N sockets ask the kernel for N rings of that size.
    // Say the total out loud rather than letting a flag that allocated one
    // buffer yesterday quietly allocate several today: at the 64 MiB default,
    // `--cores 8` is half a gigabyte of locked ring, and the operator who set
    // -B did not agree to a multiplier.
    //
    // Whether N should DIVIDE the request instead is a live design question
    // (see docs/design/live-fanout.md) and is deliberately not decided here —
    // dividing silently shrinks a buffer an operator sized on purpose, which is
    // the same class of surprise in the other direction.
    let total_ring_mb = u64::from(config.buffer_mb) * sockets as u64;
    tracing::info!(
        "'{device}': capturing on {sockets} sockets, fanout group {group}; \
         -B {} MiB is per socket, so ~{total_ring_mb} MiB of ring in total. \
         This widens CAPTURE only — processing stays on one thread, so this is \
         not {sockets} cores of analysis",
        config.buffer_mb,
    );
    let mut handles = Vec::with_capacity(sockets);
    for index in 0..sockets {
        let device = device.to_string();
        let config = config.clone();
        let tx = tx.clone();
        // Only the first socket answers the readiness handshake. N answers to a
        // one-shot channel would leave the caller's meaning of "ready" up to
        // whichever thread won.
        let ready = if index == 0 { ready_tx.clone() } else { None };
        handles.push(
            std::thread::Builder::new()
                .name(format!("capture-{device}-{index}"))
                .spawn(move || capture_live_group(&device, &config, tx, ready, Some(group)))?,
        );
    }

    let mut first_err = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert_with(|| anyhow::anyhow!("a capture thread panicked"));
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Open a handle, try to join `group`, and drop it. Answers "will this kernel
/// fan out on this device" without disturbing a real capture.
fn probe_fanout(device: &str, config: &CaptureConfig, group: u16) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let cap = pcap::Capture::from_device(device)?
            .promisc(config.promisc && device != "any")
            .snaplen(config.snaplen as i32)
            .timeout(read_timeout_ms(config.immediate_mode))
            .open()?;
        super::fanout::join_fanout_group(cap.as_raw_fd(), group)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, config, group);
        anyhow::bail!("PACKET_FANOUT is Linux-only")
    }
}

/// Whether a capture-open failure is really "you lack the privilege".
///
/// One function, called from here and from the bootstrap, because the two used
/// to carry separate copies of this test and had already drifted: the
/// bootstrap checked `socket:` and this one did not.
///
/// `CAP_NET_RAW` is the case that matters and the one that was missing. Linux
/// libpcap reports an unprivileged live open as
///
/// ```text
/// Attempt to create packet socket failed - CAP_NET_RAW may be required
/// ```
///
/// which contains no form of "permission", no `EPERM`, and no `socket:`. So a
/// normal user on Linux -- the single most common way to meet this error --
/// fell through to the generic branch and was shown the device list instead of
/// the `--setup-caps` hint that exists precisely for them. The remedy was
/// already written; it was unreachable.
pub(crate) fn is_permission_error(msg: &str) -> bool {
    msg.contains("ermission")
        || msg.contains("EPERM")
        || msg.contains("Operation not permitted")
        || msg.contains("socket:")
        || msg.contains("CAP_NET_RAW")
}

/// The single-socket capture loop, optionally joined to a fanout group.
fn capture_live_group(
    device: &str,
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
    fanout_group: Option<u16>,
) -> Result<()> {
    // Promiscuous mode is opt-out (`--no-promisc` / `config.promisc`). The "any"
    // pseudo-device on Linux does not support it regardless.
    let use_promisc = config.promisc && device != "any";

    if config.buffer_mb > MAX_BUFFER_MB {
        tracing::warn!(
            "-B/--buffer {} MiB exceeds the {MAX_BUFFER_MB} MiB ceiling \
             (pcap_set_buffer_size takes a C int); capturing with \
             {MAX_BUFFER_MB} MiB instead.",
            config.buffer_mb,
        );
    }

    // Open with the requested ring, falling back to smaller ones if the kernel
    // will not give us that much. See `buffer_ladder`.
    let mut opened = None;
    let mut open_err = None;
    // The size the kernel actually granted, which is what the drop warning has
    // to quote. It is not `config.buffer_mb` whenever the ladder stepped down.
    let mut granted_mb = config.buffer_mb;
    for (attempt, mb) in buffer_ladder(config.buffer_mb).into_iter().enumerate() {
        let result = pcap::Capture::from_device(device)
            .with_context(|| format!("Failed to open device '{device}'"))
            .and_then(|inactive| {
                inactive
                    .promisc(use_promisc)
                    .snaplen(config.snaplen as i32)
                    .buffer_size(buffer_size_bytes(mb))
                    // Read timeout and immediate mode are one decision, not two.
                    // On Linux, asking for immediate delivery makes libpcap
                    // refuse TPACKET_V3 (a V3 block cannot be retired early), so
                    // the interactive path runs on V2 — where the ring is carved
                    // into snaplen-sized slots and a 64 MiB ring at snaplen 65535
                    // holds about a thousand packets. Headless captures give up
                    // immediate delivery to get V3's snaplen-independent ring,
                    // and pay for it with a short block-retire timer instead of
                    // the 100 ms one V3 would otherwise inherit. See
                    // `read_timeout_ms` and `CaptureConfig::immediate_mode`.
                    //
                    // Neither choice touches how quickly the loop below reacts to
                    // shutdown: the handle is non-blocking, so an empty ring
                    // returns TimeoutExpired at once and the wait that follows is
                    // sipnab's own bounded `poll()` on the capture fd. `--duration`
                    // and Ctrl-C are answered within POLL_INTERVAL either way.
                    .timeout(read_timeout_ms(config.immediate_mode))
                    .immediate_mode(config.immediate_mode)
                    .open()
                    .with_context(|| format!("Failed to activate capture on '{device}'"))
            });
        match result {
            Ok(cap) => {
                if attempt > 0 {
                    // Say so loudly. A silently-shrunk ring is a capture that
                    // will drop under load for a reason nobody can see, which
                    // is the whole failure mode the bigger default exists to
                    // prevent.
                    tracing::warn!(
                        "'{device}': the kernel refused a {} MiB capture buffer; \
                         capturing with {mb} MiB instead. This host will tolerate \
                         a smaller burst before dropping — watch the drop counters, \
                         and set -B/--buffer explicitly to pin a size.",
                        config.buffer_mb,
                    );
                }
                granted_mb = effective_buffer_mb(mb);
                opened = Some(cap);
                break;
            }
            Err(e) => open_err = Some(e),
        }
    }

    let mut cap = match opened.ok_or_else(|| {
        open_err.unwrap_or_else(|| anyhow::anyhow!("Failed to open device '{device}'"))
    }) {
        Ok(cap) => cap,
        Err(e) => {
            // Help a typo'd device name: append what actually exists (the
            // auto-detect path already does). Permission failures keep their
            // own dedicated hint in the bootstrap, so skip the list there.
            let mut msg = format!("{e:#}");
            let is_permission = is_permission_error(&msg);
            if !is_permission {
                let devices = crate::capture::device::list_devices();
                if !devices.is_empty() {
                    msg.push_str(&format!("\n  Available devices: {}", devices.join(", ")));
                }
            }
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(msg.clone()));
            }
            return Err(anyhow::anyhow!(msg));
        }
    };

    if let Some(ref bpf) = config.bpf_filter
        && let Err(e) = cap.filter(bpf, true)
    {
        let err = anyhow::Error::new(e).context(format!("Failed to compile BPF filter: {bpf}"));
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(format!("{err:#}")));
        }
        return Err(err);
    }

    // Put the handle into non-blocking mode. The capture loop drives its own
    // liveness by polling the fd (see `wait_readable`), so individual reads
    // must never block — otherwise an idle interface would stall the loop and
    // `--duration` / Ctrl-C would not take effect until the next packet.
    #[cfg(unix)]
    let mut cap = match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => {
            let err = anyhow::Error::new(e)
                .context(format!("Failed to set non-blocking mode on '{device}'"));
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{err:#}")));
            }
            return Err(err);
        }
    };

    // Selectable fd for poll(2). On Linux this is the packet-socket fd and is
    // valid for the lifetime of the capture.
    #[cfg(unix)]
    let poll_fd = {
        use std::os::unix::io::AsRawFd;
        cap.as_raw_fd()
    };

    // Not gated on `target_os = "linux"`, deliberately.
    //
    // `join_fanout_group` already carries the platform split: it is a real
    // setsockopt on Linux and a stub returning `Unsupported` elsewhere. Gating
    // the CALL as well duplicated that decision, and got it wrong — the cfg
    // covered the use of `fanout_group` but not the binding, so on macOS the
    // parameter was unused and `-D warnings` failed the build. Twice.
    //
    // Keeping one platform decision in one place makes that mistake
    // unrepresentable: the parameter is read on every unix target, so it cannot
    // become unused on one of them. The `bail!` is unreachable off Linux
    // because `plan_fanout` returns `Solo` there, so `fanout_group` is `None`.
    // A FAILURE HERE IS FATAL TO THIS SOCKET, deliberately. An ungrouped socket
    // on the same interface does not capture a share of the traffic — it
    // captures ALL of it. Falling back to "carry on without the group" would
    // therefore feed the channel a duplicate of every packet for each socket
    // that failed, and duplicated RTP is not a degraded reading: it doubles
    // octet counts and reports a stream at twice its codec's rate. Refusing to
    // capture is the honest outcome; the caller probes before committing (see
    // `capture_live_fanout`) so this is the unexpected path, not the normal one.
    #[cfg(unix)]
    if let Some(group) = fanout_group {
        use std::os::unix::io::AsRawFd;
        if let Err(e) = super::fanout::join_fanout_group(cap.as_raw_fd(), group) {
            anyhow::bail!(
                "'{device}': could not join PACKET_FANOUT group {group}: {e}. \
                 Refusing to capture on this socket rather than duplicate every \
                 packet the other sockets in the group already carry."
            );
        }
        tracing::debug!("'{device}': joined PACKET_FANOUT group {group}");
    }

    // Signal that the capture device is open and ready.
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    let link_type = cap.get_datalink().0;
    let interface_name = Some(device.to_string());
    let start = std::time::Instant::now();
    let mut count: u64 = 0;
    // This device's frame numbering, kept separately from `count` because the
    // two answer different questions: `count` is what `--count` and the summary
    // line bound, whereas the ordinal is half of a provenance pointer and
    // belongs to THIS source. Under `--multi-device` and under a `-d` + `-L`
    // composite several readers push into one channel, so one counter per
    // reader is what keeps each source's positions its own -- see
    // `FrameCounter`. `None` under `PACKET_FANOUT`, where several sockets share
    // this device name and no per-socket counter could number them without
    // collisions -- see `frame_counter_for`.
    let mut frames = frame_counter_for(fanout_group);

    // Kernel/interface drop accounting. libpcap's counters are cumulative per
    // handle, so the loop keeps the previous reading and folds the delta into
    // the process-global totals — see `fold_stats`.
    let mut last_stats = std::time::Instant::now();
    let (mut prev_dropped, mut prev_if_dropped) = (0u32, 0u32);

    tracing::info!(
        "Capturing on '{device}' (link_type={link_type}, snaplen={})",
        config.snaplen
    );

    loop {
        // Ask libpcap what the kernel threw away. On a timer rather than per
        // packet: `pcap_stats` is a syscall, and a capture that polls it per
        // packet spends more time measuring loss than avoiding it.
        if last_stats.elapsed() >= STATS_INTERVAL {
            last_stats = std::time::Instant::now();
            match cap.stats() {
                Ok(stat) => fold_stats(
                    device,
                    &stat,
                    granted_mb,
                    &mut prev_dropped,
                    &mut prev_if_dropped,
                ),
                // Not fatal: some capture backends do not implement stats. The
                // capture is still good; only the loss visibility is missing.
                Err(e) => tracing::debug!("pcap_stats unavailable on '{device}': {e}"),
            }
        }

        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping live capture");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            break;
        }

        // Read FIRST, poll only when the ring is dry.
        //
        // This loop used to `poll()` before every `next_packet()`, which cost a
        // syscall per packet — at the rates this tool benchmarks at, millions
        // per second — and bought nothing whenever the ring already held data,
        // which on a busy link is essentially always. libpcap's Linux capture
        // is a memory-mapped TPACKET ring: draining it is userspace pointer
        // work, and `poll()` is only needed once it is empty.
        //
        // So the wait moved into the `TimeoutExpired` arm, which is exactly the
        // "nothing available" signal. Idle behavior is unchanged — a quiet link
        // still blocks up to POLL_INTERVAL and then re-checks
        // shutdown/count/duration at the top — so `--duration` and Ctrl-C stay
        // as responsive as before. A busy link now makes zero poll syscalls.
        match cap.next_packet() {
            Ok(pkt) => {
                let ts = pcap_ts_to_chrono(pkt.header.ts);
                let mut packet = Packet::new(
                    ts,
                    pkt.data.to_vec(),
                    pkt.header.caplen as usize,
                    pkt.header.len as usize,
                    interface_name.clone(),
                    link_type,
                );
                // Stamped beside the source name, because those two together
                // are what make the frame nameable, and BEFORE the send: once
                // the packet is on the channel this thread cannot amend it,
                // and a consumer inferring position from arrival order would
                // be wrong the moment the other member of a composite
                // interleaves its own packets.
                packet.origin = frames
                    .as_mut()
                    .map(crate::capture::packet::FrameCounter::next_origin);

                if tx.send(packet).is_err() {
                    tracing::debug!("Receiver dropped, stopping live capture");
                    break;
                }

                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => {
                // The ring is empty. Block here — bounded, so the loop still
                // re-checks shutdown/count/duration roughly every
                // POLL_INTERVAL on a completely idle link.
                #[cfg(unix)]
                match wait_readable(poll_fd, POLL_INTERVAL) {
                    Ok(WaitResult::Readable) | Ok(WaitResult::TimedOut) => {}
                    Err(e) => {
                        tracing::error!("poll on capture fd for '{device}' failed: {e}");
                        return Err(e).context("Fatal capture error while polling capture fd");
                    }
                }
                continue;
            }
            Err(e) => {
                tracing::error!("Capture error on '{device}': {e}");
                // pcap errors on live devices are generally fatal
                return Err(e).context("Fatal capture error");
            }
        }
    }

    // Final reading, so drops in the last STATS_INTERVAL are not lost — on a
    // short `--duration` run that window is most of the capture.
    if let Ok(stat) = cap.stats() {
        fold_stats(
            device,
            &stat,
            granted_mb,
            &mut prev_dropped,
            &mut prev_if_dropped,
        );
    }
    let (dropped, if_dropped) = kernel_drop_counts();
    if dropped > 0 || if_dropped > 0 {
        tracing::warn!(
            "Live capture on '{device}' finished: {count} packets captured, \
             but {dropped} dropped by the kernel buffer and {if_dropped} by \
             the interface — THIS ANALYSIS IS INCOMPLETE"
        );
    } else {
        tracing::info!("Live capture on '{device}' finished: {count} packets, no drops");
    }
    Ok(())
}

/// Largest capture buffer accepted, in MiB.
///
/// `pcap_set_buffer_size` takes a C `int`, so the byte count must fit in
/// `i32`: 2047 MiB is the last whole MiB that does. Anything larger is clamped
/// rather than allowed to wrap — `--buffer 2148` used to compute
/// `2_148_000_000` and hand libpcap **-2_146_967_296**, and `--buffer 5000`
/// overflowed `u32` before it even got that far.
const MAX_BUFFER_MB: u32 = 2047;

/// Convert a buffer size in MiB to the byte count libpcap wants.
///
/// Two things this gets right that the previous inline `mb * 1_000_000` did
/// not:
///
/// **The unit.** The field, the `-B` help text and the docs all say *MiB*, and
/// the old expression used decimal megabytes — so `--buffer 64` quietly asked
/// for 61.04 MiB. A multiplier of 1 MiB makes the number mean what every
/// surface says it means.
///
/// **Page alignment, for free.** A MiB multiplier makes every result a whole
/// multiple of 4 KiB, 16 KiB *and* 64 KiB pages, which matters because aarch64
/// server kernels are commonly built with 64 KiB pages: 64,000,000 is not a
/// multiple of 65,536, while 67,108,864 is exactly 1024 of them. libpcap
/// normalizes the request internally (it divides by the frame size to get
/// `tp_frame_nr`, and the kernel allocates the ring in page-multiple blocks),
/// so this is not a correctness fix — but handing the allocator a
/// page-multiple avoids rounding a slot's worth of ring away for nothing.
///
/// Saturating throughout, and clamped to [`MAX_BUFFER_MB`], so no input can
/// produce a negative or wrapped size.
fn buffer_size_bytes(mb: u32) -> i32 {
    let bytes = u64::from(effective_buffer_mb(mb)).saturating_mul(1024 * 1024);
    i32::try_from(bytes).unwrap_or(i32::MAX)
}

/// The size actually asked of libpcap for a request of `mb`.
///
/// [`buffer_ladder`] does not clamp — it starts at what the operator asked for
/// — so above [`MAX_BUFFER_MB`] the requested figure and the effective one part
/// company. Both [`buffer_size_bytes`] and the size reported to the operator go
/// through here, so the number in the message is the number libpcap was given.
/// Reporting the raw request instead would tell someone who passed
/// `--buffer 5000` that they have a 5000 MiB ring, when they have 2047.
fn effective_buffer_mb(mb: u32) -> u32 {
    mb.min(MAX_BUFFER_MB)
}

/// Capture-buffer sizes to try, largest first, starting from `requested`.
///
/// A big default ring is the right call on the busy servers sipnab is aimed at,
/// but it must not turn a working capture into a failing one on a small host:
/// allocating tens of megabytes of kernel ring can fail with `ENOMEM` on
/// memory-constrained or heavily loaded systems, and "sipnab will not start"
/// is a far worse outcome than "sipnab captures with a smaller buffer".
///
/// So the open path walks this ladder and takes the first size the kernel
/// accepts, warning when that is not the size asked for. Each step halves,
/// down to a 2 MiB floor — libpcap's own historical default, and the last size
/// worth trying before concluding the failure is not about memory at all.
///
/// A `requested` at or below the floor yields just that one entry: an operator
/// who explicitly passed `-B 1` gets 1 MiB or a hard error, not a silent
/// promotion to something larger.
fn buffer_ladder(requested: u32) -> Vec<u32> {
    /// Smallest ring worth falling back to, in MiB.
    const FLOOR_MB: u32 = 2;
    let mut sizes = vec![requested.max(1)];
    let mut mb = requested;
    while mb > FLOOR_MB {
        mb /= 2;
        sizes.push(mb.max(FLOOR_MB));
    }
    sizes.dedup();
    sizes
}

/// Packets whose pcap timestamp could not be converted and were stamped
/// with the wall clock instead. A non-zero value means capture timing
/// analysis (PDD, delta times, call duration) is unreliable for this run.
pub static INVALID_PCAP_TIMESTAMPS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Packets the kernel discarded because the capture ring buffer was full
/// when they arrived — `ps_drop` / `Stat::dropped`.
///
/// **A non-zero value means the analysis is incomplete.** Dialogs will be
/// missing messages, streams will show loss that the wire did not have, and
/// every count sipnab reports is a floor rather than a total. This is the
/// number to raise `--buffer` against.
pub static KERNEL_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Packets dropped by the interface or its driver before libpcap saw them —
/// `ps_ifdrop` / `Stat::if_dropped`.
///
/// Distinct from [`KERNEL_DROPPED`] because the remedy is different: a bigger
/// ring buffer cannot recover these. They point at the NIC, the driver, or a
/// link that is simply faster than the host can accept.
pub static IFACE_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set once the first drop is reported, so the operator is told immediately
/// and then left alone until the shutdown total.
static DROP_REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How often the capture loop asks libpcap for its drop counters.
///
/// `pcap_stats` is a syscall (a `getsockopt` on Linux), so it is polled on a
/// timer rather than per packet: at the rates this tool is benchmarked at,
/// per-packet polling would cost more than the capture.
const STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Kernel and interface drops so far, as `(kernel, interface)`.
///
/// Process-global and monotonic, summed across every capture device in a
/// `--multi-device` run.
#[must_use]
pub fn kernel_drop_counts() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (KERNEL_DROPPED.load(Relaxed), IFACE_DROPPED.load(Relaxed))
}

/// Fold one `pcap_stats` reading into the process-global drop counters.
///
/// libpcap's per-handle stats are **cumulative for the life of the handle**
/// (on Linux the kernel's `PACKET_STATISTICS` counter resets on read, and
/// libpcap accumulates it internally before returning), so this takes the
/// delta against the previous reading rather than storing the absolute value.
/// That is what makes the totals correct when several devices are capturing at
/// once: each device contributes its own increments to one shared total.
///
/// `prev_*` are updated in place to the values just read.
///
/// # Side effects
///
/// Adds to [`KERNEL_DROPPED`] / [`IFACE_DROPPED`] and, the first time either
/// goes non-zero, logs one `warn` naming the device — the operator needs to
/// know that the run is lossy while it is still running, not afterwards.
///
/// `buffer_mb` is the ring the kernel actually granted, not the one requested,
/// and the warning quotes it. It used to quote a hardcoded "default 2 MiB",
/// which was wrong from the moment [`DEFAULT_BUFFER_MB`] became 64: an operator
/// dropping packets at the default read that they were on a small buffer with
/// room to grow, when they were already 32x above the figure they were shown.
/// The size in use is both the number they need and the one that cannot drift.
fn fold_stats(
    device: &str,
    stat: &pcap::Stat,
    buffer_mb: u32,
    prev_dropped: &mut u32,
    prev_if: &mut u32,
) {
    use std::sync::atomic::Ordering::Relaxed;
    // Saturating: a handle that somehow reports a lower total than last time
    // (a driver quirk, or a counter wrap) must not underflow into a huge delta.
    let d_drop = u64::from(stat.dropped.saturating_sub(*prev_dropped));
    let d_if = u64::from(stat.if_dropped.saturating_sub(*prev_if));
    *prev_dropped = stat.dropped;
    *prev_if = stat.if_dropped;
    if d_drop == 0 && d_if == 0 {
        return;
    }
    KERNEL_DROPPED.fetch_add(d_drop, Relaxed);
    IFACE_DROPPED.fetch_add(d_if, Relaxed);
    if !DROP_REPORTED.swap(true, Relaxed) {
        tracing::warn!("{}", drop_warning(device, stat, buffer_mb));
    }
}

/// Build the first-drop warning.
///
/// Separate from [`fold_stats`] so it can be asserted on. `DROP_REPORTED` is a
/// process-global latch that fires once per run, so a test that drove the
/// warning through `fold_stats` would depend on being the first test to reach
/// it — which is to say it would pass or fail on test ordering. Returning the
/// string makes the operator-facing text checkable without touching the latch.
fn drop_warning(device: &str, stat: &pcap::Stat, buffer_mb: u32) -> String {
    format!(
        "PACKETS ARE BEING DROPPED on '{device}' (kernel buffer: {}, \
         interface/driver: {}). The analysis for this run is INCOMPLETE — \
         dialogs may be missing messages and RTP loss figures will overstate \
         what was on the wire. This run's kernel capture buffer is \
         {buffer_mb} MiB: raise it with -B/--buffer, narrow the capture with a \
         BPF filter, or reduce --snaplen. Interface drops are not fixed by a \
         bigger buffer; they point at the NIC or driver.",
        stat.dropped, stat.if_dropped,
    )
}

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
///
/// A corrupt timeval (out-of-range seconds, or microseconds outside
/// `0..1_000_000`) falls back to the current wall clock — but loudly:
/// the event is counted in [`INVALID_PCAP_TIMESTAMPS`] and warned about
/// (rate-limited), because silently substituted timestamps corrupt every
/// downstream timing computation.
pub(crate) fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    let sec = ts.tv_sec;
    let usec = ts.tv_usec;
    let converted = if (0..1_000_000).contains(&usec) {
        Utc.timestamp_opt(sec, usec as u32 * 1000).single()
    } else {
        None
    };
    converted.unwrap_or_else(|| {
        let n = INVALID_PCAP_TIMESTAMPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n == 1 || n.is_multiple_of(10_000) {
            tracing::warn!(
                "invalid pcap timestamp (tv_sec={sec}, tv_usec={usec}); \
                 stamping packet with current time ({n} occurrence(s) so far) — \
                 timing analysis for this capture is unreliable"
            );
        }
        Utc::now()
    })
}

/// Tests for live-capture support code: device-open error messages, poll
/// timeout conversion, bounded fd waits, and timestamp hardening.
#[cfg(test)]
mod fanout_plan_tests {
    use super::*;

    /// One socket is not a fanout group, and asking for zero is the same
    /// request. Both take the ordinary single-socket path — never a group of
    /// one, which costs a setsockopt and buys nothing.
    #[test]
    fn one_or_zero_sockets_capture_solo() {
        assert!(matches!(plan_fanout(0), FanoutPlan::Solo(_)));
        assert!(matches!(plan_fanout(1), FanoutPlan::Solo(_)));
    }

    /// Every "do not fan out" answer carries a reason, because it is reported
    /// to an operator who asked for N cores and is getting one. "It did not
    /// work" is not something they can act on.
    #[test]
    fn every_solo_answer_explains_itself() {
        for n in [0, 1] {
            match plan_fanout(n) {
                FanoutPlan::Solo(reason) => assert!(
                    !reason.is_empty(),
                    "a solo decision must say why, sockets={n}"
                ),
                FanoutPlan::Group(_) => panic!("{n} sockets must not form a group"),
            }
        }
    }

    /// On Linux a real request becomes a group of exactly that size; off Linux
    /// it degrades rather than failing the capture.
    #[test]
    fn a_real_request_becomes_a_group_on_linux_and_degrades_elsewhere() {
        let plan = plan_fanout(4);
        if cfg!(target_os = "linux") {
            assert_eq!(plan, FanoutPlan::Group(4));
        } else {
            assert!(
                matches!(plan, FanoutPlan::Solo(_)),
                "a platform without PACKET_FANOUT must capture, not refuse"
            );
        }
    }

    /// The group id is per-process. Two sipnab instances on one interface must
    /// not share a group, or each would receive a share of the other's traffic
    /// and both would under-report. Zero is avoided because it is also what an
    /// uninitialised value looks like.
    #[test]
    fn the_group_id_is_per_process_and_never_zero() {
        let id = fanout_group_id();
        assert_ne!(id, 0, "0 is indistinguishable from unset");
        assert_eq!(id, fanout_group_id(), "must be stable within a process");
        assert_eq!(
            id,
            std::process::id() as u16,
            "must be derived from the pid so instances do not collide"
        );
    }

    /// A lone socket numbers its frames; a socket in a fanout group does not.
    ///
    /// `capture_live_group` runs once per socket and every one of them stamps
    /// the same DEVICE NAME, so a counter per socket in a group would mint
    /// `eth0#0` from each of them — several different frames sharing one name.
    /// Following such a pointer returns bytes that are not the ones described,
    /// which is worse than following nothing and which nothing downstream can
    /// tell apart from a correct pointer. Withholding the ordinal restores the
    /// pre-stage-two behaviour for that mode, which is a MISSING answer.
    ///
    /// Both directions, because a rule that always refuses would silently undo
    /// the whole of this stage for ordinary single-socket capture.
    #[test]
    fn only_an_ungrouped_socket_numbers_its_own_frames() {
        let mut solo = frame_counter_for(None).expect("a lone socket owns its device's numbering");
        assert_eq!(solo.next_origin().ordinal, 0);
        assert_eq!(
            solo.next_origin().ordinal,
            1,
            "and it advances, or every stream would cite frame 0"
        );

        assert!(
            frame_counter_for(Some(0xA1B2)).is_none(),
            "a socket sharing a device name with its siblings must stamp \
             nothing rather than mint a second frame 0 for that device"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// A typo'd `-d <device>` used to fail with just "Failed to open device"
    /// — the auto-detect path lists the available devices, and the explicit
    /// path must too so the user can correct the name.
    #[test]
    fn open_failure_for_explicit_device_lists_available_devices() {
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let (tx, _rx) = crate::capture::channel::packet_channel(16);
        let config = crate::capture::CaptureConfig::default();
        let result = capture_live("sipnab-no-such-dev0", &config, tx, Some(ready_tx));
        assert!(result.is_err(), "nonexistent device must fail");
        let err = ready_rx
            .try_recv()
            .expect("ready channel must carry the error")
            .expect_err("must be Err");
        assert!(
            err.contains("sipnab-no-such-dev0"),
            "names the device: {err}"
        );
        // Permission-flavored failures intentionally skip the device list
        // (the bootstrap shows its own --setup-caps hint instead). On macOS
        // an unprivileged open of a bogus device fails with exactly such an
        // error, so mirror the production predicate here.
        let is_permission = err.contains("ermission")
            || err.contains("EPERM")
            || err.contains("Operation not permitted");
        if !is_permission && !crate::capture::device::list_devices().is_empty() {
            assert!(
                err.contains("Available devices:"),
                "must list the real devices so the typo is correctable: {err}"
            );
        }
    }

    /// The exact strings libpcap emits must classify as permission failures,
    /// so the caller reaches the `--setup-caps` hint rather than the device
    /// list.
    ///
    /// The first case is a real report from a CentOS 9 host: it named
    /// CAP_NET_RAW and still missed every clause of the old predicate.
    #[test]
    fn libpcap_privilege_messages_are_recognised_as_permission_failures() {
        for msg in [
            "Attempt to create packet socket failed - CAP_NET_RAW may be required",
            "socket: Operation not permitted",
            "You don't have permission to capture on that device",
            "(socket: Operation not permitted)",
        ] {
            assert!(
                is_permission_error(msg),
                "libpcap privilege failure not recognized, so the user is shown \
                 the device list instead of how to grant CAP_NET_RAW: {msg:?}"
            );
        }
    }

    /// A genuine typo must NOT be swallowed by the permission branch, or the
    /// device list that makes it correctable never prints.
    #[test]
    fn a_missing_device_is_not_mistaken_for_a_permission_failure() {
        for msg in [
            "No such device exists",
            "Failed to open device 'eth42'",
            "SIOCETHTOOL(ETHTOOL_GET_TS_INFO) ioctl failed: No such device",
        ] {
            assert!(
                !is_permission_error(msg),
                "a missing device was classified as a permission failure, which \
                 suppresses the device list: {msg:?}"
            );
        }
    }

    /// Build a `libc::timeval` from `sec`/`usec` (casting to the target's
    /// field widths).
    fn tv(sec: i64, usec: i64) -> libc::timeval {
        libc::timeval {
            tv_sec: sec as _,
            tv_usec: usec as _,
        }
    }

    // ── Read timeout vs immediate mode (CT7) ─────────────────────────────
    // The device open cannot be exercised here (no root, no NIC), so what is
    // pinned is the configuration decision: which timeout each ring format
    // gets, and that the batched one stays small enough that TPACKET_V3's
    // block-retire timer is not a latency regression.

    /// Immediate mode keeps the long-standing 100 ms read bound. On
    /// TPACKET_V2 this is only how long libpcap waits inside one read, and
    /// immediate delivery means it rarely waits at all.
    #[test]
    fn immediate_mode_keeps_the_hundred_millisecond_read_timeout() {
        assert_eq!(read_timeout_ms(true), 100);
    }

    /// Turning immediate mode off selects TPACKET_V3, where libpcap passes the
    /// read timeout to the kernel as `tp_retire_blk_tov`. Reusing 100 ms there
    /// would delay every packet on a link too quiet to fill a block by up to
    /// 100 ms — the regression this shorter value exists to prevent.
    #[test]
    fn batched_mode_uses_a_short_block_retire_timeout() {
        let batched = read_timeout_ms(false);
        assert!(
            batched < read_timeout_ms(true),
            "the V3 block-retire timer must be shorter than the V2 read bound"
        );
        assert!(
            (1..=10).contains(&batched),
            "a block-retire timer of {batched} ms is either a latency \
             regression (too long) or pointless churn (0 = retire only when \
             full)"
        );
    }

    /// The batched retire timer must stay well inside the interval the idle
    /// loop already blocks for, so choosing TPACKET_V3 can never be the thing
    /// that makes a capture feel slow.
    #[cfg(unix)]
    #[test]
    fn batched_timeout_is_far_below_the_idle_poll_interval() {
        let batched = u128::try_from(read_timeout_ms(false)).expect("non-negative timeout");
        assert!(
            batched * 10 <= POLL_INTERVAL.as_millis(),
            "block-retire timer {batched} ms is not an order of magnitude \
             below the {} ms idle poll",
            POLL_INTERVAL.as_millis()
        );
    }

    /// A non-positive timeout is never produced. Zero would mean "retire a V3
    /// block only when it is full", which on a quiet link holds packets
    /// indefinitely; negative is not a timeout at all.
    #[test]
    fn read_timeout_is_always_positive() {
        for immediate in [true, false] {
            assert!(
                read_timeout_ms(immediate) > 0,
                "immediate={immediate} produced a non-positive read timeout"
            );
        }
    }

    // ── poll_timeout_millis: overflow-safe Duration → c_int conversion ────
    /// Tests that the Duration → `poll(2)` millisecond conversion clamps
    /// instead of wrapping negative.
    #[cfg(unix)]
    mod poll_timeout {
        use super::*;
        use std::time::Duration;

        /// A zero duration converts to a zero timeout.
        #[test]
        fn zero_duration_is_zero() {
            assert_eq!(poll_timeout_millis(Duration::ZERO), 0);
        }

        /// An in-range duration converts to its exact millisecond count.
        #[test]
        fn normal_duration_converts_exactly() {
            assert_eq!(poll_timeout_millis(Duration::from_millis(100)), 100);
        }

        /// Exactly `c_int::MAX` milliseconds passes through unclamped.
        #[test]
        fn boundary_at_int_max_is_preserved() {
            let max = libc::c_int::MAX;
            assert_eq!(poll_timeout_millis(Duration::from_millis(max as u64)), max);
        }

        /// A huge duration clamps to `c_int::MAX`, never wrapping negative
        /// ("block forever" in poll(2)).
        #[test]
        fn overflowing_duration_clamps_not_wraps() {
            // A huge duration must clamp to c_int::MAX, never wrap to a small or
            // negative value (negative = "block forever" in poll(2) — the bug).
            let huge = Duration::from_millis(u64::MAX);
            assert_eq!(poll_timeout_millis(huge), libc::c_int::MAX);
            assert!(poll_timeout_millis(huge) > 0);
        }

        /// One millisecond past `c_int::MAX` clamps to `c_int::MAX`.
        #[test]
        fn one_past_int_max_clamps() {
            let over = Duration::from_millis(libc::c_int::MAX as u64 + 1);
            assert_eq!(poll_timeout_millis(over), libc::c_int::MAX);
        }
    }

    // ── wait_readable: a BOUNDED wait that returns even with no data ──────
    // This is the property the idle capture loop lacked, which let --duration
    // hang. Tested deterministically with a pipe — no capture privileges.
    /// Deterministic `wait_readable` tests using a pipe — no capture
    /// privileges required.
    #[cfg(unix)]
    mod wait_readable_tests {
        use super::*;
        use std::os::unix::io::RawFd;
        use std::time::{Duration, Instant};

        /// Create a pipe via `pipe(2)` and return `(read_fd, write_fd)`.
        fn make_pipe() -> (RawFd, RawFd) {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a valid 2-element array; `pipe` writes both.
            let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(r, 0, "pipe(2) failed: {}", std::io::Error::last_os_error());
            (fds[0], fds[1])
        }

        /// Close a pipe fd from `make_pipe` (exactly once).
        fn close(fd: RawFd) {
            // SAFETY: `fd` came from `make_pipe` and is closed exactly once.
            unsafe { libc::close(fd) };
        }

        /// An idle fd yields `TimedOut` within roughly the timeout — the
        /// bounded-wait property the old loop lacked.
        #[test]
        fn times_out_on_idle_fd() {
            // The regression test: nothing is ever written, yet the wait MUST
            // return (TimedOut) within roughly the timeout — not block forever.
            let (r, w) = make_pipe();
            let start = Instant::now();
            let res = wait_readable(r, Duration::from_millis(80)).expect("poll ok");
            let elapsed = start.elapsed();
            assert_eq!(res, WaitResult::TimedOut);
            assert!(
                elapsed >= Duration::from_millis(40),
                "returned too early: {elapsed:?}"
            );
            assert!(
                elapsed < Duration::from_secs(3),
                "did not return promptly: {elapsed:?}"
            );
            close(r);
            close(w);
        }

        /// With data already queued, the wait returns `Readable` promptly.
        #[test]
        fn returns_readable_when_data_present() {
            let (r, w) = make_pipe();
            // SAFETY: `w` is a live pipe fd and the buffer is 1 valid byte.
            let n = unsafe { libc::write(w, b"x".as_ptr() as *const libc::c_void, 1) };
            assert_eq!(n, 1, "write failed");
            let start = Instant::now();
            // Generous timeout: must come back fast because data is ready.
            let res = wait_readable(r, Duration::from_secs(5)).expect("poll ok");
            assert_eq!(res, WaitResult::Readable);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "should return immediately when readable"
            );
            close(r);
            close(w);
        }

        /// A zero timeout on an idle fd returns `TimedOut` immediately.
        #[test]
        fn zero_timeout_returns_immediately() {
            let (r, w) = make_pipe();
            let start = Instant::now();
            let res = wait_readable(r, Duration::ZERO).expect("poll ok");
            assert_eq!(res, WaitResult::TimedOut);
            assert!(start.elapsed() < Duration::from_millis(500));
            close(r);
            close(w);
        }

        /// A closed fd (POLLNVAL) surfaces as an error, never a spurious
        /// `Readable` that would hot-spin the capture loop.
        #[test]
        fn invalid_fd_is_an_error_not_a_spin() {
            // Adversarial: a closed fd yields POLLNVAL. wait_readable must
            // surface an error (fatal) rather than report Readable, which —
            // paired with a no-op next_packet — would hot-spin forever.
            //
            // The fd table is process-global, so a bare close(r) + poll(r)
            // races other parallel tests that can recycle the freed number
            // into a live pipe (making the poll succeed). Retry with fresh
            // pipes until one poll lands on a genuinely-closed fd: a correct
            // wait_readable errors on the first non-recycled attempt, while
            // a broken one that always reports Readable exhausts every try
            // and fails. A false pass would need hundreds of consecutive
            // recycle wins — astronomically unlikely.
            let mut saw_error = false;
            for _ in 0..512 {
                let (r, w) = make_pipe();
                close(r);
                let res = wait_readable(r, Duration::from_millis(5));
                close(w);
                if res.is_err() {
                    saw_error = true;
                    break;
                }
            }
            assert!(
                saw_error,
                "a closed fd must error (POLLNVAL); wait_readable never did"
            );
        }
    }

    /// An in-range timeval converts to the exact seconds + microseconds.
    #[test]
    fn valid_timestamp_converts_exactly() {
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, 123_456));
        assert_eq!(dt.timestamp(), 1_700_000_000);
        assert_eq!(dt.timestamp_subsec_micros(), 123_456);
    }

    /// `tv_usec = 999_999` is the last valid value and converts exactly.
    #[test]
    fn usec_boundary_999_999_is_valid() {
        let dt = pcap_ts_to_chrono(tv(0, 999_999));
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_micros(), 999_999);
    }

    /// `tv_sec = 0` is a real epoch timestamp, not an error fallback.
    #[test]
    fn zero_timestamp_is_valid_epoch() {
        // A pcap with tv_sec = 0 is a real (if odd) timestamp, not an error:
        // it must convert to the epoch, not fall back to "now".
        let dt = pcap_ts_to_chrono(tv(0, 0));
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_micros(), 0);
    }

    /// A negative `tv_usec` falls back to "now" without panicking and bumps
    /// the invalid-timestamp counter.
    #[test]
    #[serial_test::serial(invalid_timestamps)]
    fn negative_usec_does_not_panic_and_is_counted() {
        // Corrupted tv_usec: `as u32` wraps -1 to u32::MAX, and the old
        // `* 1000` overflowed (panic in debug builds). Must instead fall
        // back cleanly and count the event.
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, -1));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        // Fallback stamps with "now" (within a generous window).
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }

    /// `tv_usec >= 1_000_000` is corrupt: falls back to "now" and counts.
    #[test]
    #[serial_test::serial(invalid_timestamps)]
    fn oversized_usec_falls_back_and_is_counted() {
        // tv_usec must be < 1_000_000; 5_000_000 is corrupt.
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, 5_000_000));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }

    /// An unrepresentable `tv_sec` (i64::MAX) falls back to "now" and
    /// counts.
    #[test]
    #[serial_test::serial(invalid_timestamps)]
    fn out_of_range_sec_falls_back_and_is_counted() {
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(i64::MAX, 0));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }

    // ── Buffer size conversion (MiB, page-aligned, overflow-safe) ────────

    /// The multiplier is MiB, not decimal MB. Every surface — the field name,
    /// the `-B` help text, `docs/cli-reference.md` — says MiB, and the old
    /// `mb * 1_000_000` quietly delivered 61.04 MiB for `--buffer 64`.
    #[test]
    fn buffer_size_uses_mebibytes_not_megabytes() {
        assert_eq!(buffer_size_bytes(64), 64 * 1024 * 1024);
        assert_eq!(buffer_size_bytes(1), 1_048_576);
        assert_ne!(
            buffer_size_bytes(64),
            64_000_000,
            "decimal MB is the bug this test exists to prevent"
        );
    }

    /// Every accepted size is a whole multiple of 4 KiB, 16 KiB and 64 KiB
    /// pages. 64 KiB matters specifically: aarch64 server kernels are commonly
    /// built with 64 KiB pages, and 64,000,000 is not a multiple of 65,536.
    #[test]
    fn buffer_size_is_page_aligned_for_every_common_page_size() {
        for mb in [1u32, 2, 8, 64, 256, MAX_BUFFER_MB] {
            let bytes = buffer_size_bytes(mb) as u32;
            for page in [4096u32, 16384, 65536] {
                assert_eq!(
                    bytes % page,
                    0,
                    "{mb} MiB = {bytes} B is not a multiple of a {page} B page"
                );
            }
        }
    }

    /// A size past the `int` ceiling must clamp, never wrap. `--buffer 2148`
    /// used to hand libpcap -2_146_967_296, and `--buffer 5000` overflowed
    /// `u32` before the cast even happened.
    #[test]
    fn buffer_size_clamps_instead_of_wrapping_negative() {
        for mb in [2048u32, 2148, 4000, 5000, 100_000, u32::MAX] {
            let bytes = buffer_size_bytes(mb);
            assert!(
                bytes > 0,
                "--buffer {mb} produced {bytes}; a non-positive buffer size is \
                 the overflow bug"
            );
            assert!(
                bytes <= MAX_BUFFER_MB as i32 * 1024 * 1024,
                "--buffer {mb} produced {bytes}, above the clamp"
            );
        }
        assert_eq!(
            buffer_size_bytes(u32::MAX),
            MAX_BUFFER_MB as i32 * 1024 * 1024
        );
    }

    // ── Capture-buffer fallback ladder (CT2) ─────────────────────────────

    /// The ladder starts at what was asked for. Anything else silently
    /// capturing with a different ring than the operator requested is the
    /// defect this whole path exists to avoid.
    #[test]
    fn buffer_ladder_tries_the_requested_size_first() {
        assert_eq!(buffer_ladder(64)[0], 64);
        assert_eq!(buffer_ladder(256)[0], 256);
    }

    /// Each step halves and the ladder bottoms out at the 2 MiB floor, so a
    /// host that cannot give us 64 MiB still captures rather than failing.
    #[test]
    fn buffer_ladder_halves_down_to_the_floor() {
        assert_eq!(buffer_ladder(64), vec![64, 32, 16, 8, 4, 2]);
    }

    /// An explicit small request is honored exactly — never promoted upward,
    /// and never given extra fallback steps it did not ask for. An operator
    /// who passes `-B 1` on a tiny box means it.
    #[test]
    fn buffer_ladder_never_promotes_an_explicit_small_request() {
        assert_eq!(buffer_ladder(1), vec![1]);
        assert_eq!(buffer_ladder(2), vec![2]);
    }

    /// The ladder always terminates and never yields a zero-size ring — a
    /// `buffer_size(0)` would be a nonsense argument to libpcap.
    #[test]
    fn buffer_ladder_always_terminates_above_zero() {
        for mb in [0u32, 1, 3, 5, 7, 100, 1024, u32::MAX] {
            let ladder = buffer_ladder(mb);
            assert!(!ladder.is_empty(), "ladder for {mb} must not be empty");
            assert!(
                ladder.len() < 64,
                "ladder for {mb} must terminate, got {} entries",
                ladder.len()
            );
            assert!(
                ladder.iter().all(|&m| m > 0),
                "ladder for {mb} yielded a zero-size buffer: {ladder:?}"
            );
        }
    }

    // ── Kernel drop accounting (CT1) ─────────────────────────────────────

    /// Build a `pcap::Stat`. The struct's fields are public but its
    /// constructor is not, so tests transmute-free by going through the
    /// public field syntax the crate exposes.
    fn stat(received: u32, dropped: u32, if_dropped: u32) -> pcap::Stat {
        pcap::Stat {
            received,
            dropped,
            if_dropped,
        }
    }

    /// libpcap reports CUMULATIVE per-handle totals, so folding must add the
    /// DELTA. Two successive readings of 10 then 25 are 25 drops in total, not
    /// 35 — getting this wrong double-counts every poll for the life of the
    /// run, which would turn a healthy capture into a permanent red warning.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn fold_stats_accumulates_deltas_not_absolute_totals() {
        let before = KERNEL_DROPPED.load(Ordering::Relaxed);
        let (mut prev_d, mut prev_i) = (0u32, 0u32);

        fold_stats("test0", &stat(100, 10, 0), 64, &mut prev_d, &mut prev_i);
        fold_stats("test0", &stat(200, 25, 0), 64, &mut prev_d, &mut prev_i);

        let observed = KERNEL_DROPPED.load(Ordering::Relaxed) - before;
        assert_eq!(
            observed, 25,
            "two cumulative readings of 10 then 25 are 25 drops, not 35"
        );
        assert_eq!(prev_d, 25, "previous reading must advance to the latest");
    }

    /// A reading that goes BACKWARDS (counter wrap, or a driver that resets
    /// its own stats) must not underflow into a ~4-billion-drop delta.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn fold_stats_saturates_on_a_backwards_counter() {
        let before = KERNEL_DROPPED.load(Ordering::Relaxed);
        let (mut prev_d, mut prev_i) = (500u32, 0u32);

        fold_stats("test1", &stat(10, 3, 0), 64, &mut prev_d, &mut prev_i);

        let observed = KERNEL_DROPPED.load(Ordering::Relaxed) - before;
        assert_eq!(
            observed, 0,
            "a backwards counter must contribute 0, not underflow"
        );
        assert_eq!(prev_d, 3, "previous reading still resyncs to the new value");
    }

    /// Interface drops are tracked separately from ring-buffer drops, because
    /// the remedy differs: `-B/--buffer` fixes the first and cannot fix the
    /// second.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn fold_stats_separates_interface_drops_from_buffer_drops() {
        let before_kernel = KERNEL_DROPPED.load(Ordering::Relaxed);
        let before_iface = IFACE_DROPPED.load(Ordering::Relaxed);
        let (mut prev_d, mut prev_i) = (0u32, 0u32);

        fold_stats("test2", &stat(1000, 0, 7), 64, &mut prev_d, &mut prev_i);

        assert_eq!(
            KERNEL_DROPPED.load(Ordering::Relaxed) - before_kernel,
            0,
            "an interface drop is not a kernel-buffer drop"
        );
        assert_eq!(
            IFACE_DROPPED.load(Ordering::Relaxed) - before_iface,
            7,
            "interface drops must be counted in their own total"
        );
    }

    /// A clean poll (nothing dropped) must not touch the totals at all — a
    /// healthy capture polls this once a second for its whole life.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn fold_stats_is_a_no_op_when_nothing_dropped() {
        let before = kernel_drop_counts();
        let (mut prev_d, mut prev_i) = (4u32, 9u32);

        fold_stats("test3", &stat(5000, 4, 9), 64, &mut prev_d, &mut prev_i);

        assert_eq!(
            kernel_drop_counts(),
            before,
            "an unchanged reading must not move either counter"
        );
    }

    /// The drop warning must quote the buffer THIS run got, not a constant.
    ///
    /// It used to read "(default 2 MiB)", hardcoded, and stayed that way when
    /// `DEFAULT_BUFFER_MB` became 64. An operator dropping packets at the
    /// default was told they were on 2 MiB — so the obvious remedy, "raise the
    /// buffer", looked untried when they were already 32x above the figure in
    /// front of them. The number in the message is the one they act on, so it
    /// has to come from the run.
    #[test]
    fn the_drop_warning_quotes_the_buffer_this_run_actually_got() {
        let msg = drop_warning("eth0", &stat(1000, 12, 3), 64);
        assert!(
            msg.contains("kernel capture buffer is 64 MiB"),
            "the operator needs the size in use, got: {msg}"
        );

        // A ladder step-down is exactly when the requested size and the real
        // one differ, and exactly when quoting the wrong one misleads most.
        let stepped = drop_warning("eth0", &stat(1000, 12, 3), 8);
        assert!(
            stepped.contains("kernel capture buffer is 8 MiB"),
            "after a ladder step-down the granted size is what matters: {stepped}"
        );

        assert!(
            !msg.contains("default 2 MiB"),
            "no hardcoded default: that is the claim that went stale, {msg}"
        );
        assert!(
            msg.contains("(kernel buffer: 12, interface/driver: 3)"),
            "both drop counts stay separate in the text: {msg}"
        );
    }

    /// Above the ceiling, the reported size must be the one libpcap got.
    ///
    /// `buffer_ladder` deliberately does not clamp — it starts at what was
    /// asked for — so the requested and effective sizes diverge past
    /// `MAX_BUFFER_MB`. Reporting the request would tell someone who passed
    /// `--buffer 5000` that they have a 5000 MiB ring while `buffer_size_bytes`
    /// handed the kernel 2047 MiB, and they would go looking for the drops
    /// anywhere but the buffer.
    #[test]
    fn an_over_ceiling_request_reports_the_clamped_size_not_the_request() {
        assert_eq!(
            effective_buffer_mb(5000),
            MAX_BUFFER_MB,
            "past the C-int ceiling the effective size is the clamp"
        );
        assert_eq!(
            effective_buffer_mb(64),
            64,
            "an ordinary size passes through untouched"
        );
        // The reported figure and the bytes libpcap receives must agree.
        assert_eq!(
            buffer_size_bytes(5000),
            (MAX_BUFFER_MB as i32) * 1024 * 1024,
            "the clamp the message quotes is the clamp the bytes went through"
        );

        let msg = drop_warning("eth0", &stat(1, 1, 0), effective_buffer_mb(5000));
        assert!(
            msg.contains(&format!("kernel capture buffer is {MAX_BUFFER_MB} MiB")),
            "the operator must see the ring they have, not the one they asked \
             for: {msg}"
        );
    }

    /// Whatever the default becomes, the warning must never state a different
    /// one. This is the assertion the old text would have failed the moment
    /// `DEFAULT_BUFFER_MB` moved off 2.
    #[test]
    fn the_drop_warning_never_states_a_default_that_can_drift() {
        let msg = drop_warning("eth0", &stat(1, 1, 0), crate::capture::DEFAULT_BUFFER_MB);
        assert!(
            msg.contains(&format!(
                "kernel capture buffer is {} MiB",
                crate::capture::DEFAULT_BUFFER_MB
            )),
            "a default-buffer run must report the default it truly has: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("default"),
            "the message must quote the live value, never name a default: {msg}"
        );
    }
}
