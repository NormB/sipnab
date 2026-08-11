# Capture performance roadmap — lower-level packet capture

Future-work TODO for improving packet-capture throughput / loss on highly loaded
systems. This is a **research roadmap, not committed work**. Phases are ordered
cheapest-first; each later phase has an explicit trigger condition so we only pay
the complexity when the previous phase proves insufficient.

## Current state (baseline)

sipnab captures via **libpcap** (the `pcap` crate). Live loop in
`capture_live()` ([`src/capture/live.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs)). Symbols rather than line numbers
throughout this page: the ranges it used to cite had all rotted by the time the
work below landed, and a citation that silently points at the wrong code is
worse than none.

- `immediate_mode` is **run-mode-dependent** (`immediate_mode_for()` in
  [`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs)): on for the TUI, off for every headless run, which is
  what decides TPACKET_V2 versus V3. It was unconditionally `true` when this
  page was written.
- A kernel **BPF filter** is applied when provided (`capture_live()` in
  [`src/capture/live.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs)) — the only in-kernel optimization currently in use.
- Default kernel buffer **64 MiB** (`DEFAULT_BUFFER_MB` in
  [`src/capture/native.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs), `-B`/`--buffer`), with a halving fallback ladder to a
  2 MiB floor. It was 2 MiB when this page was written.
- `poll(2)` on the **ring-empty path only**. It used to run before every packet,
  including when the mmap'd ring already had data.

**Where loss happens under load (not the NIC — the pipeline):**

1. **Channel backpressure (primary):** capture→processing was a
   `crossbeam_channel::bounded(10_000)`. When processing (TUI render, RTP
   analysis, audio export) lagged, the queue filled and `tx.send` stalled the
   capture thread → kernel drops; ~10k RTP pps filled it in ~1 s, bursts far
   faster. Now an auto-grow capped queue ([`src/capture/channel.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs)) — see the
   Phase 1 entry below for what replaced it.
2. **Per-packet allocation:** every packet does `pkt.data.to_vec()`
   (in `capture_live()`, into `Packet::new`) — heap alloc + memcpy per packet.
   Still open.
3. **Buffer size:** the 2 MiB default filled in ~10 ms at a few hundred Mbps of
   media. Addressed — see the baseline bullet above and the Phase 1 entry below.
4. **No kernel acceleration beyond libpcap defaults** (typically TPACKET_V2);
   no AF_PACKET ring, AF_XDP, or XDP/eBPF prefilter.

**Workload note:** SIP signaling is low-PPS and must be lossless; RTP media is
high-PPS and can tolerate sampling. The dominant cost is the *processing
pipeline*, not raw I/O — so in-kernel filtering/sampling (deliver only SIP +
selected RTP) is often a bigger win than faster raw capture.

---

## Phase 1 — libpcap / pipeline tuning  ·  ~1–2 days  ·  portable  ·  do first

Low risk, no backend change, helps every platform. Expected ~20–30% throughput
and a large cut in pipeline-induced drops.

- [x] **Done:** default kernel buffer raised 2 MiB → 64 MiB
      (`DEFAULT_BUFFER_MB` in [`src/capture/native.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs)). The open walks a ladder
      that halves to a 2 MiB floor, so a host that cannot give 64 MiB still
      captures rather than failing to start, and says which size it got.
      `-B/--buffer` is a MiB multiplier on saturating arithmetic clamped to
      `MAX_BUFFER_MB` (2047, the last whole MiB that fits a positive C `int`);
      it was decimal-megabyte arithmetic that handed libpcap a negative size
      above 2047. `pcap_stats` drops are polled on a timer and surfaced.
      See [`docs/tuning-capture.md`](https://github.com/NormB/sipnab/blob/main/docs/tuning-capture.md) for the gigabit-media sizing guidance.
- [x] **Done:** the capture→processing channel is now an auto-grow, capped queue
      ([`src/capture/channel.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs)) — unbounded storage (frees segments when idle) +
      a `bounded(capacity)` semaphore for backpressure. Capacity derives from
      `[capture] buffer_budget_mb` / `--buffer-budget` (default 64 MiB);
      `sipnab_capture_queue_depth_packets` / `_backpressure_blocks_total` exported.
      **On the standalone `--metrics` server only** — which is no longer
      TUI-only: `servers::start_servers` starts it for headless runs too, and
      batch hands it a real `CaptureMeter`, so `--metrics` reads live. The
      `--api` route's `get_metrics` fills no `CaptureMeter`, so a headless run
      scraping `--api` reads both series as a hard `0` regardless of what the
      queue is doing; neither may be quoted as a reading from that route. See
      [`bench/README.md`](https://github.com/NormB/sipnab/blob/main/bench/README.md) for the line numbers this page deliberately omits.
- [ ] Buffer pool to eliminate per-packet `to_vec()` (in `capture_live()`) —
      recycle fixed buffers instead of allocating per packet.
- [ ] Stronger default auto-BPF filter when none supplied (push more drops into
      the kernel; e.g. SIP ports + configured RTP ranges).
- [ ] Investigate whether the `pcap` crate v2 exposes **TPACKET_V3**
      (`pcap_set_protocol`); if so add `--capture-mode auto|tpacket_v3|tpacket_v2`.
- [ ] Benchmark harness — **the harness exists; nothing has been measured with
      it.** [`bench/live-capture.sh`](https://github.com/NormB/sipnab/blob/main/bench/live-capture.sh) replays a synthetic sustained-RTP corpus
      (generated by [`bench/carrier.py`](https://github.com/NormB/sipnab/blob/main/bench/carrier.py); the script accepts no capture path at
      all, so a real capture cannot be fed to it) through a `veth` pair in a
      private `sipnab-bench` network namespace, and reads sipnab's own
      `sipnab_capture_packets_total`, `_kernel_dropped_packets_total`,
      `_interface_dropped_packets_total`, `_invalid_timestamps_total` and
      `_quality_degraded` off the `--api` route, alongside per-process CPU and
      peak RSS for sipnab and for the replayer separately. The box stays
      unticked until a run produces a clean row. **Everything on this page and
      in [`docs/design/capture-tuning-tasks.md`](https://github.com/NormB/sipnab/blob/main/docs/design/capture-tuning-tasks.md) is still reasoned, not
      measured.**
      - **Correction to the original acceptance criterion.** It said to measure
        `ethtool -S <iface> | grep rx_dropped`. That is unsatisfiable on the
        harness interface: `ethtool -i` reports `driver: veth`, and
        `ethtool -S | grep -c rx_dropped` returns `0` — the driver exposes no
        such counter. Of the 22 statistics a single-queue `veth` does expose,
        the only two named for a drop are `rx_queue_0_drops` and
        `rx_queue_0_xdp_drops`, and the second counts XDP verdicts, which is a
        program this harness never loads. The harness therefore reads
        `rx_queue_0_drops` (summed over the queues, since veth queue count is
        settable at creation), the `/sys/class/net/<iface>/statistics/rx_*`
        deltas, and `/proc/net/softnet_stat` labelled system-wide because it is.
      - **A veth number is not a physical-NIC number, and must never be quoted
        as one.** There is no hardware ring, no NAPI budget tuned by a driver,
        no interrupt coalescing, no RSS across queues, and no checksum or
        segmentation offload doing work — a `veth` transmit is a software
        enqueue onto the peer's backlog. What this harness can measure is the
        path from the kernel's ring to sipnab's counters: buffer sizing, ring
        format, poll behaviour, channel backpressure. What it cannot measure is
        anything a NIC and its driver contribute, which on a real gigabit link
        is where a good share of the loss lives.

## Phase 2 — AF_PACKET + TPACKET_V3 ring  ·  ~3–5 days  ·  Linux-only

**Trigger:** Phase 1 still shows >5% loss on sustained ~1 Gbps RTP.
Expected +40–60% throughput, ~30% lower latency; zero-copy within the ring.

**The Phase 1 harness straddles this trigger; it cannot hit it.** `carrier.py`
paces media by integer division of a 20 ms packet time, so the aggregate rate is
exact only at rungs that divide evenly — the two either side of a gigabit are
500,000 pps (≈856 Mbps of 214-byte frames) and 1,000,000 pps (≈1.712 Gbps).
1 Gbps would need a rung that does not exist. Whatever the harness eventually
reports, no row may be described as "1 Gbps", "passed at 1 Gbps" or "clean at
1 Gbps": the trigger above is worded in a rate the ladder straddles rather than
offers, and deciding it either way means saying which rung was actually run.

- [ ] New `src/capture/af_packet.rs`: `AF_PACKET`/`SOCK_RAW` + `PACKET_RX_RING`
      (PACKET_MMAP), TPACKET_V3 block handling; `SO_ATTACH_FILTER` for the BPF.
- [ ] `--capture-backend libpcap|af_packet`; reuse `CaptureConfig` + the channel;
      keep libpcap as the macOS/BSD fallback.
- [ ] Pre-allocated buffer pool on the copy-out path.
- [ ] Requires `CAP_NET_RAW`; Linux 3.2+. Custom `libc` bindings (no off-the-shelf
      TPACKET_V3 crate). Careful mmap/error-recovery handling + tests.

## Phase 3 — eBPF / XDP in-kernel filter + sample  ·  ~10–20 days  ·  Linux-only

**Trigger:** media volume so high the pipeline saturates even with raw capture
optimized, and RTP sampling (keep 1-in-N) is acceptable. Expected 50–90%
userspace CPU reduction; wire-rate capture feasible.

- [ ] XDP program (Rust via **`aya`**) parsing UDP + SIP/RTP heuristics; `XDP_DROP`
      non-matching; forward SIP via `bpf_ringbuf_output`; sample RTP 1-in-N.
- [ ] Userspace ring-buffer reader feeding the existing channel; behind a
      `--features xdp` flag.
- [ ] Requires `CAP_BPF`+`CAP_PERFMON`, Linux 5.8+ (ringbuf), clang/bpftool build
      toolchain, CO-RE. Main risks: verifier limits, kernel-version compatibility,
      correlating sampled RTP back to calls.
- [ ] Rust eBPF ecosystem: `aya` (pure-Rust, mature), `libbpf-rs` (libbpf
      bindings, mature); avoid `redbpf` (unmaintained).

## Phase 4 — AF_XDP (XSK)  ·  ~15–25 days  ·  likely NOT needed

**Trigger:** capturing 10+ Gbps with call-grade analysis (rare for SIP/RTP).
~10x I/O throughput, sub-ms latency, true zero-copy.

- [ ] XDP redirect program + AF_XDP socket (UMEM/RX rings) via `aya` + `afxdp`/
      `xsk-rs`. Linux 4.18+ (5.8+ for full features), `CAP_BPF`, NIC/driver XDP
      support; incompatible with the `any` pseudo-device.
- [ ] **Assessment:** skip unless benchmarks prove raw *capture* (not processing)
      is the bottleneck and Phase 3 sampling isn't enough. SIP is never 10 Gbps;
      RTP analysis is CPU-bound.

## Not recommended — PF_RING / DPDK

Wrong fit: require driver binding (UIO) / kernel patches, dedicate the NIC away
from normal networking, and target wire-rate forwarding rather than on-box
SIP/RTP analysis. Note for completeness only.

---

## References

- Linux AF_XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
- TPACKET_V3 (PACKET_MMAP): https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
- `aya` (Rust eBPF): https://github.com/aya-rs/aya
- `libbpf-rs`: https://github.com/libbpf/libbpf-rs
- `afxdp-rs`: https://github.com/redhat-et/afxdp-rs · `xsk-rs`: https://github.com/alessandrococco/xsk-rs
- libpcap (TPACKET_V3 support since 1.10): https://github.com/the-tcpdump-group/libpcap
