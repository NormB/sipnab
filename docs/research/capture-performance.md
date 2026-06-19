# Capture performance roadmap — lower-level packet capture

Future-work TODO for improving packet-capture throughput / loss on highly loaded
systems. This is a **research roadmap, not committed work**. Phases are ordered
cheapest-first; each later phase has an explicit trigger condition so we only pay
the complexity when the previous phase proves insufficient.

## Current state (baseline)

sipnab captures via **libpcap** (the `pcap` crate). Live loop in
`src/capture/live.rs:99-249`:

- `immediate_mode(true)` is set (`live.rs:120`) — packets delivered without extra
  libpcap buffering latency.
- A kernel **BPF filter** is applied when provided (`live.rs:133-141`) — the only
  in-kernel optimization currently in use.
- Default kernel buffer **2 MiB** (`src/capture/mod.rs:84-97`, `--buffer-mb`).
- `poll(2)` with a 100 ms interval (`live.rs:25,183-245`), then `next_packet()`.

**Where loss happens under load (not the NIC — the pipeline):**

1. **Channel backpressure (primary):** capture→processing is a
   `crossbeam_channel::bounded(10_000)` (`src/main.rs:428`). When processing
   (TUI render, RTP analysis, audio export) lags, the queue fills and
   `tx.send` stalls the capture thread → kernel drops. ~10k RTP pps fills it in
   ~1 s; bursts fill it far faster.
2. **Per-packet allocation:** every packet does `pkt.data.to_vec()`
   (`live.rs:221`, `src/capture/packet.rs:39-42`) — heap alloc + memcpy per packet.
3. **Buffer size:** 2 MiB default fills in ~10 ms at a few hundred Mbps of media.
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

- [ ] Raise default kernel buffer 2 MiB → 64 MiB (`--buffer-mb` default in
      `src/capture/mod.rs`); document a 128 MiB recommendation for gigabit media.
- [ ] Raise the capture→processing channel 10_000 → 100_000 (`src/main.rs:428`),
      and/or make it configurable.
- [ ] Buffer pool to eliminate per-packet `to_vec()` (`live.rs:221`) — recycle
      fixed buffers instead of allocating per packet.
- [ ] Stronger default auto-BPF filter when none supplied (push more drops into
      the kernel; e.g. SIP ports + configured RTP ranges).
- [ ] Investigate whether the `pcap` crate v2 exposes **TPACKET_V3**
      (`pcap_set_protocol`); if so add `--capture-mode auto|tpacket_v3|tpacket_v2`.
- [ ] Benchmark harness: replay a 100+ call sustained-RTP capture; measure
      `ethtool -S <iface> | grep rx_dropped`, CPU, RSS; record a baseline.

## Phase 2 — AF_PACKET + TPACKET_V3 ring  ·  ~3–5 days  ·  Linux-only

**Trigger:** Phase 1 still shows >5% loss on sustained ~1 Gbps RTP.
Expected +40–60% throughput, ~30% lower latency; zero-copy within the ring.

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
