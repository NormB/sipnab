+++
title = "Benchmarks"
weight = 11
description = "Reproducible throughput and memory benchmarks: sipnab multi-core scaling, and honest comparisons against sngrep and voipmonitor."
+++

How fast sipnab is, measured honestly. Every number here is reproducible — the
host, corpus, tool versions, and exact commands are listed so you can re-run it.

> **Read this first.** These tools do *different amounts of work*, so a raw
> throughput number only means something next to *what was reconstructed*.
> `sipgrep` is a grep-style line matcher; `sngrep` builds an interactive SIP
> ladder; voipmonitor produces full CDRs plus media spooling; sipnab does full
> SIP dialog **and** RTP-stream reconstruction with per-stream codec / jitter /
> loss. sipnab is generally doing *more* reconstruction than the tool it is
> being compared against here, which strengthens rather than weakens the result.

## Test host & method

- **Host:** `thor-02` — NVIDIA Jetson Thor (aarch64), 14 cores, PREEMPT_RT
  kernel. (A 4-vCPU VM is not used for throughput numbers.)
- **Corpus:** a synthetic carrier capture — N concurrent calls, each
  `INVITE → … → 200 → ACK → [bidirectional RTP] → BYE`, ~93% RTP by packet count.
- **Method:** offline pcap reconstruction (`-I file`), median-of-5 after one
  discarded warmup. `pkts/s = packets ÷ wall-clock seconds`.
- **Version:** sipnab 0.4.16. **Date:** 2026-06-24.

## Multi-core offline reconstruction (sipnab)

`--cores N` shards by host-pair across worker threads. On a 535k-packet corpus
throughput holds a flat plateau from 2 cores up:

| cores | pkts/s |
|------:|-------:|
| 1 | 1.24M |
| 2 | **2.51M** |
| 4 | 2.27M |
| 8 | 2.16M |

The plateau past cores 2 is the single sequential pcap reader (read + buffer copy
+ host-pair peek), not the core count. Before v0.4.16 a per-packet cross-core
hand-off collapsed this to 0.84M @ 4 cores and 0.50M @ 8; batching the hand-off
removed the regression. CPU pinning was measured and made no meaningful
difference (+3–5% within noise, ~0% at 8 cores) — the limit is data-movement, not
scheduling.

## Four-tool comparison

Same 535k-packet corpus, every tool driven offline/headless to parse the whole
file and exit (median-of-5). The **what it reconstructs** column is the point — a
throughput number only means something next to the work behind it.

| tool | pkts/s | × sngrep | what it reconstructs |
|---|---:|---:|---|
| sngrep 1.8.0 | 0.20M | 1.0× | SIP dialogs (100); no RTP-stream reconstruction headless |
| sipgrep 2.2.0 | 2.46M | 12.2× | grep-style SIP line match + Call-ID grouping; **no RTP** |
| voipmonitor 2026.05.0 | 0.73M | 3.7× | full call/CDR + RTP-stream association |
| **sipnab 0.4.16 `--cores 1`** | 1.05M | **5.2×** | SIP dialogs + **200 RTP streams** |
| **sipnab 0.4.16 `--cores 4`** | 2.30M | **11.4×** | identical full SIP + RTP reconstruction |

Read it in three buckets:

- **Grep-class (sipgrep)** posts the fastest single number but does the least —
  line-oriented SIP matching with **no RTP work at all** (it never associates the
  500k RTP packets into streams). Its lead is mostly "it does less."
- **Full reconstruction (sngrep, voipmonitor, sipnab)** parse SIP into dialogs;
  voipmonitor and sipnab additionally associate RTP into media streams.
- Within that class **sipnab wins**: single-core is **5.2× sngrep and 1.4×
  voipmonitor**, four-core is **11.4× sngrep and 3.1× voipmonitor** — and four-core
  matches grep-only sipgrep's wall-clock (0.23 s vs 0.22 s) *while also
  reconstructing all 200 RTP streams*. There is no configuration where sipnab is
  the slowest at comparable work.

> **Fairness notes.** The corpus is synthetic and reuses SDP media endpoints, so
> voipmonitor's default `sdp_multiplication=3` DoS-guard would suppress the
> duplicate-SDP streams; it was set to `0` so voipmonitor does full RTP
> association on equal footing. All four tools parsed the same file to EOF.
> sngrep and sipgrep report dialogs grouped by the 100 unique Call-IDs while
> sipnab reports the finer 35k messages / 200 streams — a reporting-depth
> difference, not a correctness one. sipnab's figures here come from an
> independent timed session, so they differ by a few percent from the scaling
> table above (normal run-to-run variance).

## Throughput and memory at carrier scale (vs voipmonitor)

The single-corpus table above is one operating point; this sweep shows how the
closest peer behaves as call volume grows. **Both tools reconstruct every call
correctly at every scale** — the difference is throughput and memory:

| calls | pkts | voipmonitor | sipnab | sipnab speed-up | sipnab RSS edge |
|------:|-----:|---|---|---:|---:|
| 500 | 53.5k | 72k p/s · 150 MiB | 539k p/s · 33 MiB | 7.5× | 4.5× |
| 2000 | 214k | 155k p/s · 506 MiB | 500k p/s · 72 MiB | 3.2× | 7.0× |
| 8000 | 856k | 233k p/s · 1931 MiB | 409k p/s · 217 MiB | 1.75× | 8.9× |
| 20000 | 2.14M | 264k p/s · 4782 MiB | 340k p/s · 507 MiB | 1.29× | 9.4× |

**Honest read:** sipnab leads on throughput at every scale up to 20k calls, but
voipmonitor is multithreaded and its per-packet throughput *climbs* with scale
(72k → 264k p/s), overtaking sipnab on raw speed at roughly ~40k calls. sipnab's
standing advantage is **memory** — about 9.4× less RSS at 20k calls (0.5 GiB vs
4.7 GiB), because voipmonitor buffers and spools heavily. (voipmonitor's *live*
capture reconstructed 0 calls on this box's virtual NIC — an mmap-ring quirk — so
this comparison is offline-only.)

## Reproduce

Each tool driven offline/headless to parse the whole file and exit:

```sh
sngrep       sngrep  -I corpus.pcap -r -N -q
sipgrep      sipgrep -I corpus.pcap -C -G
voipmonitor  voipmonitor -r corpus.pcap -c -k --config-file=vm.conf   # sdp_multiplication=0, save_*=no
sipnab       sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```

The carrier corpus generator and the comparison harness live in the companion
`siptest` repo (`bench/carrier.py`, `bench/fourtool.sh`).
