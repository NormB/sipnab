+++
title = "Benchmarks"
weight = 17
description = "Reproducible throughput and memory benchmarks: sipnab multi-core scaling, and honest comparisons against sngrep and voipmonitor."
+++

How fast sipnab is, measured honestly. Every number here is reproducible — the
host, corpus, tool versions, and exact commands are listed so you can re-run it.

sipnab numbers are measured on the released 0.5.18 artifact,
checksum-verified, run 2026-07-20. Release 0.5.20 left the
capture/packet path below unchanged (its numbers carry over), but rewrote
the `-N --json` export sink: buffered batch writes plus direct JSON
serialization cut wall-clock time ~29% and `write()` syscalls 98.5% on that
path (same-toolchain A/B on this branch, byte-identical output; not yet
re-measured on a released artifact). The current release 0.5.41 (dependency
updates only) changes neither path. The comparison
tools' numbers come from the 2026-06-24 session — same host, corpus, and
method, and their versions are unchanged. Versus the 0.4.16 session, 0.5.18
measures faster at every multi-core operating point (+9–16%) and across the
carrier sweep (+30–107%).

0.5.18's rebuilt `-O` re-emit writer (WS8.3) deserves an honest word: a
same-toolchain A/B shows the per-packet write cost down 43%, and write
errors (full disk, dead mount) now surface instead of being silently
discarded — but end-to-end `-O` throughput on *this* host is unchanged,
because here the re-emit is bound by pushing the corpus's bytes through the
page cache, not by per-packet overhead. On an x86 dev box the same change
measures +8–16% end-to-end. (Two apparent regressions in an earlier re-run —
single-core `-O` throughput and small-scale RSS — were checked with a
controlled same-day A/B of the 0.4.16 and 0.5.17 binaries: both measured
identically, so those deltas were session variance in the June figures, not
version regressions.)

> **Read this first.** These tools do *different amounts of work*, so a raw
> throughput number only means something next to *what was reconstructed*.
> `sipgrep` is a grep-style line matcher; `sngrep` builds an interactive SIP
> ladder; voipmonitor produces full CDRs plus media spooling; sipnab does full
> SIP dialog **and** RTP-stream reconstruction with per-stream codec / jitter /
> loss. sipnab is generally doing *more* reconstruction than the tool it is
> being compared against here, which strengthens rather than weakens the result.

## Test host & method

- **Host:** NVIDIA Jetson Thor devboard (aarch64), 14 cores, PREEMPT_RT
  kernel. (A 4-vCPU VM is not used for throughput numbers.)
- **Corpus:** a synthetic carrier capture — N concurrent calls, each
  `INVITE → … → 200 → ACK → [bidirectional RTP] → BYE`, ~93% RTP by packet count.
- **Method:** offline pcap reconstruction (`-I file`), median-of-5 after one
  discarded warmup. `pkts/s = packets ÷ wall-clock seconds`.
- **Version:** sipnab 0.5.18 (release artifact). **Date:** 2026-07-20.

## Multi-core offline reconstruction (sipnab)

[`--cores N`](@/docs/cli.md#resource-limits) shards by host-pair across worker threads. On a 535k-packet corpus
throughput holds a flat plateau from 2 cores up:

| cores | pkts/s |
|------:|-------:|
| 1 | 1.20M |
| 2 | **2.90M** |
| 4 | 2.52M |
| 8 | 2.35M |

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
| **sipnab 0.5.18 `--cores 1`** | 0.83M | **4.2×** | SIP dialogs + **200 RTP streams** |
| **sipnab 0.5.18 `--cores 4`** | 2.50M | **12.5×** | identical full SIP + RTP reconstruction |

Read it in three buckets:

- **Grep-class (sipgrep)** posts the fastest single number but does the least —
  line-oriented SIP matching with **no RTP work at all** (it never associates the
  500k RTP packets into streams). Its lead is mostly "it does less."
- **Full reconstruction (sngrep, voipmonitor, sipnab)** parse SIP into dialogs;
  voipmonitor and sipnab additionally associate RTP into media streams.
- Within that class **sipnab wins**: single-core is **4.2× sngrep and 1.1×
  voipmonitor**, four-core is **12.5× sngrep and 3.4× voipmonitor** — and four-core
  matches grep-only sipgrep's wall-clock (0.21 s vs 0.22 s) *while also
  reconstructing all 200 RTP streams*. There is no configuration where sipnab is
  the slowest at comparable work. (Single-core with `-O` re-emit measures the
  same on 0.4.16 and 0.5.17 in a controlled A/B — the June 1.05M row was
  session variance. The `-O` write itself costs ~35% single-core on either
  version; without `-O` single-core is flat at 1.20M.)

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
| 500 | 53.5k | 72k p/s · 150 MiB | 699k p/s · 42 MiB | 9.7× | 3.6× |
| 2000 | 214k | 155k p/s · 506 MiB | 697k p/s · 96 MiB | 4.5× | 5.3× |
| 8000 | 856k | 233k p/s · 1931 MiB | 726k p/s · 230 MiB | 3.1× | 8.4× |
| 20000 | 2.14M | 264k p/s · 4782 MiB | 703k p/s · 519 MiB | 2.7× | 9.2× |

**Honest read:** sipnab leads on throughput at every measured scale, holding a
flat ~700k p/s while voipmonitor's multithreaded per-packet throughput *climbs*
with scale (72k → 264k p/s) — on 0.4.16 that climb crossed over at roughly
~40k calls; on 0.5.18 the sweep no longer flags a crossover inside any
plausible operating range. sipnab's standing advantage is still **memory** —
about 9.2× less RSS at 20k calls (0.5 GiB vs 4.7 GiB), because voipmonitor
buffers and spools heavily. (An apparent small-scale RSS growth vs the June
figures — 39 vs 33 MiB at 500 calls — was A/B-checked: 0.4.16 measures
40/99 MiB on the same day 0.5.17 measures 39/103, so the delta was session
variance, not a version regression.) (voipmonitor's *live*
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

sipnab flag reference: [`--cores`](@/docs/cli.md#resource-limits),
[`--report`](@/docs/cli.md#output),
[`--no-cli-print`](@/docs/cli.md#output).

The carrier corpus generator and the comparison harness
(`bench/carrier.py`, `bench/fourtool.sh`) live in the internal `siptest`
harness, which is not publicly published — the corpus parameters and the
exact commands above are the full recipe.
