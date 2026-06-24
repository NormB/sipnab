# Benchmarks

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
  kernel. (opensips-1, a 4-vCPU VM, is not used for throughput numbers.)
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

## vs sngrep

Same 535k-packet corpus, both reconstructing SIP + RTP:

| tool | pkts/s | × sngrep | what it reconstructs |
|---|---:|---:|---|
| sngrep | 0.20M | 1.0× | SIP ladder + RTP (headless print capped at 100 dialogs) |
| sipnab `--cores 1` | 1.24M | **6.2×** | full SIP dialog + 200 RTP streams |
| sipnab `--cores 4` | 2.27M | **11.3×** | same |

## vs voipmonitor (carrier scale)

voipmonitor is the closest peer — it also does full CDR + media work. Across a
carrier-scale sweep, **both tools reconstruct every call correctly at every
scale**; the difference is throughput and memory:

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
4.7 GiB), because voipmonitor buffers and spools heavily. This comparison is
offline-only: voipmonitor's *live* capture reconstructed 0 calls on this box's
virtual NIC (an mmap-ring quirk), so a live head-to-head was not possible here.

## sipgrep

`sipgrep` is a different category — a grep-style SIP line matcher, not a
reconstructor — so it is not directly comparable on reconstruction throughput and
is not benchmarked here.

## Reproduce

```sh
# sipnab — offline reconstruction, multi-core
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print

# sngrep — headless full-file parse
sngrep -I corpus.pcap -r -N -q
```

The carrier corpus generator and the full comparison harness live in the
companion `siptest` repo (`bench/carrier.py`, `bench/fourtool.sh`).
