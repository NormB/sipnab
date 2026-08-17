+++
title = "Benchmarks"
weight = 17
description = "Reproducible throughput and memory benchmarks, and what the headroom buys: how much of an estate one sipnab can take at once, multi-core scaling, a controlled version A/B, and the cost of full SIP + RTP reconstruction at carrier scale."
+++

How fast sipnab is, measured honestly — and what that speed is for. The number
is not a race against the local capture tools. It is the headroom that decides
how much of an estate one binary can take at once, and therefore whether you
stand up a collector tier at all. **Every table on this page comes from one run
on 0.5.104, on 2026-08-17.**

Taken on the released 0.5.104 artifact, checksum-verified, 2026-08-17, on an
idle host, with the released 0.5.103 measured in the same session as a
control.

Every number is reproducible. The corpus generator and the timing harness ship
in [`bench/`](https://github.com/NormB/sipnab/tree/main/bench), so you can
rebuild the corpus — 535,000 packets: 35,000 SIP, 500,000 RTP (93.5%), 100
Call-IDs, 200 streams — and re-run every table below on your own hardware.

## What the throughput is for

Reach, not a benchmark win. sipnab sits between a local capture tool and a
capture platform: many nodes, no infrastructure behind it
([the position](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)).
Kamailio, OpenSIPS and Asterisk already speak HEP, so they mirror their
signalling to one sipnab listener and that single process answers for the whole
estate — nothing goes on the production hosts. Throughput is what keeps that
arrangement honest. A listener that falls behind the fan-in sends you back to
capture agents feeding a collector, which is the deployment project sipnab
exists to skip.

Put the figures next to the load. A proxy running 100 calls per second at
roughly ten SIP messages per call emits about 1,000 signalling packets per
second. The tables below measure 1.28M packets per second on one core and 2.31M
on four, on a corpus that is 93.5% RTP — media a signalling-only HEP feed never
carries at all. Three orders of magnitude separate that proxy from a single
core's budget.

Two limits on the arithmetic, stated here rather than left for a reader to
discover:

- These tables measure offline pcap reconstruction, not the HEP receive path.
  Read the ratio as a budget with room in it, not as a measured fan-in ceiling.
- Reconstruction is not the first ceiling a fan-in meets anyway.
  [`--hep-rate-limit`](@/docs/cli.md#network-listeners) caps what a listener
  accepts, and its default sits far below these tables, so size a deployment
  against that knob rather than against this page.

## Test host & method

- **Host:** NVIDIA Jetson Thor devboard (aarch64), 14 cores, PREEMPT_RT
  kernel, idle. (A 4-vCPU VM is not used for throughput numbers.)
- **Corpus:** [`bench/carrier.py`](https://github.com/NormB/sipnab/blob/main/bench/carrier.py) — N concurrent calls, each
  `INVITE → 100 → 180 → 200 → ACK → [bidirectional RTP] → BYE → 200`,
  G.711 PCMU at 20 ms, 93.5% RTP by packet count.
- **Method:** offline pcap reconstruction (`-I file`), median-of-5 after one
  discarded warmup. `pkts/s = packets ÷ wall-clock seconds`, startup included.
- **Version:** sipnab 0.5.104 (release artifact). **Date:** 2026-08-17.

## Multi-core offline reconstruction

[`--cores N`](@/docs/cli.md#resource-limits) shards by host-pair across worker
threads. On the 535k-packet fixed-state corpus (100 Call-IDs, 200 streams):

| cores | pkts/s |
|------:|-------:|
| 1 | 1.28M |
| 2 | 2.17M |
| 4 | **2.31M** |
| 8 | 2.16M |

The ceiling is the single sequential pcap reader (read + buffer copy +
host-pair peek), not the core count — which is why 8 cores is slower than 4
rather than faster.

**Single core gained 27% in 0.5.104, and the multi-core figures did not
move.** The default (single-core) path used to push every packet through the
capture channel one send at a time — machinery a profile measured at ~35% of
single-core wall time, against ~9% for the SIP and RTP analysis itself.
0.5.104 batches a file read at 128 packets per channel item, and single core
went from 1.01M to 1.28M on the released artifacts, same session,
interleaved. The `--cores` path was already batched, which is why its numbers
stayed put: its ceiling is the serial reader stage (read + buffer copy +
host-pair peek), not the hand-off. That ceiling is why the curve flattens past
two cores and sags past four — the honest sizing advice is that `--cores 4`
is the most this workload can use, and more workers than that measure
slightly worse, not better.

Before v0.4.16 a per-packet cross-core hand-off collapsed this to 0.84M @ 4
cores and 0.50M @ 8. Batching the hand-off removed that one; 0.5.104 extends
the same cure to the single-core path.

## Is the packet path still what it was at 0.5.47?

No — it is **faster**. Throughput fell 40% in 0.5.84 and held that loss for four
releases. 0.5.89 recovered part of it, and 0.5.91 went past where it started.

Both release artifacts checksum-verified, identical corpus, same idle host, same
session, with interleaved replicates so host drift cannot pass for a difference
between versions:

| cores | 0.5.47 | 0.5.88 | 0.5.89 | 0.5.91 | 0.5.91 vs 0.5.47 |
|------:|-------:|-------:|-------:|-------:|-----------------:|
| 1 | 1.06M | 0.91M | 0.96M | 1.07M | +1% |
| 2 | 2.27M | 1.39M | 1.69M | 2.21M | −3% |
| 4 | 2.02M | 1.33M | 1.90M | **2.32M** | **+15%** |
| 8 | 1.91M | 1.29M | 1.73M | 2.13M | +12% |

Within-version spread is about 2% and the 0.5.47 → 0.5.88 gap is about 39%, so
that gap is roughly eighteen times the noise floor. An unrelated third-party binary
measured identically in both arms — a different program, same corpus, same
afternoon, that did not move. That is what rules out the host.

**The cause.** 0.5.84 began stamping a frame-provenance digest on the serial
reader, the one stage `--cores` waits on: a single thread reads, copies and
host-pair-peeks every packet while the workers idle. That charged it about 240
bytes of dependent multiplies per packet, or 129 MB hashed a byte at a time on
this corpus. 0.5.89 moves the hash to the workers, computing the same FNV-1a
over the same bytes, so pointers already written down still resolve. Because
the work now spreads across workers, the recovery scales with them: about 81%
of the loss at four cores, about 34% at two.

**Why 0.5.91 overshot.** Two further changes, both from the same profile.
`parse_packet` stopped building a `FrameRef` per packet — a `FrameRef` owns an
`Arc<str>`, so each one cost an atomic pair for a pointer that ~93% of frames
never keep. The reader also stopped allocating each frame separately: it now
cuts them from a shared 64 KiB block, so the allocator's cross-thread free path
runs once per ~270 frames instead of once per frame. Together those put
four-core throughput **above** where it was before the regression — 2.32M
against 0.5.47's 2.02M. The second change beat its own predicted ceiling,
because frames sharing a block are also sequential in memory, which a
diagnostic that scattered them into an arena could not show.

**Still outstanding**, rather than left for the next re-run to discover:
sipnab hashes every frame when only a retained pointer needs a digest (~35,000
of 535,000 here), and a further ~12% of the original regression comes from
something other than the digest that nobody has identified yet. PERF1 tracks
both.

**CI measures throughput now, nightly rather than per push.** When that
regression shipped four times, nothing here measured speed. The `Throughput`
workflow now runs a regression gate at 03:29 UTC daily against a committed
baseline and fails below a stated floor. It is nightly on purpose: the reference
host is one self-hosted runner that also serves CI, so two jobs on it would
measure their own contention. It does not catch slow erosion inside the floor —
a deliberate trade.

**Continued, 2026-08-17: 0.5.103 → 0.5.104.** The table above was measured on
2026-08-10 and its columns say nothing about anything released after; this
continuation is a separate session with its own control, both released
artifacts, checksum-verified, same idle host:

| cores | 0.5.103 | 0.5.104 | change |
|------:|--------:|--------:|-------:|
| 1 | 1.01M | 1.28M | **+27%** |
| 2 | 2.21M | 2.17M | −2% |
| 4 | 2.29M | **2.31M** | +1% |
| 8 | 2.13M | 2.16M | +1% |

The single-core gain is 0.5.104's batched file read. The 0.5.103 single-core
figure also records what happened between 0.5.91 and 0.5.103: a ~4%-of-figure
erosion, diffuse across two hundred commits of added analysis, that a profiler
could not pin to any single function — found, bounded, and overtaken by the
batching change rather than chased line by line.

The same A/B settles what the pre-0.5.47 tables mean. 0.5.18 measures 1.06M
single-core here against the 1.20M this page published for it — same binary,
same host, different corpus. The gap between old and new tables is the corpus,
not a regression.

## What the throughput includes

A packets-per-second number only means something next to the work behind it, so
this is what sipnab is doing while it posts the figures above, on the same
535k-packet corpus:

- every SIP message parsed into dialogs, with state, timing and PDD
- all 500,000 RTP packets associated into **200 media streams**, each with its
  codec, jitter, loss and MOS
- frame pointers minted for anything a report can cite later, so you can
  resolve a finding back to the captured bytes

That is full reconstruction, not line matching. A tool that only greps SIP text
does a fraction of this work, and posts a larger raw number for that reason.

## Throughput and memory at carrier scale

The table above is one operating point at fixed dialog state. This sweep grows
the state: unique Call-IDs and unique RTP endpoints per call
(`--call-ids 0 --stream-pairs 0`), so dialog and stream tables scale with call
volume. Measured at `--cores 4`:

| calls | pkts | dialogs | streams | pkts/s | peak RSS |
|------:|-----:|--------:|--------:|-------:|---------:|
| 500 | 53.5k | 500 | 1,000 | 1.69M | 23.5 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 2.01M | 62.8 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 2.14M | 219.5 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 2.14M | 484.6 MiB |

**Honest read:** throughput is flat from 8k calls up — reconstruction cost is
per-packet, not per-dialog, and 40k concurrent streams do not degrade it. The
smaller corpora post lower figures because startup is inside the clock and a
53.5k-packet read is over in ~30 ms. Memory grows close to linearly with
tracked state, about 24 KiB per call (dialog + two RTP streams + jitter/loss
accounting), reaching 485 MiB at 20k calls. That linearity is the useful property: it is predictable, so capacity
planning is arithmetic rather than guesswork.

## A note on the `-N --json` export path

0.5.20 rewrote the `-N --json` export sink — buffered batch writes plus direct
JSON serialization, measured at ~29% less wall-clock and 98.5% fewer `write()`
syscalls on that path in a same-toolchain A/B with byte-identical output. That
figure came from a development branch, not from a released artifact, and
has not been re-measured since. [`--group-by`](@/docs/cli.md#output) (added in
0.5.44) buffers messages to end-of-capture when passed, and that measurement
predates it. The tables above do not exercise the JSON sink.

## Reproduce

Full instructions, including artifact download and checksum verification, are in
[`bench/README.md`](https://github.com/NormB/sipnab/blob/main/bench/README.md).
In short — the generator runs first, because both harnesses read the corpus it
writes:

```sh
# Run all of these, in order.
python3 bench/carrier.py --calls 5000 --out corpus.pcap
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
```

sipnab 0.5.104 at four cores, with the per-message stream suppressed so only the
end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```

sipnab flag reference: [`--cores`](@/docs/cli.md#resource-limits),
[`--report`](@/docs/cli.md#output),
[`--no-cli-print`](@/docs/cli.md#output).
