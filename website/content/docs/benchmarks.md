+++
title = "Check how fast sipnab is"
weight = 19
description = "Reproducible throughput and memory benchmarks, and what the headroom buys: how much of an estate one sipnab can take at once, multi-core scaling, and the cost of full SIP + RTP reconstruction at carrier scale."
+++

How fast sipnab is, measured honestly — and what that speed is for. The number
is not a race against the local capture tools. It is the headroom that decides
how much of an estate one binary can take at once, and therefore whether you
stand up a collector tier at all. **The multi-core and carrier-scale tables on
this page come from one session on 2026-10-11.**

Taken on a local release build of 0.5.211 (`15e5e7bd`), 2026-10-11, on an idle host
— main after the v0.5.211 tag, which adds the single-core reader change to the
tag. `vmstat` was idle at 99% before every run, with no CI job or toolchain
build running. A local build
rather than a published artifact, deliberately: the nightly throughput gate has
to catch a regression the day it lands, not once it has shipped, so the number
this page publishes is the number that gate measures.

**[`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json)
commits every figure in those tables** — all three replicates per core count,
the peak resident set of each, and the whole carrier-scale sweep. The published figure is the LOWEST replicate rather
than the median, so a reader who re-runs the harness meets or beats it instead
of falling short of it.

**A raise here and a raise in that file are one event, and a test now says so.**
They came apart three times while the rule lived in a comment that asked a
reader to remember it. The last separation published 3.23M for 0.5.122 while
the committed baseline held 3.25M with replicates 3.25/3.29/3.29M — a figure the recorded run
never produced, 0.6% adrift, inside this page's own noise floor, which is
exactly why no reader caught it.

Every number is reproducible. The corpus generator and the timing harness ship
in [`bench/`](https://github.com/NormB/sipnab/tree/main/bench), so you can
rebuild the corpus — 535,000 packets: 35,000 SIP, 500,000 RTP (93.5%), 100
Call-IDs, 200 streams — and re-run every table below on your own hardware.

## What the throughput is for

Reach, not a benchmark win. sipnab sits between a local capture tool and a
capture platform: many nodes, no infrastructure behind it
([the position](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)).
Kamailio, OpenSIPS and Asterisk already speak HEP, so they mirror their
signaling to one sipnab listener and that single process answers for the whole
estate — nothing goes on the production hosts.

Throughput is what keeps that
arrangement honest. A listener that falls behind the fan-in sends you back to
capture agents feeding a collector, which is the deployment project sipnab
exists to skip.

Put the figures next to the load. A proxy running 100 calls per second at
roughly ten SIP messages per call emits about 1,000 signaling packets per
second. The tables below measure 1.18M packets per second on one core and 3.52M
on four, on a corpus that is 93.5% RTP — media a signaling-only HEP feed never
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
- **Version:** sipnab 0.5.211, local release build `15e5e7bd` (main after
  the v0.5.211 tag), with every feature, built as the nightly gate builds it.
  **Date:** 2026-10-11.
- **Published figure:** the LOWEST of three replicates, per core count. The
  peak RSS cell is the HIGHEST of the three, the figure to plan memory against.
  [`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json)
  commits every replicate, so each cell below resolves to a recorded run rather
  than a remembered one.

## Multi-core offline reconstruction

[`--cores N`](@/docs/cli.md#resource-limits) shards by host-pair across worker
threads. On the 535k-packet fixed-state corpus (100 Call-IDs, 200 streams):

Each row is median-of-5 after a discarded warmup, three replicates, on one idle
host. The published column is the lowest replicate. The spread column carries
all three, so a reader sees the noise rather than taking the word for it.

| cores | pkts/s | replicates | peak RSS |
|------:|-------:|-----------:|---------:|
| 1 | 1.18M | 1.18 / 1.18 / 1.18M | 168.4 MiB |
| 2 | 2.57M | 2.59 / 2.57 / 2.60M | 107.9 MiB |
| 4 | **3.52M** | 3.56 / 3.56 / 3.52M | 103.4 MiB |
| 8 | 3.15M | 3.15 / 3.16 / 3.17M | 107.0 MiB |

**Four cores is the peak, and eight is slower** — in every replicate, not in one
bad run. The single-core row holds the most memory, 168.4 MiB against about
105 MiB on two or more cores. It did so through libpcap as well, and it still
does now that the single-threaded reader maps the file. This page does not yet
have a measured cause for it.

The 4-core cell is the figure
[`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json)
commits and the nightly throughput gate measures against. It is the same number
in both places because a test refuses any commit where it is not.

**0.5.108 raised the multi-core ceiling by removing a read.** The `--cores` path is
one serial thread reading, copying and host-pair-peeking every packet while N
workers wait, and reading through libpcap charged that thread a `read` into
libpcap's buffer *and* a copy out of it. 0.5.108 maps the capture file
instead, so it parses records in place out of page cache and copies only the
frame.

That moves where the curve stops, and the mechanism is why one and two cores
did not move with it: until the change after 0.5.211, `--cores 1` and a run
with no `--cores` used the single-threaded reader through libpcap, and on two
cores nothing needs unblocking until enough workers pile up behind the reader.
The single-threaded reader now maps the file too, and
[Throughput history](@/docs/internals/profiling.md#throughput-history)
records what that did on one core.

**The A/B that measured this is not on this page**, and this page drops the
sentences that used to quote its spread and its per-core gaps rather than
carrying them forward.

They described a session whose table was never published here, so a
reader had no way to check them — the same defect as a stale number, wearing the
shape of a measurement it cannot produce.

What survives is the mechanism, and
the table above, which measures where the curve actually stops on the current
release: four cores is the peak and eight is slower.

Before v0.4.16 a per-packet cross-core hand-off collapsed this to 0.84M @ 4
cores and 0.50M @ 8. Batching the hand-off removed that one, and 0.5.104 extends
the same cure to the single-core path.

## Throughput history

The A/B sessions that measured past regressions and their repairs, from 0.5.47
onward, are in
[Profiling: Throughput history](@/docs/internals/profiling.md#throughput-history).

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
| 500 | 53.5k | 500 | 1,000 | 2.08M | 33.5 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 2.74M | 73.6 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 3.05M | 233.2 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 3.06M | 531.1 MiB |

[`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json)
commits every row under `carrier_scale_sweep`, from the same 2026-10-11 session
and the same host as the table above.

**This table moves more between sessions than within one.** Two more sessions
the same evening measured `15e5e7bd` at 3.14-3.31M at 20,000 calls, against
3.06M here, and 0.5.160's 2026-09-09 session published 3.26M. Interleaved in
one session, 0.5.160, 0.5.211 and `15e5e7bd` were within 5% of each other at
every size: 0.5.160 was fastest at 500 calls and slowest at 20,000. The lower
figures here are the session, not a regression. Memory did grow: at 20,000
calls 0.5.160 peaked at 493-499 MiB in that session, 0.5.211 at 517-531 MiB
and `15e5e7bd` at 527-537 MiB.

**Honest read:** throughput is flat from 8k calls up — reconstruction cost is
per-packet, not per-dialog, and 40k concurrent streams do not degrade it. The
smaller corpora post lower figures because startup is inside the clock and a
53.5k-packet read is over in ~26 ms.

Memory grows close to linearly with
tracked state, about 27 KiB per call (dialog + two RTP streams + jitter/loss
accounting), reaching 531 MiB at 20k calls. That linearity is the useful property: it is predictable, so capacity
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

- Generate the corpus:

   ```sh
   python3 bench/carrier.py --calls 5000 --out corpus.pcap
   ```

- Then run the scaling harness against it:

   ```sh
   bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
   ```

sipnab 0.5.108 at four cores, with the per-message stream suppressed so only the
end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```

sipnab flag reference: [`--cores`](@/docs/cli.md#resource-limits),
[`--report`](@/docs/cli.md#output),
[`--no-cli-print`](@/docs/cli.md#output).
