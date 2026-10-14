# Benchmarks

How fast sipnab is, measured honestly — and what that speed is for.

- The number is not a race against the local capture tools.
- It is the headroom that decides how much of an estate one binary can take at once.
- It therefore decides whether you stand up a collector tier at all.

**Every table on this page names the session that measured it.**

- The multi-core and carrier-scale tables come from one session on 2026-10-11.
- The version A/B further down is 2026-08-10.
  Its continuations are 2026-08-17 and 2026-10-11, each carrying a control of its own.

Every number here is reproducible. It has been a checked claim rather than an
asserted one since 0.5.47.

- That release put the corpus generator and the
  timing harness in [`bench/`](../bench/).
- So you can regenerate the corpus and re-run every table below.
- 0.5.47 dates the recipe, not this run.

> **Measured against 0.5.211 at `15e5e7bd`, on 2026-10-11.** The multi-core and
> carrier-scale tables below are that measurement.
>
> - No number here stands in for a release it did not measure.
> - None carries forward from a run nobody repeated.
>
> **[`bench/baseline.json`](../bench/baseline.json) commits every figure in
> those two tables**:
>
> - all three replicates per core count,
> - the peak resident set of each,
> - the whole carrier-scale sweep.
>
> The published figure is the LOWEST replicate rather than the median.
>
> - So a reader who re-runs the harness meets or beats it instead of falling short of it.
> - And the throughput gate's floor cannot sit above a number this host actually produces.
>
> **A raise here and a raise in that file are one event, and a test now says
> so.**
>
> - They came apart three times while the rule lived in a comment that
>   asked a reader to remember it.
> - The last separation published 3.23M for 0.5.122.
>   - The committed baseline held 3.25M with replicates 3.25/3.29/3.29M.
>   - So the page showed a figure the recorded run never produced.
>   - It was 0.6% adrift, inside this page's own noise floor. That is exactly why no reader caught it.
> - `benchmarks_pages_headline_matches_the_committed_baseline` binds the
>   baseline to both hand-maintained copies of this page and to the homepage
>   tile.
>
> **0.5.118 through 0.5.121 ran materially slower than 0.5.117, and 0.5.122
> repaired it.**
>
> - The cause was [`is_merged`](https://github.com/NormB/sipnab/blob/main/src/capture/merged.rs),
>   the probe that decides whether a capture is a merged pcapng.
> - It read the ENTIRE file into memory and then rejected it on the first four bytes.
> - So every offline run over an ordinary pcap:
>   - loaded the whole capture,
>   - threw it away,
>   - and only then started work.
> - Three call sites run it before the reader touches a packet.
>
> [`bench/regression-gate.sh`](../bench/regression-gate.sh) exists to catch
> exactly that and did not.
>
> - Its baseline still recorded 0.5.104's figure.
> - The drop read as 105% of a baseline four releases stale.
> - So the gate passed while the tool lost a quarter of its throughput.
> - That is the failure its own baseline file warns about in writing: a stale baseline "silently
>   widens the band it advertises".
> - This page's numbers and that file's are now
>   re-measured together or not at all.

The generator reproduces the documented corpus composition exactly:

- 535,000 packets,
- 35,000 SIP messages,
- 500,000 RTP,
- 93.5% RTP,
- 100 Call-IDs,
- 200 streams.

**Measured on a local release build of 0.5.211 (`15e5e7bd`), 2026-10-11, on an idle host**
— main after the v0.5.211 tag, which adds the single-core reader change to the
tag.

- `vmstat` was idle at 99% before every run.
- No CI job or toolchain build was running.
- That is the gate [`bench/baseline.json`](../bench/baseline.json) records as its condition for a
  measurement to count.
- A local build rather than a published artifact is deliberate.
  - The throughput gate has to catch a regression the day it lands, not once it has shipped.
  - So the number this page publishes is the number that gate measures.
- Nothing here is comparable to the pre-0.5.47 figures.
  Those came from an unpublished corpus nobody can rebuild.

## What the throughput is for

Reach, not a benchmark win.

- sipnab sits between a local capture tool and a capture platform:
  many nodes, no infrastructure behind it
  ([the position](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)).
- Kamailio, OpenSIPS and Asterisk already speak HEP.
  - So they mirror their signaling to one sipnab listener.
  - That single process answers for the whole estate.
  - Nothing goes on the production hosts.
- Throughput is what keeps that arrangement honest.
  - A listener that falls behind the fan-in sends you back to
    capture agents feeding a collector.
  - That is the deployment project sipnab exists to skip.

Put the figures next to the load.

- A proxy running 100 calls per second at roughly ten SIP messages per call
  emits about 1,000 signaling packets per second.
- The tables below measure 1.18M packets per second on one core and 3.52M on four.
  - The corpus is 93.5% RTP.
  - That is media a signaling-only HEP feed never carries at all.
- Three orders of magnitude separate that proxy from a single core's budget.

Two limits on the arithmetic, stated here rather than left for a reader to
discover:

- These tables measure offline pcap reconstruction, not the HEP receive path.
  Read the ratio as a budget with room in it, not as a measured fan-in ceiling.
- Reconstruction is not the first ceiling a fan-in meets anyway.
  - [`--hep-rate-limit`](cli-reference.md#network-listeners) caps what a listener
    accepts.
  - Its default sits far below these tables.
  - So size a deployment against that knob rather than against this page.

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
- **Published figure:** the LOWEST of three replicates, per core count.
  - The peak RSS cell is the HIGHEST of the three, the figure to plan memory against.
  - [`bench/baseline.json`](../bench/baseline.json) commits every replicate.
    So each cell below resolves to a recorded run rather than to a remembered one.

## Multi-core offline reconstruction

`--cores N` shards by host-pair across worker threads. On the 535k-packet
fixed-state corpus (100 Call-IDs, 200 streams):

- Each row is median-of-5 after a discarded warmup, three replicates, on one idle host.
- The published column is the lowest replicate.
- The spread column carries all three.
  So a reader sees the noise rather than taking the word for it.

| cores | pkts/s | replicates | peak RSS |
|------:|-------:|-----------:|---------:|
| 1 | 1.18M | 1.18 / 1.18 / 1.18M | 168.4 MiB |
| 2 | 2.57M | 2.59 / 2.57 / 2.60M | 107.9 MiB |
| 4 | **3.52M** | 3.56 / 3.56 / 3.52M | 103.4 MiB |
| 8 | 3.15M | 3.15 / 3.16 / 3.17M | 107.0 MiB |

**Four cores is the peak, and eight is slower** — in every replicate, not in
one bad run.

- The single-core row holds the most memory, 168.4 MiB against
  about 105 MiB on two or more cores.
- It did so through libpcap as well.
  It still does now that the single-threaded reader maps the file.
- This page does not yet have a measured cause for it.

The 4-core cell is the figure [`bench/baseline.json`](../bench/baseline.json)
commits and [`bench/regression-gate.sh`](../bench/regression-gate.sh) measures
against nightly. It is the same number in both places, because a test refuses
any commit where it is not.

**0.5.108 raised the multi-core ceiling by removing a read.**

- The `--cores` path is one serial thread reading, copying and host-pair-peeking every packet
  while N workers wait.
- Reading through libpcap charged that thread a `read`
  into libpcap's buffer *and* a copy out of it.
- 0.5.108 maps the capture file instead.
  So it parses records in place out of page cache and copies only the frame.

That moves where the curve stops. The mechanism is why one and two cores
did not move with it:

- Until the change after 0.5.211, `--cores 1` and a run
  with no `--cores` used the single-threaded reader through libpcap.
- On two cores, nothing needs unblocking until enough workers pile up behind the reader.
- The single-threaded reader now maps the file too.
  The 2026-10-11 continuation below measures what that did on one core.

**The A/B that measured this is not on this page.**

- This page drops the sentences that used to quote its spread and its per-core gaps.
  It does not carry them forward.
- They described a 2026-08-17 session whose table was never
  published here. So a reader had no way to check them.
- That is the same defect as a stale number, wearing the shape of a measurement it cannot
  produce.
- What survives:
  - the mechanism, which the code and
    [`docs/internals/zero-copy-payloads.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/zero-copy-payloads.md)
    record,
  - the table above, which measures where the curve actually stops on
    the current release: four cores is the peak and eight is slower.

The obvious version of that change is a regression. That is worth stating on a
page about honest measurement.

- Handing each frame out as a refcounted slice of
  the mapping, copying nothing at all, measures 1.88M at four cores.
  That is well under libpcap.
- One mapping is one atomic refcount.
- 535k frames cloned by the reader and dropped by the workers drive ~1M atomic updates through a single
  cache line.
- [`docs/internals/zero-copy-payloads.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/zero-copy-payloads.md) records the failed
  hypotheses in full.

## Is the packet path still what it was at 0.5.47?

No — it is **faster**.

- Throughput fell 40% in 0.5.84 and held that loss for four releases.
- 0.5.89 recovered part of it.
- 0.5.91 went past where it started.

The conditions:

- both artifacts checksum-verified,
- identical corpus,
- same idle host,
- same session,
- **interleaved** replicates, so drift in the host cannot masquerade as a
  difference between versions.

| cores | 0.5.47 | 0.5.88 | 0.5.89 | 0.5.91 | 0.5.91 vs 0.5.47 |
|------:|-------:|-------:|-------:|-------:|-----------------:|
| 1 | 1.06M | 0.91M | 0.96M | 1.07M | +1% |
| 2 | 2.27M | 1.39M | 1.69M | 2.21M | −3% |
| 4 | 2.02M | 1.33M | 1.90M | **2.32M** | **+15%** |
| 8 | 1.91M | 1.29M | 1.73M | 2.13M | +12% |

- Within-version spread is ~2%. The 0.5.47 → 0.5.88 gap is ~39%.
  So that gap is roughly eighteen times the noise floor.
- In the same runs an **unrelated third-party binary measured identically in
  both arms**.
  - It was a different program, same corpus, same afternoon, and it did not move.
  - That is what rules out the host.

**What it was.**

- 0.5.84 added a frame-provenance stamp that fixed a real bug.
  The parallel reader was silently dropping frame pointers on exactly the large
  captures where provenance matters most.
- But it computed the digest on the **serial reader**.
  - That is the one stage the whole `--cores` design waits on.
  - A single thread reads, copies and host-pair-peeks every packet while N workers sit idle.
  - This page had already named that stage as the plateau past two cores.
- Hashing there charged it ~240 bytes of dependent FNV multiplies per packet.
  Over this corpus that is arithmetic rather than a measurement: 535,000 packets × ~240
  bytes ≈ 128 MB hashed one byte at a time.

**What 0.5.89 did.**

- The workers compute the digest.
- The reader still assigns the ordinal, the one fact only it can know.
- Same input, same FNV-1a, same value.
  - A pointer from a `--cores` run resolves identically to one from a single-threaded run.
  - Pointers already written down still resolve.
- The work now scales with worker count, so the recovery does too: **~81% of the
  loss at four cores, ~34% at two.**
- Four cores is within 6% of 0.5.47.

**What 0.5.91 did, and why it overshot.** Two more changes, both from the same
profile:

- `parse_packet` stopped building a `FrameRef` per packet.
  - A `FrameRef` owns an `Arc<str>`.
  - So each one cost an atomic pair for a pointer ~93% of frames never keep.
- The reader also stopped allocating each frame separately.
  - It now cuts them from a shared 64 KiB block.
  - So the allocator's cross-thread free path runs once per ~270 frames instead of once per frame.

Together those put four-core throughput **above where it was before the
regression** — 2.32M against 0.5.47's 2.02M.

- The second change even beat its own predicted ceiling.
- Frames sharing a block are also sequential in memory.
  A diagnostic that scattered them into an arena could not show that.

**What the tables above still carried, and what closed after them.**

- Every build these tables measure hashes every frame.
- Only a *retained* pointer needs a digest:
  - a dialog's `first_frame`,
  - a stream's `first_frame`,
  - a finding's `frame_ref`.
- That is about 35,000 of 535,000 frames on this corpus.
- PERF1 in
  [`docs/design/backlog.md`](https://github.com/NormB/sipnab/blob/main/docs/design/backlog.md) closed that on 2026-08-28.
  It records the measurement it closed on:
  - two release builds off one tree differing only in this change,
  - same harness and corpus,
  - 2.70M at two cores against 2.10M,
  - 3.56M at four against 3.21M.
- The 0.5.160 table this page published on 2026-09-09 reflected it.
  It independently reproduced its four-core figure to the digit: 3.56M,
  measured twelve days later on the same host and corpus.

**What stays open.**

- A diagnostic build with the digest removed entirely
  measures 2.05M at two cores against 0.5.83's 2.33M.
- So roughly 12% of the original regression was never the digest at all.
  It remains unidentified.
- The same PERF1 entry carries that residue, together with:
  - the two obvious fixes,
  - the tests that already reject each.

**Scope.**

- The table above spans 0.5.47 → 0.5.91, measured on 2026-08-10.
  Its columns say nothing about anything released after.
- The continuation below is a separate session.
  It is not directly comparable to those columns.
- The host had drifted ~4% between the two dates.
  That is exactly why each session carries its own control.

**Continued, 2026-08-17: 0.5.103 → 0.5.104.** Both released artifacts,
checksum-verified, same idle host, same session:

| cores | 0.5.103 | 0.5.104 | change |
|------:|--------:|--------:|-------:|
| 1 | 1.01M | 1.28M | **+27%** |
| 2 | 2.21M | 2.17M | −2% |
| 4 | 2.29M | **2.31M** | +1% |
| 8 | 2.13M | 2.16M | +1% |

- The single-core gain is 0.5.104's batched file read.
  The default path had paid the channel hand-off per packet (see the multi-core section above).
- The 0.5.103 single-core figure also records honestly what happened between 0.5.91
  and 0.5.103:
  - a ~4%-of-figure erosion,
  - diffuse across two hundred commits of added analysis,
  - that a profiler could not pin to any single function.
  - The work found it, bounded it, and then overtook it with the batching change rather than chasing it line by
    line.

**Continued, 2026-10-11: 0.5.160, 0.5.211 and main after 0.5.211.**

- Local release builds of:
  - the v0.5.160 tag (`6df351b8`),
  - the v0.5.211 tag (`1d81503a`),
  - main at `15e5e7bd`.
- Same idle host, same session, the three interleaved in every replicate.
- Each cell is the three replicates, lowest first:

| cores | 0.5.160 | 0.5.211 | `15e5e7bd` |
|------:|--------:|--------:|-----------:|
| 1 | 1.06 / 1.06 / 1.07M | 0.97 / 0.97 / 0.98M | **1.16 / 1.19 / 1.19M** |
| 2 | 2.63 / 2.68 / 2.69M | 2.58 / 2.59 / 2.59M | 2.59 / 2.61 / 2.64M |
| 4 | 3.50 / 3.55 / 3.55M | 3.41 / 3.48 / 3.55M | 3.45 / 3.49 / 3.56M |
| 8 | 3.07 / 3.12 / 3.18M | 3.05 / 3.05 / 3.17M | 3.11 / 3.12 / 3.18M |

`vmstat` idle fell to 90-91% during the second replicate of 0.5.211 and of
`15e5e7bd`. That is below the 96% this page requires. The conclusions below hold with
or without those two replicates.

**One core lost about 8% between 0.5.160 and 0.5.211, and the change after
0.5.211 more than recovered it.**

- `perf` on main after 0.5.210 put:
  - 9.6% of cycles in glibc's `fread` lock on the libpcap reader thread,
  - 7.6% in `clock_gettime`, called once per packet by the keylog poll even with no
    keylog watch.
- `15e5e7bd` reads the file through the same mapping `--cores` uses.
  It cuts frames from shared 64 KiB blocks.
- It reads the clock only for `--keylog-watch` or `--keylog-fd`.
- One core is now about 20% above 0.5.211 and about 10% above 0.5.160.
- Two, four and eight cores are the
  same within the spread of each version's replicates.

The single-core runs of `15e5e7bd` produce byte-identical `--json-dialogs`
output to 0.5.211's on this corpus.

- Peak RSS on one core rose from 160.9 to 168.4 MiB.
- 0.5.160 measured 167.9-168.2 MiB.

**CI measures throughput nightly, rather than per push.**

- The `Throughput` workflow runs [`bench/regression-gate.sh`](https://github.com/NormB/sipnab/blob/main/bench/regression-gate.sh) at 03:29 UTC daily.
- It runs against the figure committed in [`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json).
- It fails below a stated floor.

It is nightly on purpose:

- The reference host is one self-hosted runner that also serves CI.
  So two jobs on it measure their own contention rather than the tool.
- A per-push wall-clock gate would be flaky in the direction that gets a gate muted.
- It does not catch slow erosion. A drift inside the floor passes.
- That is a deliberate trade, argued in [`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json).

The same A/B settles what the pre-0.5.47 tables mean.

- They measure an unpublished corpus nobody can rebuild.
- So nothing below them compares to them, and this page does not restate them.
- This paragraph used to carry a
  single-core figure for 0.5.18 against a figure "this page once published".
  Neither resolved to a committed record:
  - the older of the two resolved to a corpus that no longer exists,
  - the newer resolved to a session with no table.
- The claim they supported still holds and is the useful part: the gap between the old tables
  and these is the corpus, not a regression.

## What the throughput includes

A packets-per-second number only means something next to the work behind it.
So this is what sipnab is doing while it posts the figures above, on the same
535k-packet corpus:

- every SIP message parsed into dialogs, with state, timing and PDD
- all 500,000 RTP packets associated into **200 media streams**, each with its
  codec, jitter, loss and MOS
- frame pointers minted for anything a report can cite later, so you can
  resolve a finding back to the captured bytes

That is full reconstruction, not line matching. A tool that only greps SIP text
does a fraction of this work. It posts a larger raw number for that reason.

## Throughput and memory at carrier scale

The table above is one operating point at fixed dialog state. This sweep grows
the state:

- unique Call-IDs and unique RTP endpoints per call
  (`--call-ids 0 --stream-pairs 0`),
- so dialog and stream tables scale with call volume.

Measured at `--cores 4`:

| calls | pkts | dialogs | streams | pkts/s | peak RSS |
|------:|-----:|--------:|--------:|-------:|---------:|
| 500 | 53.5k | 500 | 1,000 | 2.08M | 33.5 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 2.74M | 73.6 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 3.05M | 233.2 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 3.06M | 531.1 MiB |

[`bench/baseline.json`](../bench/baseline.json) commits every row under
`carrier_scale_sweep`. The rows come from the same 2026-10-11 session and the same host as
the table above.

**This table moves more between sessions than within one.**

- Two more sessions the same evening measured `15e5e7bd` at 3.14-3.31M at 20,000 calls.
  This table shows 3.06M.
- 0.5.160's 2026-09-09 session published 3.26M.
- Interleaved in one session, 0.5.160, 0.5.211 and `15e5e7bd` were within 5% of each other at
  every size.
  0.5.160 was fastest at 500 calls and slowest at 20,000.
- The lower figures here are the session, not a regression.
- Memory did grow. At 20,000 calls in that session:
  - 0.5.160 peaked at 493-499 MiB,
  - 0.5.211 at 517-531 MiB,
  - `15e5e7bd` at 527-537 MiB.

**Honest read:**

- Throughput is flat from 8k calls up.
  - Reconstruction cost is per-packet, not per-dialog.
  - 40k concurrent streams do not degrade it.
- The smaller corpora post lower figures because startup is inside the clock.
  A 53.5k-packet read is over in ~26 ms.
- Memory grows close to linearly with tracked state.
  - It is about 27 KiB per call (dialog + two RTP streams + jitter/loss accounting).
  - It reaches 531 MiB at 20k calls.
- That linearity is the useful property. It is predictable.
  So capacity planning is arithmetic rather than guesswork.

The mapping does not stay resident.

- The read hands pages back to the kernel as it passes them.
- So a capture larger than RAM costs the same working set as a small one.
- This paragraph used to compare each row against the same sweep on 0.5.104.
  That table has never appeared on this page, so no reader could resolve the comparison.
  This page drops it rather than repeating it.

## Reproduce

Full instructions, including artifact download and checksum verification, are in
[`bench/README.md`](../bench/README.md). In short — the generator runs first,
because both harnesses read the corpus it writes:

```sh
# Run all of these, in order.
python3 bench/carrier.py --calls 5000 --out corpus.pcap
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
```

A single timed run at four cores, with the per-message stream suppressed so
only the end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```
