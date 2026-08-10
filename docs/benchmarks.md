# Benchmarks

How fast sipnab is, measured honestly. Every number here is reproducible, and
as of 0.5.47 that is a checked claim rather than an asserted one: the corpus
generator and the timing harness are in [`bench/`](../bench/), so you can
regenerate the corpus and re-run every table below.

> **Measured against 0.5.91, on 2026-08-10.** Every table below is that
> measurement, taken on the released artifact rather than a local build. The
> previous version of this page carried 0.5.47 figures from 2026-07-27 and said
> so; re-running them is what found the regression the
> [A/B section](#is-the-packet-path-still-what-it-was-at-0547) now documents,
> which had been shipping unnoticed for four releases. No number here has been
> adjusted to stand in for a release it was not measured on, and none has been
> carried forward from a run nobody repeated.

They were not, before. From 0.5.18 to 0.5.46 this page said the listed commands
were "the full recipe" while the generator lived in an unpublished repository —
nobody could re-run these numbers, including on the reference host named below.
The generator was rewritten from the documented corpus parameters and now
reproduces every one of them exactly (535,000 packets, 35,000 SIP messages,
500,000 RTP, 93.5% RTP, 100 Call-IDs, 200 streams).

**Measured on the released 0.5.91 artifact, checksum-verified, 2026-08-10, on
an idle host.** Comparable to the 0.5.47 figures this page carried before:
the corpus generator still reproduces the same composition
(535,000 packets, 35,000 SIP, 500,000 RTP, 100 Call-IDs, 200 streams), and
0.5.47 was re-measured on the same host in the same session as a control — it
reproduced its published tables within noise twelve days on. Neither set is
comparable to the pre-0.5.47 figures, which came from an unpublished corpus
nobody can rebuild.

> **Read this first.** These tools do *different amounts of work*, so a raw
> throughput number only means something next to *what came back out*.
> `sipgrep` is a grep-style line matcher; `sngrep` builds an interactive SIP
> ladder; voipmonitor produces full CDRs plus media spooling; sipnab does full
> SIP dialog **and** RTP-stream reconstruction with per-stream codec / jitter /
> loss. sipnab is generally doing *more* reconstruction than the tool it is
> this comparison uses, which strengthens rather than weakens the result.

## Test host & method

- **Host:** NVIDIA Jetson Thor devboard (aarch64), 14 cores, PREEMPT_RT
  kernel, idle. (A 4-vCPU VM is not used for throughput numbers.)
- **Corpus:** `bench/carrier.py` — N concurrent calls, each
  `INVITE → 100 → 180 → 200 → ACK → [bidirectional RTP] → BYE → 200`,
  G.711 PCMU at 20 ms, 93.5% RTP by packet count.
- **Method:** offline pcap reconstruction (`-I file`), median-of-5 after one
  discarded warmup. `pkts/s = packets ÷ wall-clock seconds`, startup included.
- **Version:** sipnab 0.5.91 (release artifact). **Date:** 2026-08-10.

## Multi-core offline reconstruction

`--cores N` shards by host-pair across worker threads. On the 535k-packet
fixed-state corpus (100 Call-IDs, 200 streams):

| cores | pkts/s |
|------:|-------:|
| 1 | 1.07M |
| 2 | 2.21M |
| 4 | **2.32M** |
| 8 | 2.13M |

**The peak moved from 2 cores to 4, and that is the fix showing up.**
Through 0.5.88 the reader computed the frame-provenance digest on the single
sequential stage that already sets this ceiling (read + buffer copy +
host-pair peek), so adding work there capped every core count at once.
0.5.89 moved it to the workers, which is why more workers help: at 2
cores there are two to absorb it and at 4 there are four. Before v0.4.16 a
per-packet cross-core hand-off collapsed this to 0.84M @ 4 cores and 0.50M @ 8.
Batching the hand-off removed that one.

## Is the packet path still what it was at 0.5.47?

No — it is **faster**. Throughput fell 40% in 0.5.84 and held that loss for
four releases. 0.5.89 recovered part of it, and 0.5.91 went past where it
started.

The previous version of this section concluded "twenty-nine releases on,
throughput holds within measurement noise", and closed by telling the reader
**not** to restate it with a higher version number — to re-run the A/B or leave
the claim where its evidence was. Re-running it is what found this. Had the
sentence been re-dated instead, the regression would still be shipping.

Both artifacts checksum-verified, identical corpus, same idle host, same
session, **interleaved** replicates so drift in the host cannot masquerade as a
difference between versions:

| cores | 0.5.47 | 0.5.88 | 0.5.89 | 0.5.91 | 0.5.91 vs 0.5.47 |
|------:|-------:|-------:|-------:|-------:|-----------------:|
| 1 | 1.06M | 0.91M | 0.96M | 1.07M | +1% |
| 2 | 2.27M | 1.39M | 1.69M | 2.21M | −3% |
| 4 | 2.02M | 1.33M | 1.90M | **2.32M** | **+15%** |
| 8 | 1.91M | 1.29M | 1.73M | 2.13M | +12% |

Within-version spread is ~2% and the 0.5.47 → 0.5.88 gap is ~39%, so that gap
is roughly eighteen times the noise floor. In the same runs **voipmonitor
measured 0.40M in both arms, exactly** — an unrelated binary on the same corpus
on the same afternoon did not move, which is what rules out the host.

**What it was.** 0.5.84 added a frame-provenance stamp that fixed a real bug:
the parallel reader was silently dropping frame pointers on exactly the large
captures where provenance matters most. But it computed the digest on the
**serial reader**, the one stage the whole `--cores` design waits on — a single
thread reads, copies and host-pair-peeks every packet while N workers sit idle.
This page had already named that stage as the plateau past two cores. Hashing
there charged it ~240 bytes of dependent FNV multiplies per packet — 129 MB
hashed one byte at a time on this corpus.

**What 0.5.89 did.** The workers compute the digest. The reader still assigns
the ordinal, the one fact only it can know. Same input, same FNV-1a, same
value — a pointer from a `--cores` run resolves identically to one from a
single-threaded run, and pointers already written down still resolve. Because
the work now scales with worker count, the recovery does too: **~81% of the
loss at four cores, ~34% at two.** Four cores is within 6% of 0.5.47.

**What 0.5.91 did, and why it overshot.** Two more changes, both from the same
profile. `parse_packet` stopped building a `FrameRef` per packet — a `FrameRef`
owns an `Arc<str>`, so each one cost an atomic pair for a pointer ~93% of
frames never keep. The reader also stopped allocating each frame separately:
it now cuts them from a shared 64 KiB block, so the allocator's cross-thread
free path runs once per ~270 frames instead of once per frame.

Together those put four-core throughput **above where it was before the
regression** — 2.32M against 0.5.47's 2.02M. The second change even beat its
own predicted ceiling, because frames sharing a block are also sequential in
memory, which a diagnostic that scattered them into an arena could not show.

**What is still wrong, stated rather than left for the next re-run to find.**
sipnab hashes every frame when only a *retained* pointer needs a digest — a dialog's `first_frame`, a stream's `first_frame`, a finding's
`frame_ref` — which on this corpus is about 35,000 of 535,000 frames. A
diagnostic build with the digest removed entirely measures 2.05M at two cores
against 0.5.83's 2.33M, so roughly 12% of the original regression is *not* the
digest at all and remains unidentified. Both are PERF1 in
`docs/design/backlog.md`, together with the two obvious fixes and the tests
that already reject each.

**And the same trap is open again.** This A/B spans 0.5.47 → 0.5.91, measured
on 2026-08-10. It says nothing about anything released after. Do not restate it
with a higher version number: re-run it, or leave the claim where its evidence
is.

**Nothing in CI measures throughput.** A 40% regression shipped four times
because the only thing that would have caught it was a page nobody re-ran.

The same A/B settles what the pre-0.5.47 tables mean. 0.5.18 measured 1.06M
single-core against the 1.20M this page once published for it — same binary,
same host, different corpus. The gap between old and new tables is the corpus,
not a regression.

## Tool comparison

Same 535k-packet corpus, every tool driven offline/headless to parse the whole
file and exit (median-of-5). The **what it reconstructs** column is the point —
a throughput number only means something next to the work behind it.

| tool | pkts/s | × sngrep | what it reconstructs |
|---|---:|---:|---|
| sngrep 1.8.0 | 0.19M | 1.0× | SIP dialogs; no RTP-stream reconstruction headless |
| sipgrep 2.2.1 | 2.17M | 11.4× | grep-style SIP line match + Call-ID grouping; **no RTP** |
| voipmonitor 2026.07.1 | 0.40M | 2.1× | full call/CDR + RTP-stream association |
| **sipnab 0.5.91 `--cores 1`** | 1.06M | **5.6×** | SIP dialogs + **200 RTP streams** |
| **sipnab 0.5.91 `--cores 4`** | 2.31M | **12.2×** | identical full SIP + RTP reconstruction |

Read it in three buckets:

- **Grep-class (sipgrep)** posts the fastest single number but does the least —
  line-oriented SIP matching with **no RTP work at all** (it never associates
  the 500k RTP packets into streams). Its lead is mostly "it does less."
- **Full reconstruction (sngrep, voipmonitor, sipnab)** parse SIP into dialogs;
  voipmonitor and sipnab additionally associate RTP into media streams.
- Within that class **sipnab leads**: single-core is **5.6× sngrep and 2.6×
  voipmonitor**, four-core is **12.2× sngrep and 5.8× voipmonitor**. There is no
  configuration where sipnab is the slowest at comparable work.
- **And four-core sipnab is now faster than grep-only sipgrep** — 2.31M against
  2.17M, 0.2315 s against 0.2461 s — *while also reconstructing all 200 RTP
  streams that sipgrep never touches*. That ordering is new. Every previous
  measurement on this page had sipgrep ahead, and the note under it said its
  lead was mostly "it does less". It still does less; it is no longer faster
  for it.

> **How voipmonitor ran.** No package exists for the reference host, so it
> builds from source in a container
> ([`bench/voipmonitor.Dockerfile`](../bench/voipmonitor.Dockerfile)) rather
> than installed onto the machine. Two things make that fair. Its timing loop
> runs *inside* a single container, because timing `docker run` would charge it
> ~0.8 s of container startup per invocation — on this corpus that is longer
> than sipnab's entire run, and would have manufactured a multiple-fold win out
> of nothing. And the config disables spooling, not analysis: re-running with
> `savesip`/`savertp` on confirms voipmonitor emits one SIP and one RTP capture
> per call, each containing both directions of the stream, so it really is doing
> the RTP association this table credits it with.
>
> The remaining asymmetry is that voipmonitor runs containerised while the other
> three run natively. On Linux that is namespaces rather than virtualisation, so
> CPU-bound parsing is essentially native speed — but it is not nothing, and it
> is voipmonitor's number that would carry any cost.

> **Fairness notes.** The corpus is synthetic and reuses SDP media endpoints, so
> voipmonitor's default `sdp_multiplication=3` DoS-guard would suppress the
> duplicate-SDP streams; `bench/vm.conf` sets it to `0` so voipmonitor does full
> RTP association on equal footing. All tools parsed the same file to EOF.
> sngrep and sipgrep report dialogs grouped by the 100 unique Call-IDs while
> sipnab reports the finer 35k messages / 200 streams — a reporting-depth
> difference, not a correctness one.

## Throughput and memory at carrier scale

The table above is one operating point at fixed dialog state. This sweep grows
the state: unique Call-IDs and unique RTP endpoints per call
(`--call-ids 0 --stream-pairs 0`), so dialog and stream tables scale with call
volume. Measured at `--cores 4`:

| calls | pkts | dialogs | streams | pkts/s | peak RSS |
|------:|-----:|--------:|--------:|-------:|---------:|
| 500 | 53.5k | 500 | 1,000 | 1.52M | 21.0 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 1.69M | 55.4 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 1.70M | 205.6 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 1.75M | 460.6 MiB |

**Honest read:** throughput is flat from 2k calls up — reconstruction cost is
per-packet, not per-dialog, and 40k concurrent streams do not degrade it.
Memory grows close to linearly with tracked state, about 23 KiB per call
(dialog + two RTP streams + jitter/loss accounting), reaching 461 MiB at 20k
calls. That linearity is the useful property: it is predictable, so capacity
planning is arithmetic rather than guesswork.

Against voipmonitor on the same corpora, same method:

| calls | pkts | voipmonitor | sipnab | speed-up | RSS edge |
|------:|-----:|---|---|---:|---:|
| 500 | 53.5k | 0.13M p/s · 58.2 MiB | 1.52M p/s · 21.0 MiB | 11.7× | 2.8× |
| 2,000 | 214k | 0.29M p/s · 167.6 MiB | 1.69M p/s · 55.4 MiB | 5.8× | 3.0× |
| 8,000 | 856k | 0.42M p/s · 594.0 MiB | 1.70M p/s · 205.6 MiB | 4.0× | 2.9× |
| 20,000 | 2.14M | 0.48M p/s · 1451.9 MiB | 1.75M p/s · 460.6 MiB | 3.6× | 3.2× |

voipmonitor's own numbers land within noise of what this page published for it
on 2026-07-27 (0.48M vs 0.50M, 1451.9 vs 1455 MiB at 20k calls). An unrelated
binary reproducing its figures on the same host twelve days later is what makes
the sipnab column's movement attributable to sipnab.

sipnab leads on throughput at every scale, but the lead *narrows* with volume —
11.7× at 500 calls down to 3.6× at 20,000 — because voipmonitor's multithreaded
per-packet throughput climbs with scale (0.12M → 0.50M) while sipnab's is
already flat. Extrapolating that trend past the measured range would be
guesswork, so it is not done here.

**This corrects a claim in sipnab's favour that no longer holds.** The page
previously advertised a ~9.2× memory advantage at 20k calls. Measured against
voipmonitor 2026.07.1 it is **~3.2×**, and remarkably steady across the whole
sweep. voipmonitor's own footprint is far below what this page used to report
for it (1.46 GiB at 20k calls against a published 4.7 GiB). The old figure came
from an older voipmonitor on a corpus nobody can rebuild, so the two are not
strictly comparable — but the published figure claimed a 9.2× advantage, and it is 3.2× when
measured, and the smaller number is the one with a recipe attached.

Getting this measurement right requires the unbounded pools. Run the sweep with
the default bounded pools and RSS tops out around 123 MiB at 20k calls, because
state stops at 100 dialogs regardless of call count — that measures buffer
memory and mislabels it as state growth.

## Reproduce

Full instructions, including artifact download and checksum verification, are in
[`bench/README.md`](../bench/README.md). In short — the generator runs first,
because both harnesses read the corpus it writes:

```sh
# Run all of these, in order.
python3 bench/carrier.py --calls 5000 --out corpus.pcap
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
VM_IMAGE=voipmonitor:bench VM_CONF=bench/vm.conf \
  bench/compare.sh "$BIN" corpus.pcap 535000 --runs 5
```

The tool comparison is four separate runs over the same `corpus.pcap`, each
driven offline/headless so it parses the whole file and exits. Run them one at
a time: two of these competing for the same cores measures the contention, not
the tools.

sngrep 1.8.0, reading the file to EOF and quitting instead of opening its
interactive ladder:

```sh
sngrep  -I corpus.pcap -r -N -q
```

sipgrep 2.2.1, line-oriented SIP matching with Call-ID grouping and no RTP work
at all:

```sh
sipgrep -I corpus.pcap -C -G
```

voipmonitor 2026.07.1, pointed at `bench/vm.conf` so spooling is off and the
`sdp_multiplication` guard does not suppress the corpus's duplicate-SDP
streams. **This is the command `compare.sh` runs, not one you can run here**:
voipmonitor is not packaged for the reference host, so it comes from the
container built by `bench/voipmonitor.Dockerfile` and the run needs
`VM_IMAGE`/`VM_CONF` as shown above. Without them `compare.sh` reports
voipmonitor as `MISSING` and excludes the row rather than quietly shipping a
comparison with an absent competitor:

```sh
voipmonitor -r corpus.pcap -c -k --config-file=bench/vm.conf
```

sipnab 0.5.91 at four cores, with the per-message stream suppressed so only the
end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```
