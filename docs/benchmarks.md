# Benchmarks

How fast sipnab is, measured honestly. Every number here is reproducible, and
as of 0.5.47 that is a checked claim rather than an asserted one: the corpus
generator and the timing harness are in [`bench/`](../bench/), so you can
regenerate the corpus and re-run every table below.

> **Last measured against 0.5.47, on 2026-07-27. This page does not track the
> current release.** Every table below is that measurement; nothing here has
> been re-run since. If you are reading this on a later release — and you are,
> unless you pinned 0.5.47 — treat these as the most recent *verified* figures
> rather than as figures for the binary you are holding. That distinction is
> the whole point of the A/B section further down: it is what "the numbers
> carried forward" used to mean here before anyone checked, and re-checking it
> is three commands ([Reproduce](#reproduce)). No number on this page has been
> adjusted to stand in for a release it was not measured on.

They were not, before. From 0.5.18 to 0.5.46 this page said the listed commands
were "the full recipe" while the generator lived in an unpublished repository —
nobody could re-run these numbers, including on the reference host named below.
The generator was rewritten from the documented corpus parameters and now
reproduces every one of them exactly (535,000 packets, 35,000 SIP messages,
500,000 RTP, 93.5% RTP, 100 Call-IDs, 200 streams).

**Measured on the released 0.5.47 artifact, checksum-verified, 2026-07-27, on
an idle host.** Numbers on this page are not comparable to the pre-0.5.47
figures: they came from the old unpublished corpus, and while the new
one matches its documented composition exactly it is not byte-identical. Where
the two differ, the corpus differs — see the A/B below, which separates the two
causes rather than guessing between them.

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
- **Version:** sipnab 0.5.47 (release artifact). **Date:** 2026-07-27.

## Multi-core offline reconstruction

`--cores N` shards by host-pair across worker threads. On the 535k-packet
fixed-state corpus (100 Call-IDs, 200 streams):

| cores | pkts/s |
|------:|-------:|
| 1 | 1.06M |
| 2 | **2.32M** |
| 4 | 2.03M |
| 8 | 1.89M |

The plateau past 2 cores is the single sequential pcap reader (read + buffer
copy + host-pair peek), not the core count. Before v0.4.16 a per-packet
cross-core hand-off collapsed this to 0.84M @ 4 cores and 0.50M @ 8. Batching
the hand-off removed the regression.

## Is the packet path still what it was at 0.5.18?

This page used to assert that the numbers carried forward because "the current
release changes no packet-path code versus 0.5.18". Nobody ever checked it, and
the version number in the sentence moved release after release.

Someone has now checked. Both release artifacts, both checksum-verified, run
against the identical corpus on the same idle host in the same session:

| cores | 0.5.18 | 0.5.47 | delta |
|------:|-------:|-------:|------:|
| 1 | 1.06M | 1.06M | 0.0% |
| 2 | 2.37M | 2.32M | −2.1% |
| 4 | 2.08M | 2.03M | −2.4% |
| 8 | 1.96M | 1.89M | −3.6% |

Three interleaved replicates at 2 and 8 cores put that delta inside the noise
floor: 0.5.47 measured 2.32 / 2.33 / 2.36M at 2 cores against 0.5.18's 2.37 /
2.42 / 2.34M, so the between-version gap (~2%) is smaller than the
within-version spread (~3.4%), and one replicate has 0.5.47 ahead. **Twenty-nine
releases on, throughput holds within measurement noise.** The judgement
this page carried for a year happens to have been correct — but it is now a
measurement, and re-checking it is three commands.

**And the same trap is open again, which is worth stating rather than
quietly re-opening.** This A/B spans 0.5.18 → 0.5.47 and was run on 2026-07-27.
It says nothing about anything released since; releases after 0.5.47 have
changed capture-path defaults (the kernel ring buffer moved 2 → 64 MiB, and
`poll(2)` came out of the per-packet path), so there is a live reason to expect
movement — in either direction — that nobody has measured. Do **not** restate
the sentence above with a higher version number in it. Re-run the A/B against
the current release artifact and publish what comes back, or leave the claim
where its evidence is: **0.5.47, 2026-07-27**.

The same A/B settles what the pre-0.5.47 tables mean. 0.5.18 measures 1.06M
single-core here against the 1.20M this page published for it — same binary,
same host, different corpus. The gap between old and new tables is the corpus,
not a regression.

## Tool comparison

Same 535k-packet corpus, every tool driven offline/headless to parse the whole
file and exit (median-of-5). The **what it reconstructs** column is the point —
a throughput number only means something next to the work behind it.

| tool | pkts/s | × sngrep | what it reconstructs |
|---|---:|---:|---|
| sngrep 1.8.0 | 0.19M | 1.0× | SIP dialogs; no RTP-stream reconstruction headless |
| sipgrep 2.2.1 | 2.19M | 11.8× | grep-style SIP line match + Call-ID grouping; **no RTP** |
| voipmonitor 2026.07.1 | 0.40M | 2.2× | full call/CDR + RTP-stream association |
| **sipnab 0.5.47 `--cores 1`** | 1.04M | **5.6×** | SIP dialogs + **200 RTP streams** |
| **sipnab 0.5.47 `--cores 4`** | 2.06M | **11.1×** | identical full SIP + RTP reconstruction |

Read it in three buckets:

- **Grep-class (sipgrep)** posts the fastest single number but does the least —
  line-oriented SIP matching with **no RTP work at all** (it never associates
  the 500k RTP packets into streams). Its lead is mostly "it does less."
- **Full reconstruction (sngrep, voipmonitor, sipnab)** parse SIP into dialogs;
  voipmonitor and sipnab additionally associate RTP into media streams.
- Within that class **sipnab leads**: single-core is **5.6× sngrep and 2.6×
  voipmonitor**, four-core is **11.1× sngrep and 5.1× voipmonitor** — and
  four-core lands within 6% of grep-only sipgrep's wall-clock (0.259 s vs
  0.245 s) *while also reconstructing all 200 RTP streams*. There is no
  configuration where sipnab is the slowest at comparable work.

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
| 500 | 53.5k | 500 | 1,000 | 1.56M | 18.6 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 1.84M | 53.4 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 1.93M | 192.9 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 1.94M | 448.2 MiB |

**Honest read:** throughput is flat from 2k calls up — reconstruction cost is
per-packet, not per-dialog, and 40k concurrent streams do not degrade it.
Memory grows close to linearly with tracked state, about 22 KiB per call
(dialog + two RTP streams + jitter/loss accounting), reaching 448 MiB at 20k
calls. That linearity is the useful property: it is predictable, so capacity
planning is arithmetic rather than guesswork.

Against voipmonitor on the same corpora, same method:

| calls | pkts | voipmonitor | sipnab | speed-up | RSS edge |
|------:|-----:|---|---|---:|---:|
| 500 | 53.5k | 0.12M p/s · 60.6 MiB | 1.56M p/s · 18.6 MiB | 12.6× | 3.3× |
| 2,000 | 214k | 0.29M p/s · 170.8 MiB | 1.84M p/s · 53.4 MiB | 6.4× | 3.2× |
| 8,000 | 856k | 0.45M p/s · 596.2 MiB | 1.93M p/s · 192.9 MiB | 4.3× | 3.1× |
| 20,000 | 2.14M | 0.50M p/s · 1455 MiB | 1.94M p/s · 448.2 MiB | 3.9× | 3.2× |

sipnab leads on throughput at every scale, but the lead *narrows* with volume —
12.6× at 500 calls down to 3.9× at 20,000 — because voipmonitor's multithreaded
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
`sdp_multiplication` guard does not suppress the corpus's duplicate-SDP streams:

```sh
voipmonitor -r corpus.pcap -c -k --config-file=bench/vm.conf
```

sipnab 0.5.47 at four cores, with the per-message stream suppressed so only the
end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```
