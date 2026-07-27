# Benchmarks

How fast sipnab is, measured honestly. Every number here is reproducible, and
as of 0.5.47 that is a checked claim rather than an asserted one: the corpus
generator and the timing harness are in [`bench/`](../bench/), so you can
regenerate the corpus and re-run every table below.

They were not, before. From 0.5.18 to 0.5.46 this page said the listed commands
were "the full recipe" while the generator lived in an unpublished repository —
nobody could re-run these numbers, including on the reference host named below.
The generator was rewritten from the documented corpus parameters and now
reproduces every one of them exactly (535,000 packets, 35,000 SIP messages,
500,000 RTP, 93.5% RTP, 100 Call-IDs, 200 streams).

**Measured on the released 0.5.47 artifact, checksum-verified, 2026-07-27, on
an idle host.** Numbers on this page are not comparable to the pre-0.5.47
figures: those were measured on the old unpublished corpus, and while the new
one matches its documented composition exactly it is not byte-identical. Where
the two differ, the corpus differs — see the A/B below, which separates the two
causes rather than guessing between them.

> **Read this first.** These tools do *different amounts of work*, so a raw
> throughput number only means something next to *what was reconstructed*.
> `sipgrep` is a grep-style line matcher; `sngrep` builds an interactive SIP
> ladder; voipmonitor produces full CDRs plus media spooling; sipnab does full
> SIP dialog **and** RTP-stream reconstruction with per-stream codec / jitter /
> loss. sipnab is generally doing *more* reconstruction than the tool it is
> being compared against here, which strengthens rather than weakens the result.

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
cross-core hand-off collapsed this to 0.84M @ 4 cores and 0.50M @ 8; batching
the hand-off removed the regression.

## Is the packet path still what it was at 0.5.18?

This page used to assert that the numbers carried forward because "the current
release changes no packet-path code versus 0.5.18". Nobody ever checked it, and
the version number in the sentence was advanced release after release.

It has now been checked. Both release artifacts, both checksum-verified, run
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
releases on, throughput is unchanged within measurement noise.** The judgement
this page carried for a year happens to have been correct — but it is now a
measurement, and re-checking it is three commands.

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
| sipgrep 2.2.1 | 2.32M | 12.5× | grep-style SIP line match + Call-ID grouping; **no RTP** |
| **sipnab 0.5.47 `--cores 1`** | 1.09M | **5.9×** | SIP dialogs + **200 RTP streams** |
| **sipnab 0.5.47 `--cores 4`** | 2.05M | **11.0×** | identical full SIP + RTP reconstruction |

Read it in two buckets:

- **Grep-class (sipgrep)** posts the fastest single number but does the least —
  line-oriented SIP matching with **no RTP work at all** (it never associates
  the 500k RTP packets into streams). Its lead is mostly "it does less."
- **Full reconstruction (sngrep, sipnab)** parse SIP into dialogs; sipnab
  additionally associates RTP into 200 media streams. Within that class sipnab
  is **5.9× sngrep single-core and 11.0× at four cores**, and four-core lands
  within 13% of grep-only sipgrep's wall-clock (0.261 s vs 0.231 s) *while also
  reconstructing every RTP stream*.

> **voipmonitor was not re-measured.** It is not installed on the reference
> host and is not packaged for it, so a source build pulling in a database
> service would be required. Its previously published figures (0.73M pkts/s
> here, and the memory sweep below) were measured on 2026-06-24 against the old
> corpus and are **not** carried into the tables above — a comparison whose
> competitor is absent is not a comparison. `bench/compare.sh` reports it as
> `MISSING` rather than skipping it quietly, and will measure it if you have it.

> **Fairness notes.** The corpus is synthetic and reuses SDP media endpoints, so
> voipmonitor's default `sdp_multiplication=3` DoS-guard would suppress the
> duplicate-SDP streams; set it to `0` so voipmonitor does full RTP association
> on equal footing. All tools parsed the same file to EOF. sngrep and sipgrep
> report dialogs grouped by the 100 unique Call-IDs while sipnab reports the
> finer 35k messages / 200 streams — a reporting-depth difference, not a
> correctness one.

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

Getting this measurement right requires the unbounded pools. Run the sweep with
the default bounded pools and RSS tops out around 123 MiB at 20k calls, because
state is capped at 100 dialogs regardless of call count — that measures buffer
memory and mislabels it as state growth.

## Reproduce

Full instructions, including artifact download and checksum verification, are in
[`bench/README.md`](../bench/README.md). In short:

```sh
python3 bench/carrier.py --calls 5000 --out corpus.pcap
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
bench/compare.sh "$BIN" corpus.pcap 535000 --runs 5
```

Each tool driven offline/headless to parse the whole file and exit:

```sh
sngrep       sngrep  -I corpus.pcap -r -N -q
sipgrep      sipgrep -I corpus.pcap -C -G
voipmonitor  voipmonitor -r corpus.pcap -c -k --config-file=vm.conf   # sdp_multiplication=0, save_*=no
sipnab       sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```
