# Benchmarks

How to measure sipnab's throughput and memory on your own capture, and the
reference results measured on one host.

- Use the how-to to size a deployment from your own traffic.
- Use the reference tables to compare your host against a known one.

The history of past regressions and the A/B sessions that measured them is in
[Profiling: Throughput history](internals/profiling.md#throughput-history).

## Measure sipnab on your own capture

You need the capture, a release build of sipnab, and GNU `time`
(`/usr/bin/time` on Linux, `gtime` from Homebrew on macOS). Run on an idle
host: other load on the machine shows up in the result.

### Time one run

```sh
/usr/bin/time -f '%e s elapsed, %M KiB peak RSS' sipnab -N -I capture.pcap --cores 4 --report --no-cli-print
```

`--report --no-cli-print` prints only the end-of-run report, so the time
measures reconstruction rather than terminal output. The report goes to
standard output and the measurements to standard error. The last lines of
standard error:

```text
… INFO sipnab::capture::file: Read 53500 packets: 1 of 1 file(s) read in full
… INFO sipnab::app::batch: sipnab: 53500 packets, 3500 SIP messages, 50000 RTP packets across 200 streams (4 cores)
0.32 s elapsed, 45376 KiB peak RSS
```

This example ran a debug build on a host that was 13% idle, against a
53,500-packet capture from `bench/carrier.py --calls 500`. The figures show the
format, not sipnab's throughput.

Divide the packet count by the elapsed time for packets per second: 53,500
packets in 0.32 s is about 0.17M packets per second.

### Compare core counts

From a checkout of the sipnab repository, [`bench/scaling.sh`](https://github.com/NormB/sipnab/blob/main/bench/scaling.sh) runs the same
measurement at several core counts, discards one warmup run, and reports the
median:

```sh
bench/scaling.sh "$BIN" capture.pcap --cores 1,4 --runs 3
```

Set `BIN` to the path of the sipnab binary. With no packet count given, the
script asks sipnab to count the packets first. Output, from the same debug
build and capture as above:

```text
binary:  sipnab 0.5.222 (16f7b0ea) features: native,tui,audio,metrics
corpus:  capture.pcap (53500 packets)
method:  median-of-3 after 1 discarded warmup
host:    Linux aarch64, 14 cores

cores      pkts/s    wall(s)   RSS(MiB)       runs
------ ---------- ---------- ---------- ----------
1           0.06M     0.8373       44.0          3
4           0.17M     0.3170       43.7          3
```

Pick the core count with the highest `pkts/s`. On the reference host, four
cores is faster than eight. See [Multi-core offline reconstruction](#multi-core-offline-reconstruction).

### Estimate memory for a larger capture

Peak memory grows with the number of calls the capture holds, at about
27 KiB per call on the reference corpus (a dialog, two RTP streams, and their
jitter and loss accounting). The [carrier-scale table](#throughput-and-memory-at-carrier-scale)
gives measured points from 500 to 20,000 calls.

## What the throughput is for

The throughput decides how much traffic one sipnab process can take, and
therefore whether you need a collector tier.

- Kamailio, OpenSIPS and Asterisk send HEP copies of their signaling to one
  sipnab listener, so one process can answer for many proxies.
- A proxy running 100 calls per second at roughly ten SIP messages per call
  emits about 1,000 signaling packets per second.
- The reference tables below measure 1.18M packets per second on one core and
  3.52M on four, on a corpus that is 93.5% RTP. A signaling-only HEP feed
  carries no RTP.

Two limits on that arithmetic:

- The tables measure offline pcap reconstruction, not the HEP receive path.
  Read the ratio as a budget, not as a measured HEP ceiling.
- [`--hep-rate-limit`](cli-reference.md#network-listeners) caps what a HEP
  listener accepts. Its default is 50,000 packets per second, well below these
  tables. Size a HEP deployment against that setting.

## What the throughput includes

On the reference corpus, while it posts the figures below, sipnab:

- parses every SIP message into dialogs, with state, timing and PDD,
- associates all 500,000 RTP packets into **200 media streams**, each with its
  codec, jitter, loss and MOS,
- mints frame pointers for anything a report can cite later, so you can
  resolve a finding back to the captured bytes.

That is full reconstruction, not line matching. A tool that only searches SIP
text does a fraction of this work and posts a larger raw number for that reason.

## Test host & method

**Measured on a local release build of 0.5.211 (`15e5e7bd`), 2026-10-11, on an idle host.**

- **Host:** NVIDIA Jetson Thor devboard (aarch64), 14 cores, PREEMPT_RT
  kernel. `vmstat` showed the host 99% idle before every run, with no CI job
  or toolchain build running.
- **Corpus:** [`bench/carrier.py`](https://github.com/NormB/sipnab/blob/main/bench/carrier.py) — N concurrent calls, each
  `INVITE → 100 → 180 → 200 → ACK → [bidirectional RTP] → BYE → 200`,
  G.711 PCMU at 20 ms. At `--calls 5000` it writes 535,000 packets:
  35,000 SIP messages and 500,000 RTP (93.5%), across 100 Call-IDs and 200 streams.
- **Method:** offline pcap reconstruction (`-I file`), median-of-5 after one
  discarded warmup. `pkts/s = packets ÷ wall-clock seconds`, startup included.
- **Version:** sipnab 0.5.211, local release build `15e5e7bd` (main after
  the v0.5.211 tag), with every feature.
- **Published figure:** the LOWEST of three replicates, per core count.
  The peak RSS cell is the HIGHEST of the three, the figure to plan memory against.
  [`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json)
  records every replicate.

## Multi-core offline reconstruction

`--cores N` shards packets by host pair across N worker threads. On the
535k-packet corpus (100 Call-IDs, 200 streams), with three replicates per row:

| cores | pkts/s | replicates | peak RSS |
|------:|-------:|-----------:|---------:|
| 1 | 1.18M | 1.18 / 1.18 / 1.18M | 168.4 MiB |
| 2 | 2.57M | 2.59 / 2.57 / 2.60M | 107.9 MiB |
| 4 | **3.52M** | 3.56 / 3.56 / 3.52M | 103.4 MiB |
| 8 | 3.15M | 3.15 / 3.16 / 3.17M | 107.0 MiB |

- Four cores is the peak. Eight is slower in every replicate.
- One core uses the most memory: 168.4 MiB, against about 105 MiB on two or
  more cores.

The nightly throughput gate measures against the four-core figure.

## Throughput and memory at carrier scale

This sweep gives every call a unique Call-ID and unique RTP endpoints
(`--call-ids 0 --stream-pairs 0`), so the dialog and stream tables grow with
the call count. Measured at `--cores 4`, in the same session and on the same
host as the table above:

| calls | pkts | dialogs | streams | pkts/s | peak RSS |
|------:|-----:|--------:|--------:|-------:|---------:|
| 500 | 53.5k | 500 | 1,000 | 2.08M | 33.5 MiB |
| 2,000 | 214k | 2,000 | 4,000 | 2.74M | 73.6 MiB |
| 8,000 | 856k | 8,000 | 16,000 | 3.05M | 233.2 MiB |
| 20,000 | 2.14M | 20,000 | 40,000 | 3.06M | 531.1 MiB |

- Throughput is flat from 8,000 calls up. Reconstruction cost is per packet,
  not per dialog, and 40,000 concurrent streams do not reduce it.
- The smaller captures post lower figures because startup time is inside the
  measurement. A 53.5k-packet read finishes in about 26 ms.
- Memory grows close to linearly with tracked state, about 27 KiB per call,
  reaching 531 MiB at 20,000 calls.
- sipnab returns the pages of the capture file to the kernel as it reads past
  them, so a capture larger than RAM does not need a larger working set than
  a small one.

Repeated sessions on the same host differ by more than the replicates within
one session. Compare your results with these tables as a range, not to the
digit.

## Reproduce

Full instructions, including artifact download and checksum verification, are in
[`bench/README.md`](https://github.com/NormB/sipnab/blob/main/bench/README.md).
The generator runs first, because both harnesses read the corpus it writes:

```sh
# Run all of these, in order.
python3 bench/carrier.py --calls 5000 --out corpus.pcap
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
```

`carrier.py` prints the composition it wrote, for example at `--calls 500`:

```text
capture.pcap: 53500 packets (3500 SIP, 50000 RTP = 93.5%), 500 calls, 100 unique Call-IDs, 200 RTP streams
```

A single timed run at four cores, with the per-message output suppressed so
only the end-of-run report prints:

```sh
sipnab -N -I corpus.pcap --cores 4 --report --no-cli-print
```
