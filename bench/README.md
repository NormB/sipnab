# Benchmark harness

Everything needed to reproduce the numbers on the [benchmarks
page](../docs/benchmarks.md). Nothing here depends on a private repository.

That is the point of this directory. For twenty-nine releases the benchmarks
page claimed "every number here is reproducible … the exact commands above are
the full recipe" while the corpus generator and comparison harness lived in an
unpublished internal repo. Nobody could re-run those numbers — not even on the
reference host named in the methodology. These three scripts are that missing
recipe.

## Contents

| script | what it does |
|---|---|
| `carrier.py` | generates the synthetic carrier corpus (stdlib Python 3, no deps) |
| `scaling.sh` | sipnab throughput + peak RSS across `--cores` values |
| `compare.sh` | sipnab against sngrep / sipgrep / voipmonitor on one corpus |

## Reproducing the published tables

Benchmarks are measured against a **checksum-verified release artifact**, never
a local dev build, on an otherwise idle host:

```sh
gh release download v0.5.47 -R NormB/sipnab \
  -p 'sipnab-0.5.47-aarch64-unknown-linux-gnu.tar.gz*'
sha256sum -c sipnab-0.5.47-aarch64-unknown-linux-gnu.tar.gz.sha256
tar xzf sipnab-0.5.47-aarch64-unknown-linux-gnu.tar.gz
BIN=./sipnab-0.5.47-aarch64-unknown-linux-gnu/sipnab
```

**Multi-core scaling** and the **tool comparison** use the fixed-state corpus —
a bounded pool of 100 Call-IDs and 200 RTP streams, so dialog state stays
constant and the measurement isolates the packet path:

```sh
python3 bench/carrier.py --calls 5000 --out corpus.pcap
# 535000 packets (35000 SIP, 500000 RTP = 93.5%), 100 Call-IDs, 200 streams

bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
bench/compare.sh "$BIN" corpus.pcap 535000 --runs 5
```

**The carrier sweep** uses unique dialogs per call (`--call-ids 0
--stream-pairs 0`), because a memory sweep has to let state grow with call
volume. With the bounded pools it measures buffer memory and mislabels it as
state growth:

```sh
for c in 500 2000 8000 20000; do
  python3 bench/carrier.py --calls $c --call-ids 0 --stream-pairs 0 \
    --out sweep-$c.pcap
done
bench/scaling.sh "$BIN" sweep-20000.pcap 2140000 --cores 4 --runs 5
```

## Method

- **median-of-5 after one discarded warmup**, so the corpus is in page cache for
  every timed run
- wall clock from a nanosecond clock, not `time -f %e` — the latter resolves to
  10 ms, which on a sub-second corpus is two significant figures
- peak RSS from GNU `time -f %M`
- `pkts/s = packets ÷ wall-clock seconds`, startup included
- output is deterministic: same arguments in, byte-identical pcap out

## voipmonitor

`compare.sh` reports voipmonitor as `MISSING` unless it is installed *and*
`VM_CONF` points at a config file. It is never silently skipped — a comparison
table with an absent competitor reads exactly like a comparison it won.

voipmonitor needs `sdp_multiplication=0` on this corpus. The corpus reuses SDP
media endpoints, so voipmonitor's default DoS guard (`=3`) suppresses the
duplicate-SDP streams and it does less RTP association than sipnab, which would
flatter sipnab's numbers.
