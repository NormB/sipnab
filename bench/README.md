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
# Run all of these, in order.
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
# Run all of these, in order.
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
# Run all of these, in order.
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

voipmonitor is not packaged for most distributions and a host install pulls in
a database service, so it is built from source in a container:

```sh
# Run all of these, in order.
docker build -f bench/voipmonitor.Dockerfile -t voipmonitor:bench bench/
VM_IMAGE=voipmonitor:bench VM_CONF=bench/vm.conf \
  bench/compare.sh "$BIN" corpus.pcap 535000 --runs 5
```

`compare.sh` uses a native `voipmonitor` if one is on `PATH`; otherwise it uses
`VM_IMAGE`. With neither, it reports voipmonitor as `MISSING` rather than
omitting the row — a comparison table with a silently absent competitor reads
exactly like a comparison it won.

Three things keep the container measurement fair, and all three matter:

- **The timing loop runs inside one container.** Timing `docker run` per
  invocation charges voipmonitor ~0.8 s of container startup, which on the 535k
  corpus is longer than sipnab's entire run. That alone would fabricate a
  several-fold sipnab win out of the measurement apparatus.
- **`sdp_multiplication = 0`.** The corpus reuses SDP media endpoints, so
  voipmonitor's default DoS guard (`=3`) suppresses the duplicate-SDP streams —
  it would do *less* RTP association than sipnab and flatter sipnab's numbers.
- **The config disables spooling, not analysis.** Verify this rather than trust
  it: re-run with `savesip`/`savertp` set to `yes` and a writable `spooldir`,
  and voipmonitor should emit one SIP and one RTP capture per call, each
  carrying both directions. sipnab itself will read those files back
  (`sipnab -N -I <spooled>.pcap --report`), which is a convenient cross-check.

What remains asymmetric: voipmonitor runs containerised while sngrep, sipgrep
and sipnab run natively. On Linux that is namespaces, not virtualisation, so
CPU-bound parsing is near native — but the cost, whatever it is, lands on
voipmonitor's number.
