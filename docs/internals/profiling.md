# Profiling

How to find out where sipnab's time actually goes, on this hardware, without
guessing.

This page exists because one 40% throughput regression got diagnosed twice.

- First by bisecting release artifacts and reading diffs.
- Then by profiling.
- The two answers disagreed, and the profiler was right.
- Bisection tells you *which commit* changed the number.
- Only a profiler tells you *what the machine is doing*.
- Those are different questions.

## Get a binary worth profiling

`[profile.release]` sets `strip = true`.

- So a release binary has no symbols.
- A profile of it is a wall of hex.

Use the `profiling` profile instead.

- It inherits release, so the codegen is identical.
- It turns the symbols back on:

```toml
[profile.profiling]
inherits = "release"
strip = false
debug = true
panic = "unwind"
```

```sh
cargo build --features full --profile profiling
```

Never profile a debug build. It measures the absence of optimization.

## perf, and the trap on this box

`perf` is the right default tool. It is a sampling profiler.
So the overhead is a few percent, not the 20-50× a simulator costs.

**On the reference host, plain `perf` does not work and the error is
misleading.**

- The kernel is `6.8.12-rt-tegra`.
- The Debian wrapper looks for a perf matching that exact string.
- It fails, and prints

```
WARNING: perf not found for kernel 6.8.12-rt
```

That reads like "perf is not installed". It is.

- The wrapper cannot resolve the `-rt-tegra` suffix.
- The binary shipping alongside it is a perfectly good `perf 6.8.12`:

```sh
# Run all of these, in order.
PERF=/usr/lib/linux-tools/6.8.0-136-generic/perf
$PERF --version        # perf version 6.8.12
```

Use that path directly.

- `/proc/sys/kernel/perf_event_paranoid` is `2` here.
  - That allows user-space sampling — enough for everything below.
- Kernel-symbol profiling would need it lowered.
  - That has not been necessary.

### Recording

```sh
# Run all of these, in order.
PERF=/usr/lib/linux-tools/6.8.0-136-generic/perf
$PERF record --call-graph dwarf -F 999 -o p.data -- \
  target/profiling/sipnab -N -I corpus.pcap --cores 2 --report --no-cli-print
```

- `--call-graph dwarf`
  - Optimized aarch64 builds omit frame pointers.
  - So `fp` unwinding produces truncated stacks.
  - DWARF unwinding is slower to *report*.
  - But it is the only thing that gives usable callers here.
- `-F 999` — samples per second.
  - The default is often too coarse for a run that
    finishes in a third of a second.
- `--no-cli-print` — otherwise you profile the terminal writer.

**Sample count is the thing to check first.**

- A 0.3-second run at 499 Hz yields about 390 samples.
  - That is enough to see a 40% effect.
  - It is not enough to trust a 2% one.
- For anything finer, profile `sweep-20000.pcap` (2.14M packets, ~4×
  longer) or loop the run.
- [`bench/carrier.py`](../../bench/carrier.py) regenerates both corpora.
  See [`../../bench/README.md`](../../bench/README.md).

### Reporting

Flat profile, which is where to start:

```sh
$PERF report -i p.data --stdio --no-children --sort symbol -g none | head -20
```

`--no-children` reports *self* time.
Without it the top of the list is `main` and every wrapper above the real work.
That tells you nothing.

Callers of one symbol:

```sh
$PERF report -i p.data --stdio --no-children -S __aarch64_ldadd8_relax \
  -g graph,0.3,caller
```

**`perf report` on a DWARF profile of the large corpus can take longer than ten
minutes.** It unwinds every sample.

- When that happens, dump raw stacks once.
- Then post-process them yourself.
- That is far faster than repeated `report` calls:

```sh
$PERF script -i p.data > script.txt      # do this ONCE
# then group leaf-adjacent frames with awk/python
```

## Reading an aarch64 profile

Symbols like `__aarch64_ldadd8_relax`, `__aarch64_ldadd8_rel`,
`__aarch64_cas8_acq_rel` and `__aarch64_swp4_rel` are **outlined atomics**.

- They are the compiler's helper functions for atomic add, compare-and-swap and swap.
- They are not a library you called.
- They are refcounts, locks and allocator bookkeeping.

Seeing them high in a profile means the program is paying for *sharing*, not for
computing. On this codebase the usual sources are, in order:

- **Cross-thread allocation churn.**
  - One thread allocates and another frees.
  - So the allocator's cross-thread path runs on every packet.
  - mimalloc shows this as `mi_free`, `mi_free_try_collect_mt`, `mi_abandoned_page_try_reclaim` and
    `_mi_page_free_collect`.
- **`Arc` clones on a per-packet path.**
  - Each clone is one atomic increment.
  - Each drop is one decrement.
- **`bytes::Bytes` refcounts** — `shared_clone` and `shared_drop`.

An `Arc` clone costs a few nanoseconds.
That is nothing until it happens 535,000 times on the one thread everything else waits for.

## Rust-specific tools

| Tool | What it gives | When |
|---|---|---|
| `cargo flamegraph` | `perf` + an interactive SVG | Best first look; the SVG is shareable and readable without a terminal |
| `samply record ./binary` | Sampling profiler, Firefox Profiler UI in a browser | Easiest call-tree exploration; no `perf` invocation to get right |
| `perf` + Hotspot | Lowest overhead, GUI for `perf.data` | When you already have a `perf.data` and want to explore it |
| `pprof-rs` | In-process CPU profiler, integrates with criterion | Profiling one benchmark rather than a whole run |
| **valgrind `callgrind`** | Exact instruction counts, deterministic, no sampling noise | Comparing two builds where the difference is small enough that sampling noise hides it. 20-50× slowdown; use the small corpus |
| **valgrind `cachegrind`** | Cache-miss and branch-prediction simulation | When the profile is flat but the work is memory-bound |
| `dhat` / `heaptrack` / `bytehound` | Heap allocation sites, peak usage, leaks | When the allocator is hot — which, given the finding above, is the likely next question |
| `coz` (`coz-rs`) | Causal profiling: predicts the end-to-end speedup from optimizing a given function | When a pipeline has several hot spots and you need to know which one actually gates throughput |

The reference host carries `coz` and its `libcoz.so` runtime. It does not
carry valgrind (checked 2026-08-23).

**`coz` deserves a note.**

- A conventional profiler tells you where time goes.
- In a producer/consumer pipeline that misleads.
  - Speeding up a stage nobody waits on changes nothing.
- sipnab's `--cores` path is exactly that shape: one serial reader feeding N workers.
- So a causal profiler answers the question that matters:
  "if this got faster, would the program?"

Further reading: [The Rust Performance Book, "Profiling"
chapter](https://nnethercote.github.io/perf-book/profiling.html).

## Measuring the change, not just finding it

A profile tells you where the time goes. It does not tell you whether your fix
worked.

- For that, use the throughput harness.
- It is the same one CI runs nightly:

```sh
# Run all of these, in order.
bench/regression-gate.sh target/release/sipnab      # against bench/baseline.json
bench/scaling.sh "$BIN" corpus.pcap 535000 --cores 1,2,4,8 --runs 5
```

[`bench/scaling.sh`](../../bench/scaling.sh) takes a directory as well as a file.

- A **multi-file** `-I` set is a different measurement, not a longer one.
  - The calling thread reads a lone file itself.
  - A set gets one reader thread per file, and a
    dispatcher that hands the workers each file in turn.
- Cut one corpus into rotated members. Do not generate several.
  - Then the members share one timeline the way a real rotation does:

```sh
# Run all of these, in order.
python3 bench/carrier.py --calls 40000 --out big.pcap   # 4,280,000 packets
editcap -F pcap -c 535000 big.pcap rot/rot.pcap         # 8 members of 535k
bench/scaling.sh "$BIN" rot 4280000 --cores 1,2,4,8,12 --runs 9
```

`-F pcap` is not optional.

- `editcap` writes pcapng by default.
- The mapped reader declines pcapng.
- So the whole set would fall back to libpcap and measure a different reader.

Two rules learned the hard way, both recorded in
[`build-ci-release.md`](build-ci-release.md) and [`bench/baseline.json`](../../bench/baseline.json):

- **Interleave the arms.**
  - Measure A, B, A, B — never all of A then all of B.
  - Host state drifts.
  - A drift that lines up with your change is indistinguishable from the change.
- **Check an unrelated binary.**
  - Comparing 0.5.47 against 0.5.88, voipmonitor
    measured 0.40M in both arms *exactly*.
  - That is what turned "the numbers look low" into an attributable regression, not a suspicion.

## Throughput history

The engineering record behind the [Benchmarks](../benchmarks.md) page: the
regressions, the A/B sessions that measured them, and the reasons the
published tables have the shape they have. The benchmarks page carries only
the current reference tables and the method.

### Why the page and the baseline are one event

[`bench/baseline.json`](../../bench/baseline.json) commits every figure in the
multi-core and carrier-scale tables: all three replicates per core count, the
peak resident set of each, and the whole carrier-scale sweep.

The published figure is the LOWEST replicate rather than the median.

- So a reader who re-runs the harness meets or beats it instead of falling short of it.
- And the throughput gate's floor cannot sit above a number this host actually produces.

**A raise on the page and a raise in that file are one event, and a test says
so.**

- They came apart three times while the rule lived in a comment that
  asked a reader to remember it.
- The last separation published 3.23M for 0.5.122.
  - The committed baseline held 3.25M with replicates 3.25/3.29/3.29M.
  - So the page showed a figure the recorded run never produced.
  - It was 0.6% adrift, inside the page's own noise floor. That is why no reader caught it.
- `benchmarks_pages_headline_matches_the_committed_baseline` binds the
  baseline to both hand-maintained copies of the page and to the homepage
  tile.

The page measures a local release build rather than a published
artifact. The throughput gate has to catch a regression the day it lands, not
once it has shipped, so the number the page publishes is the number that gate
measures.

### The 0.5.118 to 0.5.121 regression

**0.5.118 through 0.5.121 ran materially slower than 0.5.117, and 0.5.122
repaired it.**

- The cause was [`is_merged`](../../src/capture/merged.rs),
  the probe that decides whether a capture is a merged pcapng.
- It read the ENTIRE file into memory and then rejected it on the first four bytes.
- So every offline run over an ordinary pcap:
  - loaded the whole capture,
  - threw it away,
  - and only then started work.
- Three call sites run it before the reader touches a packet.

[`bench/regression-gate.sh`](../../bench/regression-gate.sh) exists to catch
exactly that and did not.

- Its baseline still recorded 0.5.104's figure.
- The drop read as 105% of a baseline four releases stale.
- So the gate passed while the tool lost a quarter of its throughput.
- That is the failure its own baseline file warns about in writing: a stale baseline "silently
  widens the band it advertises".
- The page's numbers and that file's are now re-measured together or not at all.

### The multi-core ceiling and the mapped reader

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
  The 2026-10-11 session below measures what that did on one core.

The A/B that measured 0.5.108 is not published. The benchmarks page dropped the
sentences that quoted its spread and its per-core gaps: they described a
2026-08-17 session whose table was never published, so a reader had no way to
check them. What survives is the mechanism, which the code and
[Zero-copy payloads](zero-copy-payloads.md) record.

The obvious version of that change is a regression.

- Handing each frame out as a refcounted slice of
  the mapping, copying nothing at all, measures 1.88M at four cores.
  That is well under libpcap.
- One mapping is one atomic refcount.
- 535k frames cloned by the reader and dropped by the workers drive ~1M atomic updates through a single
  cache line.
- [Zero-copy payloads](zero-copy-payloads.md) records the failed hypotheses in full.

Before v0.4.16 a per-packet cross-core hand-off collapsed four-core throughput
to 0.84M and eight-core to 0.50M. Batching the hand-off removed that, and
0.5.104 extended the same batching to the single-core path.

The single-core row holds the most memory, 168.4 MiB against about 105 MiB on
two or more cores. It did so through libpcap as well, and it still does with
the mapped single-threaded reader. No measurement has identified the cause yet.

### The 0.5.84 regression, 0.5.47 to 0.5.91

Throughput fell 40% in 0.5.84 and held that loss for four releases. 0.5.89
recovered part of it. 0.5.91 went past where it started.

The conditions, on 2026-08-10:

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
regression**: 2.32M against 0.5.47's 2.02M.

- The second change beat its own predicted ceiling.
- Frames sharing a block are also sequential in memory.
  A diagnostic that scattered them into an arena could not show that.

**What closed after them.**

- Every build that table measures hashes every frame.
- Only a *retained* pointer needs a digest:
  - a dialog's `first_frame`,
  - a stream's `first_frame`,
  - a finding's `frame_ref`.
- That is about 35,000 of 535,000 frames on this corpus.
- PERF1 in [`docs/design/backlog.md`](../design/backlog.md) closed that on 2026-08-28.
  It records the measurement it closed on:
  - two release builds off one tree differing only in this change,
  - same harness and corpus,
  - 2.70M at two cores against 2.10M,
  - 3.56M at four against 3.21M.
- The 0.5.160 table published on 2026-09-09 reflected it.
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

**Scope.** The table above spans 0.5.47 → 0.5.91, measured on 2026-08-10. The
sessions below are separate and not directly comparable to its columns. The
host had drifted ~4% between the two dates, which is why each session carries
its own control.

### The batched single-core read, 2026-08-17

Both released artifacts, checksum-verified, same idle host, same session:

| cores | 0.5.103 | 0.5.104 | change |
|------:|--------:|--------:|-------:|
| 1 | 1.01M | 1.28M | **+27%** |
| 2 | 2.21M | 2.17M | −2% |
| 4 | 2.29M | **2.31M** | +1% |
| 8 | 2.13M | 2.16M | +1% |

- The single-core gain is 0.5.104's batched file read.
  The default path had paid the channel hand-off per packet.
- The 0.5.103 single-core figure also records what happened between 0.5.91
  and 0.5.103:
  - a ~4%-of-figure erosion,
  - diffuse across two hundred commits of added analysis,
  - that a profiler could not pin to any single function.
  - The batching change overtook it rather than anyone chasing it line by line.

### The mapped single-core reader, 2026-10-11

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
`15e5e7bd`. That is below the 96% the benchmarks page requires. The conclusions
below hold with or without those two replicates.

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

### The carrier-scale sweep between sessions

The carrier-scale table moves more between sessions than within one.

- Two more sessions the same evening as the published table measured
  `15e5e7bd` at 3.14-3.31M at 20,000 calls. The table shows 3.06M.
- 0.5.160's 2026-09-09 session published 3.26M.
- Interleaved in one session, 0.5.160, 0.5.211 and `15e5e7bd` were within 5% of each other at
  every size.
  0.5.160 was fastest at 500 calls and slowest at 20,000.
- The lower figures in the table are the session, not a regression.
- Memory did grow. At 20,000 calls in that session:
  - 0.5.160 peaked at 493-499 MiB,
  - 0.5.211 at 517-531 MiB,
  - `15e5e7bd` at 527-537 MiB.

The benchmarks page once compared each carrier-scale row against the same sweep
on 0.5.104. That table never appeared on the page, so the page dropped the comparison.

### Figures before 0.5.47

Every number on the benchmarks page has been reproducible since 0.5.47, which
put the corpus generator and the timing harness in [`bench/`](../../bench/).
0.5.47 dates the recipe, not any one run.

The tables published before 0.5.47 measure an unpublished corpus nobody can
rebuild, so nothing after them compares to them.

- The page once carried a single-core figure for 0.5.18 against a figure
  "this page once published". Neither resolved to a committed record:
  - the older of the two resolved to a corpus that no longer exists,
  - the newer resolved to a session with no table.
- The gap between the old tables and the current ones is the corpus, not a regression.

### Why the throughput gate runs nightly, not per push

- The `Throughput` workflow runs [`bench/regression-gate.sh`](../../bench/regression-gate.sh) at 03:29 UTC daily.
- It runs against the figure committed in [`bench/baseline.json`](../../bench/baseline.json).
- It fails below a stated floor.

It is nightly on purpose:

- The reference host is one self-hosted runner that also serves CI.
  So two jobs on it measure their own contention rather than the tool.
- A per-push wall-clock gate would be flaky in the direction that gets a gate muted.
- It does not catch slow erosion. A drift inside the floor passes.
- [`bench/baseline.json`](../../bench/baseline.json) argues that trade.
