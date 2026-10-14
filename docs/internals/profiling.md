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
