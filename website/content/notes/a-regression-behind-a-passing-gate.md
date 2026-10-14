+++
title = "Offline throughput regression in 0.5.118 to 0.5.121, missed by a stale benchmark baseline"
date = 2026-08-21
updated = 2026-10-11
description = "Why sipnab 0.5.118 to 0.5.121 read capture files more slowly than 0.5.117, why the benchmark check passed on all four releases, and what changed in 0.5.122."

[extra]
kind = "postmortem"
+++

## In short

From 0.5.118 to 0.5.121, sipnab read capture files more slowly than 0.5.117
did.

- A check that runs before reading loaded the whole file into memory first.
- A benchmark check exists to catch slowdowns like this. But it compared each
  release against a reference figure that nobody had updated for several
  releases. So it passed.
- 0.5.122 fixed the code and updated the reference figure.
- 0.5.161 added a test that keeps the published figure and the reference
  figure equal.

## What happened

- sipnab 0.5.118 shipped on 2026-08-20.
- 0.5.119, 0.5.120 and 0.5.121 followed on 2026-08-21.
- 0.5.122 fixed the slowdown the same day.

The 0.5.122 entry in `CHANGELOG.md` records the measurements. They used a
128 MB benchmark capture read with four parallel workers (`--cores 4`):

| Version | Packets per second | Memory in use |
|---|---:|---:|
| 0.5.117 | 3.29M | 97 MiB |
| 0.5.118 to 0.5.121 | 2.40M | 143 MiB |
| 0.5.122 | 3.26M | 97 MiB |

2.40M is 27% below 3.29M. The same entry records that every release from
0.5.108 to 0.5.117 measured about 3.26M.

`bench/regression-gate.sh`, the benchmark check, ran on each of those four
releases and passed each time.

## Why it happened

### Reading the whole file

Before sipnab reads a capture file, it checks whether the file is a merged
pcapng.

- A merged pcapng is a pcapng file whose recorded interfaces disagree.
- The standard capture library cannot read it.
- The function is `is_merged` in `src/capture/merged.rs`.
- Three call sites run it before sipnab reads the first packet.

In 0.5.118 it began with:

```rust
pub fn is_merged(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    // Section Header Block magic, little-endian; anything else is not pcapng.
    if bytes.len() < 12 || bytes[0..4] != 0x0a0d_0d0au32.to_le_bytes() {
        return false;
    }
```

`std::fs::read` loads the whole file into memory. For an ordinary pcap file the
first four bytes decide the answer. So every run over a pcap file:

- loaded the entire capture,
- compared four bytes,
- discarded the copy,
- and then started reading packets.

The comment above the function described the intended behavior:

> Cheap: reads interface description blocks only, and stops at the first
> disagreement. A single-interface file — the overwhelming majority — costs
> one short read and takes the ordinary path untouched.

The code did not match the comment, and no test measured how much the function
read.

### Comparing against an old figure

`bench/regression-gate.sh` compares four-worker throughput against the figure
in `bench/baseline.json`. It fails below 80% of it (`floor_pct`).

- At 0.5.121 that file still held 2,280,000 packets per second, measured on
  0.5.104.
- Release 0.5.108 had raised real throughput to about 3.30M.
- The benchmarks page changed to the new figure at that time. The baseline
  file did not.

So the check compared 2.40M against 2.28M. The result was 105%, and the check
passed.

The baseline was 31% below the real figure. With that baseline, the check
would have passed any result above 1.82M (80% of 2.28M). That is a drop of up
to about 45% from 3.30M.

## What changed

- **The code.** `is_merged` now opens the file and reads four bytes first.
  - When the first four bytes are not the pcapng marker, it returns without
    reading anything else.
  - sipnab still reads a real pcapng file in full. Its interface blocks may
    appear anywhere in it.
- **A test of the effect.**
  `a_classic_pcap_is_rejected_without_reading_the_capture` in
  `src/capture/merged.rs`:
  - passes an input through a reader that counts bytes. The input is the
    four-byte ordinary pcap marker and 1 MiB of filler.
  - fails if the check reads more than 16 of them.
- **The baseline.** 0.5.122 set the baseline to 3.25M.
  - That is the lowest of three measurement runs.
  - So the 80% floor (2.60M) cannot sit above a figure the benchmark host
    produces.
  - 2.40M is below that floor.
  - The current baseline is 3.52M, measured on 2026-10-11, with a floor of
    2.82M.
- **One figure, enforced by a test.**
  - The benchmarks page and the baseline file are now updated together.
  - `benchmarks_pages_headline_matches_the_committed_baseline` in
    `tests/site_journey_test.rs` fails if the page's headline figure and the
    baseline differ.

## What you can check yourself

These commands run in a clone of the sipnab repository with its tags.

Release dates of the affected versions, from the changelog:

```bash
grep -n -E '^## \[0\.5\.(11[789]|12[0-2])\]' CHANGELOG.md
```

```text
8347:## [0.5.122] - 2026-08-21
8395:## [0.5.121] - 2026-08-21
8466:## [0.5.120] - 2026-08-21
8536:## [0.5.119] - 2026-08-21
8650:## [0.5.118] - 2026-08-20
8736:## [0.5.117] - 2026-08-20
```

The baseline and floor percentage the check used at 0.5.121:

```bash
git show v0.5.121:bench/baseline.json | jq '.cores_4_pkts_per_s, .floor_pct'
```

```text
2280000
80
```

The baseline after the fix:

```bash
git show v0.5.122:bench/baseline.json | jq '.cores_4_pkts_per_s'
```

```text
3250000
```

The baseline and floor percentage today:

```bash
jq '.cores_4_pkts_per_s, .floor_pct' bench/baseline.json
```

```text
3520000
80
```

## Terms used here

- **Throughput**: how many packets per second sipnab processes when it reads a
  capture file.
- **Capture file, pcap, pcapng**: files of recorded network packets. pcap is
  the older format. pcapng is the newer one. It can record several network
  interfaces in one file.
- **Benchmark**: a repeatable speed measurement on a fixed input.
- **Baseline**: the committed reference figure that the check compares a new
  measurement against.
- **Gate** or **check**: an automated test that must pass before a change is
  accepted.
- **Regression**: a change that makes a later version slower, or makes
  something stop working that worked in an earlier version.
- **Memory in use** (resident memory, RSS): the memory the process actually
  occupies.
- **Tag**: the name git gives a specific released version of the source.
- **jq**: a command-line program that selects fields from JSON.

## Related guides

- [Multi-core offline reconstruction](@/docs/benchmarks.md#multi-core-offline-reconstruction)
- [Test host and method](@/docs/benchmarks.md#test-host-method)
- [Reproduce the benchmarks](@/docs/benchmarks.md#reproduce)
