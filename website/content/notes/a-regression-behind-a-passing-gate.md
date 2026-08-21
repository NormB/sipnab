+++
title = "A 27% regression hid behind a gate built to catch it"
date = 2026-08-21
description = "sipnab shipped a quarter of its offline throughput away for ten releases. The benchmark gate ran on every one of them and passed. Here is why, and what the fix says about ratchets."
+++

sipnab's benchmarks page said 3.25M packets per second at four cores. On
2026-08-21 the same machine, at full clock and 100% idle, measured **2.40M**
from the released binary. The page had been wrong since 0.5.118, which is ten
releases and about a month.

The interesting part is not the bug. A gate exists specifically to catch this,
it ran on every one of those releases, and it passed every time.

## Blaming the host, and getting it wrong

The obvious suspect was the machine. The devboard that produced the August
figure now also hosts a CI runner, five harness containers and a resident MCP
server. So stop all of it, drop the page cache, measure again.

```text
cores    pkts/s
1        1.02M
4        2.40M
```

Identical. Stopping everything changed nothing, which kills the theory
outright. That deserves saying plainly, because "the box was busy" is the
comfortable answer and it stays available until somebody tests it.

Power mode came next, since the board sits at 120W with a MAXN mode available.
Also wrong. `scaling_governor` read `performance`, `scaling_max_freq` equalled
`cpuinfo_max_freq` at 2601 MHz, and uptime showed 33 days, so the mode had not
moved since before the August run. The corpus held exactly 535,000 packets,
which matches the divisor the harness takes.

## The control was the bug

The comparison had been 0.5.118 against 0.5.121. They agreed within 0.4%, and
that agreement looked like "no regression".

It was not. **0.5.118 was already the broken build.** Choosing it as the
control put the baseline underneath the cliff, where everything looks flat.

Downloading every released artifact in the window and measuring each one takes
about two minutes and settles it:

| release | pkts/s @ 4 cores |
|---|---:|
| 0.5.108 | 3.26M |
| 0.5.109 to 0.5.117 | 3.23M to 3.28M |
| **0.5.118** | **2.34M** |
| 0.5.121 | 2.40M |

One release, 28%. The August number was never wrong. The tool had stopped
meeting it.

## Two theories that died on contact

The source delta between the tags covers five files.

**The build environment.** 0.5.118's release workflow gained 124 lines, and the
binary's feature list gained `plugins` and `bpf`. But `readelf -p .comment` on
both artifacts shows the same Debian 12 GCC 12.2.0 and clang 22.1.0-rc2, and
the same `GLIBC_2.34` floor. Same container, same toolchain.

**The `plugins` feature.** `plugins` pulls in `wasmi`, and the release profile
sets `lto = true, codegen-units = 1`. A bigger LTO graph genuinely can change
how the optimizer inlines unrelated hot code. That is testable: build the same
commit twice, once with `plugins` and once without.

```text
noplug   4 cores   2.35M
plug     4 cores   2.39M
```

Neither is fast. Feature set exonerated.

Building the v0.5.117 and v0.5.118 *sources* on the same machine reproduced the
cliff, 3.29M against 2.39M, which put the cause back inside those five files.
Resident memory moved with it, 99 MiB to 143 MiB, and that turned out to be the
useful clue. Something allocated tens of megabytes that had not before.

## What it was

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

`is_merged` decides whether a capture is a pcapng whose interfaces disagree,
which is a file libpcap declines to read. It pulls the **entire file into
memory** and then rejects it on the first four bytes.

Three call sites run it before anything reads a packet. So every offline run
over an ordinary pcap loaded the whole capture into a heap `Vec`, compared four
bytes, dropped it, and only then started work. On a 128 MB corpus that adds
about 0.06 s to a 0.16 s run, which is the entire measured difference.

The comment directly above the function reads:

> Cheap: reads interface description blocks only, and stops at the first
> disagreement. A single-interface file, the overwhelming majority, costs one
> short read and takes the ordinary path untouched.

The comment describes the intended design correctly. `std::fs::read` is simply
not that design. Review does not catch this, because the sentence and the code
look like they agree.

## Why the gate passed

`bench/regression-gate.sh` exists because a 40% regression once shipped in
0.5.84 and survived four releases. It compares four-core throughput against
`bench/baseline.json` with an 80% floor.

The baseline recorded **2,280,000**, measured on 0.5.104.

0.5.108 then raised the real figure to 3.30M by mapping the capture file
instead of reading it. The benchmarks page moved that day. The baseline did
not.

So when the tool fell to 2.40M, the gate compared it against a four-release-old
number and got **105% of baseline**. Green. A 20% band had quietly become a 31%
band, and the regression fitted through the gap.

That file's own comment had already predicted this, in writing:

> A stale baseline does not merely under-report. It silently widens the band it
> advertises.

The paragraph was right, nobody acted on it, and the same file went stale one
release after somebody wrote it down.

## The two fixes

The code fix is small. Check the magic against four bytes before reading
anything else. A real pcapng still reads in full, because interface blocks may
legally appear anywhere in a section and a bounded guess that fell short would
mis-detect one. Four cores returns to 3.26M and RSS to 97 MiB.

The test asserts the **effect** rather than the shape. A counting reader takes
a 1 MiB buffer whose first four bytes say "classic pcap":

```rust
assert!(!is_merged_in(&mut r), "a classic pcap is not a merged pcapng");
assert!(r.read <= 16, "is_merged read {} bytes of a {}-byte capture it \
    rejects on the first four", r.read, file.len());
```

Before the fix that reports `read 1048580 bytes of a 1048580-byte capture`. A
test asserting "returns false" would have passed the whole time.

Writing it also surfaced that **nothing tested `is_merged` in the positive
direction at all**. Every existing test drove the reader struct directly, so a
version that always answered "no" passed the suite while quietly routing every
merged capture back to the libpcap reader that cannot open one. A mutation
confirms it: stubbing the function to `false` leaves three tests green and
fails only the new one.

The second fix matters more. The baseline now records 3.25M, the *lowest* of
three replicates rather than the median, so the floor it derives cannot sit
above a figure the host actually produces. That gives a 2.60M floor, which
2.40M trips.

## What to take from it

A ratchet is only as good as the day somebody last moved it. This one carried a
correct, well-argued warning about staleness and went stale anyway, because
raising the published number and raising the gate looked like two separate
chores instead of one event. They are one event, and the baseline file now says
so.

When a benchmark disagrees with a page, check that the **control** sits on the
right side of the cliff before concluding anything. Two builds agreeing tells
you nothing when the cliff sits under both of them.
