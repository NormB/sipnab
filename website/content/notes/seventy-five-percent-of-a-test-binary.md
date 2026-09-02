+++
title = "Three quarters of a test binary was debug info"
date = 2026-08-29
description = "A CI linker ran out of disk after two test files landed. Measuring before changing anything found 315 MB of DWARF in a 422 MB binary, and a profile setting the release build had used for years."

[extra]
kind = "postmortem"
+++

CI's Linux leg failed with:

```text
ld: final link failed: No space left on device
```

The previous commit was green. The only change between them was two more test
files, and every test binary in this repository links the whole dependency
tree.

## Measure first, because the obvious answer had already been wrong once

The temptation is to reach for the reclaim step, add a directory, move on.
Blaming disk had already produced a wrong answer earlier the same week. The
Benchmarks job drew the same diagnosis, died with 113 GB free, and turned out
to have a different cause entirely: debug info in the profiling profile.

So this time the measurement came first, on 0.5.133:

| measured on 0.5.133 | size |
|---|---:|
| a debug test binary | 422 MB |
| of which `.debug_*` | 315 MB |
| share of the binary | 75% |

The Linux leg runs on GitHub's hosted `ubuntu-24.04-arm`, which has roughly
14 GB of disk. Three quarters of every test binary was information no test run
reads.

Two facts made this a diagnosis rather than a guess. The linker named the
condition itself, so there was no inference about what ran out. And the 75%
came off the section headers rather than off an assumption about what a debug
build contains.

## The fix was a setting the release profile already had

```toml
[profile.dev]
debug = "line-tables-only"
```

`line-tables-only` keeps the file and line a backtrace needs, and drops the
variable and type information only an interactive debugger uses. A failing test
still names its file and line. Nothing a test run reads goes away.

The release profile had carried that setting for a long time. The dev profile
simply never did, which is the kind of asymmetry nobody notices while there is
headroom.

The reversal is one environment variable, recorded beside the setting:

```bash
CARGO_PROFILE_DEV_DEBUG=full cargo test --test whatever
```

for when somebody genuinely does need to step through something under a
debugger.

## What the shape of this failure teaches

Disk exhaustion in CI has at least three distinct causes and they want
different fixes.

The linker ran out because the artifacts themselves were too large, and the fix
is to make the artifacts smaller. The runner
[ran out three days later](@/notes/the-process-that-died-writing-its-own-log.md)
because the runner image still carried every preinstalled toolchain, and the
fix was to reclaim them consistently. The Benchmarks job did not run out at
all, and the fix there was to stop calling it a disk problem.

"No space left on device" names the symptom and nothing else. Three incidents,
three different causes, and the message is identical in all three.

## Worth stealing

When a resource runs out, measure what is consuming it before adding more of
it. The number is usually cheap — here it came from reading section sizes off
one binary — and it is the difference between a fix and a delay.

And check whether the release configuration already solved the problem. A
setting applied to one profile and not its sibling is invisible for exactly as
long as the sibling has room.
