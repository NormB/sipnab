+++
title = "CI test binaries ran out of disk space because they carried full debug information"
date = 2026-08-29
updated = 2026-10-11
description = "Why the Linux CI job failed to link its test binaries on 2026-08-29, what a measurement showed, and the one-line build setting that fixed it in 0.5.133."

[extra]
kind = "postmortem"
+++

## In short

sipnab's automated test system (CI) builds many test programs on a rented
GitHub machine with limited disk space. On 2026-08-29 the build failed
because the disk filled up. Three quarters of each test program was debugging
information that tests never use. sipnab 0.5.133 changed one build setting so
that test programs keep only the file-and-line information needed to report
where a failure happened.

## What happened

The Linux job in CI failed while linking (the final build step that writes a
program file) with:

```text
ld: final link failed: No space left on device
```

The previous commit had passed. The failing commit added two test files, and
each test binary links the whole dependency tree (comment above
`[profile.dev]` in `Cargo.toml`).

## Why it happened

Before any change, a measurement of one debug test binary from 0.5.133 gave:

| Measured on 0.5.133 | Size |
|---|---:|
| One debug test binary | 422 MB |
| Of which `.debug_*` sections | 315 MB |
| Share | 75% |

The `Cargo.toml` comment, the 0.5.133 CHANGELOG entry and commit 4499cb79
record these figures. They were not re-measured for this note.

The `.debug_*` sections hold DWARF debug information: variable names, types
and source locations used by an interactive debugger. The Linux job runs on
GitHub's hosted `ubuntu-24.04-arm` runner (`.github/workflows/ci.yml`), which
has roughly 14 GB of disk according to the `Cargo.toml` comment. The
`dev` build profile, which test builds inherit, had no `debug` setting, so it
produced full debug information. The `[profile.release]`
profile had used `debug = "line-tables-only"` since 2026-04-15 (commit
515899bb).

Earlier the same day, the project had first treated a different CI failure as
a disk problem. The Benchmarks job stopped after about 6 minutes of compiling.
A step added to free disk space did not help. The job had 113 GB free at
the point of failure (commit 442adf1e and the comment in
`.github/workflows/quality.yml`). Building that job's
profiling profile with `CARGO_PROFILE_PROFILING_DEBUG: line-tables-only` fixed
it. For the link failure, the message from the linker named disk space
directly, and the size measurement came before the choice of fix.

## What changed

Commit 4499cb79 (2026-08-29, released in 0.5.133) added this to `Cargo.toml`:

```toml
[profile.dev]
debug = "line-tables-only"
```

`line-tables-only` keeps the file and line numbers that a panic backtrace
prints, so a failing test still names its location. It drops the variable and
type information that only an interactive debugger uses. To build with full
debug information for a debugging session, override the setting for one
command, as the `Cargo.toml` comment describes:

```bash
CARGO_PROFILE_DEV_DEBUG=full cargo test --test us_spelling_test
```

Three days later, on 2026-09-01, a CI runner ran out of disk for a different
reason: the four copies of the CI step that removes preinstalled software from
the runner had drifted apart, and the copy in `ci.yml` removed less than the
others. The note
[The process that died writing its own log](@/notes/the-process-that-died-writing-its-own-log.md)
describes that incident and its fix (the `.github/actions/free-disk` action,
commit 15fa67c9).
That incident's error message, `System.IO.IOException: No space left on device`, came from
the runner process, not from the linker.

## What you can check yourself

Confirm the setting is in place:

```bash
grep -A1 '^\[profile.dev\]' Cargo.toml
```

```text
[profile.dev]
debug = "line-tables-only"
```

The CHANGELOG entry is under `## [0.5.133] - 2026-08-29`, in the "Fixed"
section, as "CI ran out of disk linking test binaries."

## Terms used here

- **CI**: continuous integration, the automated system that builds and tests
  every change.
- **Runner**: the machine that runs a CI job; "hosted" means GitHub provides
  it.
- **Linker / link**: the build step that combines compiled code into one
  program file.
- **Test binary**: a program built only to run tests.
- **Dependency tree**: all the external libraries a program uses, and the
  libraries they use.
- **Debug information / DWARF**: data in a program file that maps machine code
  back to source code; DWARF is its format.
- **Build profile**: a named set of compiler settings in `Cargo.toml`, such as
  `dev` (used by `cargo build` and `cargo test`) and `release`.
- **Backtrace**: the list of functions, with file and line, printed when a
  program panics.

## Related guides

- [Build, CI and release: the toolchain](@/docs/internals/build-ci-release.md#the-toolchain)
- [Build, CI and release: symbol files](@/docs/internals/build-ci-release.md#symbol-files)
