+++
title = "Three tests failed on macOS and the cleaner was innocent"
date = 2026-09-01
description = "A GNU-only flag in a test fixture silently did nothing on macOS. The code under test behaved correctly, three assertions about it failed anyway, and every message pointed at the wrong file."

[extra]
kind = "postmortem"
+++

Three tests in `tests/repo_hygiene_test.rs` failed on macOS and nowhere else.
They assert that `scripts/clean-stale.py` removes old files, and their messages
all said the cleaner had not removed something it should have.

The cleaner was correct. The fixture held the defect, and the defect was that
it did nothing.

## The one-flag version of the story

`Fixture::age` backdated a file so the cleaner's age floor could see it as old.
It did that by shelling out:

```sh
touch -d @<epoch> <path>
```

`touch -d` is a GNU extension. BSD `touch` has no `-d` — it spells the same idea
`-t`, with a different argument format. On macOS the command simply failed.

Follow the consequences in order:

1. The command fails, and nothing checks its status.
2. The file keeps today's timestamp.
3. The cleaner's age floor correctly declines to remove a file written seconds
   ago.
4. Three assertions about **the cleaner** fail.

Every step after the first is correct behavior. The failure message named the
cleaner, the reader goes and reads the cleaner, and finds nothing wrong with
it.

A local run could not have caught this, because the box that runs the local
suite is Linux and GNU `touch` accepts `-d` there. It took a CI cycle to
understand.

## A setup step that does nothing looks exactly like one that worked

That sentence is the whole class, and it is broader than one flag.

Backdating happens in Rust now, and — the part that matters — it checks that it
happened:

```rust
assert!(
    age.as_secs() >= days * 86_400 / 2,
    "backdating {} did not take: it reads as {}s old, not {}d. Every \
     age-gated assertion below would then be testing the fixture \
     rather than the cleaner.",
    p.display(),
    age.as_secs(),
    days
);
```

The message says what a failure here means. A fixture that silently no-ops
turns every test resting on it into a test of the fixture, and the tests keep
their original names while doing it.

## The floor, proven in both directions in one run

The primitive gets a test of its own, so a broken fixture fails as a broken
fixture rather than as a defect somewhere downstream:

```rust
fn backdating_a_fixture_file_actually_moves_its_mtime() { ... }
```

And the age floor gets asserted both ways at once:

```rust
fn the_age_floor_separates_recent_from_backdated_in_one_run() { ... }
```

Both directions in **one** run, deliberately. A fixture that made everything
look old would pass every removal test. A fixture that made everything look new
would pass the retention test. Only writing an old file and a new file into the
same run, and asserting the cleaner removes one and keeps the other, catches a
backdating mechanism that has quietly stopped working — which is exactly the
state this started in.

## Gating the class rather than the flag

Six tests went in, and only one of them is about `touch`.

No test in the suite shells out for file metadata, because `std::fs` is
portable and the shell tools are not. The cleaner shells out to nothing at all,
since it deletes files and must not additionally depend on which platform
supplies `rm`. Every fixture stays inside `CARGO_TARGET_TMPDIR`, because these
tests hand a recursive remover a root directory.

And no executable line in `scripts/`, `.githooks/` or `bench/` uses a GNU-only
spelling:

```rust
const GNU_ONLY: &[(&str, &str)] = &[
    ("touch -d", "BSD touch has no -d; use std::fs or -t"),
    ("stat -c", "BSD spells it `stat -f`; `wc -c` is portable"),
    ("readlink -f", "BSD readlink has no -f"),
    ("date -d ", "BSD date spells it -v or -j -f"),
    ("cp --preserve", "BSD cp uses -p"),
];
```

Each entry names a BSD counterpart that behaves differently, so the command
does not fail loudly on macOS. It fails in whatever way that platform's tool
chooses, and for the one that started this the choice was "silently do nothing".

That scan found one real hit on its first run: `stat -c %s` in
`bench/live-capture.sh`, now `wc -c` — POSIX, and the same number everywhere.

## The mutation that did not land

All three mutations written against these tests died as they should. The first
one did not apply on its first attempt, and its guard said so.

That guard exists for the same reason this note does. A mutation that never
landed looks exactly like a passing test: the suite is green, the report says
the test survived a deliberate break, and neither statement is true. Every
mutation written for this work carries a guard, so a failed application exits
loudly rather than reporting a result it never produced.

## Worth stealing

When a test fails, check whether the failing assertion is about the code or
about the setup that got there. The message cannot tell you — it quotes the
assertion, and the assertion names the code by construction.

Any setup step that can silently do nothing needs to verify itself. Backdating
a file, seeding a database, starting a listener, planting a fixture: if the
step has a failure mode that produces no error, the step has to read back what
it did.
