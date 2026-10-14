+++
title = "Three hygiene tests failed on macOS because their setup step did not run"
date = 2026-09-01
updated = 2026-10-11
description = "Why three tests of sipnab's file-cleanup script failed only on macOS while the script itself was correct, and the checks added so that test setup confirms it worked."

[extra]
kind = "postmortem"
+++

## In short

sipnab's repository has a maintenance script that deletes old temporary
files. It also has tests that check it. To test it, the tests first make some
files look old.

On 2026-09-01:

- the command they used for that failed on the macOS CI runner;
- nothing checked whether it had worked;
- the files stayed new;
- the script correctly kept them;
- three tests reported the script as broken.

The tests now set file times in Rust. They confirm the change took effect.

This is about the project's own test suite. It does not affect how sipnab
behaves for users.

## What happened

`scripts/clean-stale.py` deletes stray log files and other leftovers from a
checkout.

- It deletes only files older than a minimum age (its age floor).
- So it does not remove a file a running build is still writing.

`tests/repo_hygiene_test.rs` runs the script against temporary directories.
It checks what the script removed and what it kept.

On 2026-09-01, three of those tests failed on the macOS CI runner. They passed
on Linux.

- Each failure message said the script had not removed a file it should have
  removed.
- The script was correct.
- Nothing had ever made the files old.

## Why it happened

The tests' setup code, `Fixture::age`, made a file look old. It ran
`touch -d @<epoch>` on it.

- The test source records that form as a GNU extension.
- On the macOS runner the command failed.

In order:

- The `touch` command failed. The setup code did not check its exit status.
- The file kept its current modification time.
- The script's age floor kept the file. That is correct for a new file.
- Three assertions about the script failed.

Every step after the first behaved correctly. The failure messages named the
script, not the setup.

The suite's local runs are on Linux, where the command works. So the failure
appeared only in CI.

## What changed

Commit `6efa9937`, released in 0.5.142:

- `Fixture::age` sets the modification time with Rust's standard library
  (`set_modified`).
  - It reads the time back.
  - It fails with this message if the file is not old enough.
  - The message fills the `{}` with the file's path, its age in seconds, and
    the age in days the test asked for:

  ```text
  backdating {} did not take: it reads as {}s old, not {}d. Every age-gated assertion below would then be testing the fixture rather than the cleaner.
  ```

- The change added six tests:
  - `backdating_a_fixture_file_actually_moves_its_mtime` checks the setup step
    by itself.
  - `the_age_floor_separates_recent_from_backdated_in_one_run` writes one old
    and one new file in the same run.
    - It asserts that the script removes the old one and keeps the new one.
    - A setup step that made every file look old, or every file look new,
      fails it.
  - `no_test_shells_out_for_file_metadata` rejects tests that run `touch`,
    `stat`, `date` or `readlink` as a separate process.
  - `no_executable_line_uses_a_gnu_only_spelling` rejects five command forms
    in `scripts/`, `.githooks/` and `bench/`.
    - The forms are `touch -d`, `stat -c`, `readlink -f`, `date -d` and
      `cp --preserve`.
    - Its first run found `stat -c %s` in `bench/live-capture.sh`.
    - That script now uses `wc -c`.
  - `the_cleaner_shells_out_to_nothing` asserts that the script starts no
    other program.
  - `every_fixture_is_confined_to_the_cargo_temp_dir` asserts that every test
    directory is inside `CARGO_TARGET_TMPDIR`.
    - So a defect in the script cannot delete files outside it.

The commit message records three deliberate code changes (mutations).

- Their purpose was to confirm the new tests fail when the behavior breaks.
- The tests detected all three.
- The first did not apply on the first attempt.
  - The mutation's guard reported that.
  - It did not report a result for a change that was never made.

## What you can check yourself

From the root of a sipnab checkout:

```bash
grep -n 'set_modified' tests/repo_hygiene_test.rs
```

```text
576:        f.set_modified(when)
```

```bash
grep -n 'CORPUS_REAL_BYTES=' bench/live-capture.sh
```

```text
2035:CORPUS_REAL_BYTES=""
2135:  CORPUS_REAL_BYTES=$(wc -c < "$1/corpus.pcap" | tr -d ' ')
```

- The first shows the Rust call that sets the file time.
- The second shows the script that used `stat -c %s`. It now measures the file
  with `wc -c`.

## Terms used here

- **Test, assertion**: code that runs part of the project and checks a
  result. An assertion is one such check.
- **Fixture**: the setup a test prepares before it checks anything. Here it is
  a temporary directory with files in it.
- **Modification time**: the time a file was last written. The script uses it
  to judge the file's age.
- **GNU, BSD**: two families of the standard command-line tools (`touch`,
  `stat`, `date` and others). They accept different options for some
  commands.
- **CI**: continuous integration, the servers that build and test every push.
  Here they run Linux and macOS.
- **Mutation**: a deliberate break in the code, made to confirm that a test
  fails when the behavior it checks breaks.
- **`CARGO_TARGET_TMPDIR`**: a temporary directory that cargo provides to
  tests.

## Related guides

- [Contributing: Running tests](@/docs/contributing.md#running-tests)
- [Testing](@/docs/internals/testing.md)
