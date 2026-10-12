+++
title = "Stray files filled the development checkout until a test and a scheduled cleaner enforced cleanup"
date = 2026-09-01
updated = 2026-10-11
description = "How leftover logs, unused worktrees and build caches built up in the sipnab development checkout, and the test and cleanup script that now detect and remove them."

[extra]
kind = "postmortem"
+++

## In short

Work on sipnab leaves files behind: saved command output, copies of the
repository made for parallel work, and build caches. A written instruction said
to delete them, but nothing checked that anyone did, and they came to occupy
44% of the development machine's disk. The project now has a test that fails
when leftover files are present and a script that removes them safely on a
daily schedule. This note describes the tooling that keeps the sipnab source
tree clean, not sipnab itself.

## What happened

The comment at the top of `scripts/clean-stale.py` records that the project's
development instructions, which are not part of the public repository, had
said "delete every temp file in the SAME turn" for months. It also records the
state of the development checkout on 2026-09-01:

- 21 stray `.git/*.log` files written across sessions
- three abandoned worktrees totalling 136 GB
- a `target/` build directory of 1.6 TB, of which 551 GB was incremental build
  cache and 961 GB was the `deps/` dependency cache

Together these took up 44% of the disk, by the same comment's count.

The script's `--disk-floor-gb` help records that the disk was a 3.6 TB disk and
76% full.

## Why it happened

The instruction existed only as text, and no tool checked it.

The leftover files were also hard to see in ordinary work. A file saved inside
`.git/` is never listed by `git status`. An abandoned worktree (a second
working copy of the repository linked to the same history) appears only in
`git worktree list`. Neither shows up in the commands used during normal
development.

## What changed

The project added two parts. They run at different times and do different
jobs.

### A test that fails while the mess is small

`tests/repo_hygiene_test.rs` runs with the test suite and fails when:

- `.git/` holds a file ending in `.log`, `.out` or `.err` that the project's
  own git hooks did not write (`the_git_directory_holds_no_stray_logs`)
- the working tree holds a file ending in `.orig`, `.rej`, `.snap.new`, `.bak`
  or `~`, as left by a merge, a patch, a snapshot test or an editor
  (`the_working_tree_holds_no_conflict_or_snapshot_detritus`)
- a worktree has no uncommitted changes, no commits ahead of its upstream
  branch, and nobody has touched it for 24 hours
  (`no_worktree_is_abandoned_with_nothing_worth_keeping`).

The stray-file rule covered only `.log` until 2026-09-12, when it gained `.out`
and `.err`.

### A script that removes what has accumulated

`scripts/clean-stale.py` deletes stray logs and leftover merge and snapshot
files. On the development machine it runs once a day from a systemd user
timer. That timer is part of the machine's own configuration, not of the
repository. The test reports leftover files and deletes nothing. The script
deletes files and does not run for each change, so it cannot point to the
change that left them.

The script has four safety properties, each covered by a test in
`tests/repo_hygiene_test.rs`:

- **Dry run by default.** Without `--apply` it only lists what it would remove
  (`the_cleaner_removes_nothing_without_apply`).
- **A minimum age.** It leaves alone any file younger than `--min-age-days`,
  default 1 day, because a build may still be writing it
  (`a_recent_file_is_never_removed`).
- **A root check.** It refuses to run on a directory that is not a git
  checkout (`the_cleaner_refuses_a_root_that_is_not_a_checkout`).
- **A closed list of file endings.** It removes only files ending in `.orig`,
  `.rej`, `.snap.new`, `.bak` or `~`, never a pattern that could match a source
  file (`apply_removes_detritus_and_never_source`).

The script removes build caches only when you pass `--reclaim-build-cache`, and
only when free disk space is below `--disk-floor-gb` (default 250 GB). Even
then the script removes only `target/*/incremental/`, which the Rust build tool
regenerates on demand. It never removes `deps/`
(`the_cleaner_never_touches_the_dependency_cache`). Clearing that directory
takes a person running `cargo clean`.

The script uses only the Python standard library and starts no other program.
`the_cleaner_shells_out_to_nothing` fails if the script contains
`subprocess`, `os.system`, `Popen` or `shell=True`.

The test and the script agree on which logs belong to the hooks through one
value. Both define the prefix `sipnab-pre-`, and
`the_gate_and_the_cleaner_share_one_definition_of_a_hook_log` fails if the
script no longer contains the prefix the test uses.

## What you can check yourself

These commands run from the root of a sipnab checkout.

A dry run, which lists what the script would remove and removes nothing:

```bash
python3 scripts/clean-stale.py
```

```text
nothing stale; removed 0 files, reclaimed 0 bytes
```

The output depends on the checkout. This one held no stray files. The root
check, pointed at a directory that is not a checkout:

```bash
python3 scripts/clean-stale.py --root /
```

```text
/ is not a git checkout. Refusing: pointed at the wrong directory, a recursive remover is a disaster, and doing its best is the wrong behavior here.
```

The script exits with status 2 in that case. The shared hook-log prefix:

```bash
grep -n 'HOOK_LOG_PREFIX.*=' scripts/clean-stale.py tests/repo_hygiene_test.rs
```

```text
scripts/clean-stale.py:41:HOOK_LOG_PREFIX = "sipnab-pre-"
tests/repo_hygiene_test.rs:41:const HOOK_LOG_PREFIX: &str = "sipnab-pre-";
```

## Terms used here

- **Checkout**: a copy of the repository's files on disk, with its git history.
- **Worktree**: an additional checkout linked to the same history, used to work
  on two branches at once.
- **`.git/`**: the directory where git keeps its own data for a checkout.
- **Git hook**: a script git runs at a set point, for example before a commit.
- **Test suite**: the project's automated tests, run before a change is
  accepted.
- **Build cache**: files the Rust build tool (`cargo`) keeps to make the next
  build faster. `incremental/` and `deps/` are two of them.
- **Dry run**: a mode that reports what a command would do without doing it.
- **systemd user timer**: a Linux feature that runs a command on a schedule
  for one user.

## Related guides

- [Running tests](@/docs/contributing.md#running-tests)
- [Git hooks](@/docs/contributing.md#git-hooks)
