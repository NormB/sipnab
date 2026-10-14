+++
title = "A CI job ran out of disk space and left no readable log"
date = 2026-09-01
updated = 2026-10-11
description = "Why one of sipnab's automated build jobs stopped on 2026-09-01 without a usable log, and how sipnab replaced four copies of its disk cleanup step with one shared, tested definition that reports the free space it leaves."

[extra]
kind = "postmortem"
+++

## In short

Each time sipnab's code changes, rented GitHub machines build and test it
automatically.

- On 2026-09-01 one of those machines ran out of disk space.
- The job stopped without producing a log that explained why.
- The cause was a cleanup step that existed in four copies.
  - Two of them removed less than the other two.
- The problem affected the project's own build checks. It did not affect any
  released version of sipnab.

## What happened

CI (continuous integration) is the automated build-and-test jobs that run on
each change. It runs on GitHub-hosted machines called runners.

- A runner starts with many preinstalled programs that sipnab's build does not
  use.
- So each heavy job first deletes some of them to make room.

On 2026-09-01 a CI job stopped with this error. The comment at the top of
`.github/actions/free-disk/action.yml` records it in the repository:

```text
System.IO.IOException: No space left on device :
  '/home/runner/actions-runner/cached/2.337.0/_diag/Worker_....log'
```

The four dots in the file name appear in the recorded message.

- The program that failed was the runner's own logging process.
  - It could not write its log file.
- Because the logger itself failed, the job produced:
  - no build output,
  - no test names,
  - no last message to read.

The fix commit (15fa67c9) records two facts:

- The project found the cause in a check annotation after the full job log
  had expired.
  - A check annotation is a short status note GitHub attaches to a job.
- The Coverage job had warned about low disk space in the two runs before.

For users of sipnab there was no visible effect. The failure was in the
project's own CI, not in a released version.

## Why it happened

Two workflow files, `ci.yml` and `quality.yml`, each held two copies of a step
named "Free disk space". That is four copies in all. They did not remove the
same things:

- the two copies in `ci.yml` removed .NET, Android, GHC (Haskell), CodeQL and
  Boost;
- the two copies in `quality.yml` removed all of those, plus:
  - Swift,
  - the hosted tool cache,
  - every Docker image.

The comment in the shared action that replaced them explains the longer list.

- It dates from an earlier time the Coverage job (in `quality.yml`) ran out of
  space.
- The `ci.yml` copies stayed as they were.
- A job in `ci.yml` was the one that ran out on 2026-09-01.

## What changed

The change is in the repository from 0.5.142 (2026-09-01).

- **One definition.**
  - The cleanup is now a single shared action,
    `.github/actions/free-disk/action.yml`.
  - Every "Free disk space" step uses it. As of 0.5.211 there are:
    - four in `ci.yml`,
    - three in `quality.yml`,
    - one in `release.yml`.
  - It removes everything any of the four old copies removed.
  - It also removes the `/usr/share/miniconda`, `/usr/local/share/powershell`,
    `/usr/local/lib/node_modules` and `/usr/local/.ghcup` directories.
- **It reports the margin.**
  - The action measures free space before and after cleaning.
  - It prints one line in this form. So each job's log shows the free space
    that remains:

  ```text
  reclaimed %.1f GB; %.1f GB free before, %.1f GB free after
  ```

  - It does not fail a job below a fixed threshold.
  - Its comment states that no measured threshold value exists yet.
- **Tests keep it that way.** `tests/ci_disk_headroom_test.rs` holds four
  checks on `ci.yml` and `quality.yml`:
  - every step named "Free disk space" uses the shared action. It has no
    inline script of its own beside it;
  - the action still removes every path the four old copies removed;
  - the action still prints both the space reclaimed and the space left;
  - each of the two workflow files uses the shared action at least once.
    Both contain full-feature or coverage builds.

  `release.yml` uses the same action but is not read by these tests.

## What you can check yourself

- The action is `.github/actions/free-disk/action.yml`.
- Its tests are in `tests/ci_disk_headroom_test.rs`.
- On any CI run, check the log of a job that frees disk space.
  - It contains a line from the action in the form shown above.
  - The line has the numbers for that run.

## Terms used here

- **CI**: continuous integration, the automated jobs that build and test
  sipnab on every change.
- **Runner**: the rented machine a CI job runs on.
- **Workflow file**: a file under `.github/workflows/` that lists CI jobs and
  their steps.
- **Step**: one command or action inside a CI job.
- **Action**: a reusable step defined once and used from several workflows.
- **Check annotation**: a short message GitHub attaches to a job's result. It
  stays after the job log expires.
- **Coverage job**: the CI job that measures which lines of code the tests
  run.

## Related guides

- [What CI enforces on a pull request](@/docs/contributing.md#pull-request-process)
- [What a change needs before it can merge](@/docs/contributing.md#what-a-change-needs-before-it-can-merge)
