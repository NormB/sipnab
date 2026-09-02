+++
title = "An instruction with no gate is a suggestion"
date = 2026-09-01
description = "A written rule said to delete every temp file in the same turn. The checkout held 21 stray logs, three abandoned worktrees and a 1.6 TB target directory. What the enforcement had to prove before it could delete anything."

[extra]
kind = "postmortem"
+++

The development instructions for this repository have said the same thing for
months: delete every temp file, log, redirect target and scratch script in the
**same** working session, not later.

The instruction is correct. On 2026-09-01 the checkout held:

* 21 stray `.git/*.log` files written across sessions
* three abandoned worktrees, 136 GB between them
* a `target/` directory of 1.6 TB

That is 44% of a disk that genuinely fills up, on the same box whose CI runner
[died writing its own log](@/notes/the-process-that-died-writing-its-own-log.md)
the same day. Cleaning it by hand took the disk from 76% to 56% used.

Nothing had gone wrong with the instruction. Nothing enforced it, so people
followed it exactly as well as anybody follows an unenforced instruction.

## Why the mess is invisible

`.git/*.log` is the interesting case. Those files are redirect targets — the
output of a command somebody piped somewhere while debugging. They sit inside
`.git/`, so `git status` never mentions them. Nothing anybody looks at in the
course of ordinary work says they exist.

An abandoned worktree is the same shape at a different scale. Three of them
accounted for 136 GB here, they appear in `git worktree list` and nowhere else,
and that is a command nobody runs unless they already suspect something.

Mess that shows up in the tool you use every hour gets cleaned. Mess that
requires a specific command to see does not, and the second kind is where the
disk goes.

## Two halves that run at different times

The enforcement splits in two, deliberately.

`tests/repo_hygiene_test.rs` runs with the suite and fails while the mess is
still one `rm`: no stray log in `.git/` but the hooks' own, no `.orig`, `.rej`
or `.snap.new` left behind, no worktree abandoned with nothing in it worth
keeping.

`scripts/clean-stale.py` reclaims what has already accumulated, on a daily
systemd timer, so it runs whether or not anybody remembers.

The gate cannot do the second job — it would have to delete things during a
test run — and the timer cannot do the first, because a daily sweep says
nothing about the commit that introduced the mess.

## Four properties, because being wrong deletes files

A cleaner is unrecoverable in one direction. Every property that makes this one
safe carries a mutation test, because a safety property nobody has watched fail
is a safety property nobody has tested.

**Dry run by default.** Somebody eventually runs it without its flag.

**An age floor.** It can run while a build is writing, and a file touched
seconds ago may be in use. Without a floor this is a race rather than a
cleanup.

**A root check.** Pointed at the wrong directory, a recursive remover does the
worst possible thing competently. It declines instead.

**A closed list of suffixes** — `.orig`, `.rej`, `.snap.new`, `.bak`, `~` —
never a pattern that could reach a source file.

Two more decisions are worth spelling out. Build caches only go under a disk
floor — 250 GB free by default — so an ordinary night costs nobody a rebuild.
And the cleaner never touches `deps/`, only `incremental/`, which cargo
regenerates on demand. Of the 1.6 TB `target/`, 551 GB was incremental cache
and 961 GB was `deps/`. Partial removal from `deps/` leaves cargo rebuilding in
confusing ways, so clearing it stays a `cargo clean`: a decision a person
makes, not a cron job.

The cleaner also shells out to nothing at all:

```rust
for forbidden in ["subprocess", "os.system", "Popen", "shell=True"] {
```

It is pure standard-library Python, which makes it portable by construction
rather than by inspection. A tool that deletes files must not additionally
depend on which platform supplies `rm` — a lesson that arrived
[the same day, from its own test fixtures](@/notes/the-fixture-was-what-broke.md).

## The gate and the cleaner share one definition

Both need to know which logs are mess and which are not. The hooks write
durable logs on purpose — `.git/sipnab-pre-commit-*.log` — and those are a
record to read rather than mess to delete.

That prefix lives in the script, and the test asserts the script contains it:

```rust
const HOOK_LOG_PREFIX: &str = "sipnab-pre-";
```

One rule, checked from both sides. Two copies of it would agree until the day
somebody renamed a hook log, and then the gate would start reporting the hooks'
own output as somebody's litter.

## Worth stealing

If a written rule keeps getting broken, the useful question is not who is
breaking it. It is what would have to fail for somebody to notice, and how long
that takes. Here the answer was "the disk fills", and the delay was months.

An instruction with no gate is a suggestion. That is not a criticism of anybody
who wrote one. It is a statement about what an instruction can do, and the
remedy is to make the machine hold the rule instead.
