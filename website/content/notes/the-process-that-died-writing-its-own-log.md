+++
title = "The process that died writing its own log"
date = 2026-09-01
description = "CI ran out of disk, and the thing that could not write was the logger. There was no readable job log to diagnose it from, and the cause was four copies of one rule that had drifted apart."

[extra]
kind = "postmortem"
+++

On 2026-09-01 a CI job died like this:

```text
System.IO.IOException: No space left on device :
  '/home/runner/actions-runner/cached/2.337.0/_diag/Worker_....log'
```

The GitHub Actions runner process could not write its own diagnostic log.

That failure produces no readable job log, because the component that failed
**is** the logger. There is no build output to scroll, no test name to search
for, no last-line-before-death. Diagnosing it meant reading a check annotation
after the log blob had already expired. It cost a release cycle.

## The warning nobody had to act on

The Coverage job had been reporting the condition for two runs, with 62 MB
left.

A warning is not a failure. Nothing stopped, nothing went red, and a number
printed in a passing job is a number nobody reads. Two runs later a different
job crossed the same line and took the whole cycle with it.

## Four copies of one rule

Both `ci.yml` and `quality.yml` carried a step called "Free disk space", and
each carried it twice.

The two in `ci.yml` removed `dotnet`, `android`, `ghc`, CodeQL and boost. The
two in `quality.yml` removed those **plus** swift, the hosted tool cache and
every docker image.

The stronger pair exists because the Coverage job ran out of space once, and
whoever fixed it fixed the file in front of them. CI's copy never got the
update. CI is what ran out.

Two copies of a rule agree until one of them changes. Four copies are the same
statement with more chances to be wrong, and the copy that goes stale is
whichever one nobody was looking at when the lesson arrived.

## One action, and it reports the margin

There is one `.github/actions/free-disk/action.yml` now, and all four steps use
it. It reclaims the union of what the four copies removed between them, not the
weaker set.

The part worth copying is the tail — quoted from the action rather than
something to run:

```text
after=$(df --output=avail -k / | tail -1)
awk -v b="$before" -v a="$after" 'BEGIN {
  printf "reclaimed %.1f GB; %.1f GB free before, %.1f GB free after\n",
         (a-b)/1048576, b/1048576, a/1048576
}'
```

`df -h` printed after the fact says what is free right now. It does not say how
close the job came, and it does not say whether the margin has been shrinking
run over run. The number that predicts the next failure is the one this prints
and the old steps never did.

The action deliberately does **not** enforce a floor. Its own comment says why:

> A floor is deliberately NOT enforced here yet — the right value is a
> measurement nobody has taken, and a threshold invented to look rigorous is
> worse than none.

That is the honest position for a value nobody has measured. Report first,
enforce once there is a distribution to enforce against.

## Gating the class, not the incident

`tests/ci_disk_headroom_test.rs` holds four properties, and the interesting
thing about them is that none of them checks disk space.

Every step named "Free disk space" has to use the shared action, and none may
carry an inline `run:` block beside it, because an inline script is the second
copy again. The action has to keep reclaiming every path the four copies
between them reclaimed, since losing an entry is silent — the job still runs,
just with less room, until one day it does not. The action has to report both
numbers. And every workflow that builds the whole matrix has to reclaim first:

```rust
assert!(
    reclaims > 0,
    "{wf} builds the whole matrix and no job reclaims disk first. The \
     runner dies writing its own log, which produces no readable failure \
     at all."
);
```

The gate that would have caught this is not a disk gate. It is a
**duplication** gate. The disk was the symptom, and it was already the second
symptom of the same drift.

## What is different about this failure mode

Most CI failures hand you their own diagnosis. A test names itself, a compiler
names a file and a line, a linker names the object it could not place. Even
[the linker running out of space three days
earlier](@/notes/seventy-five-percent-of-a-test-binary.md) said `ld: final link
failed: No space left on device`, which is a complete sentence about what
happened.

Exhausting the disk under the runner's own logging is different, because the
failure removes the evidence about itself as it happens. Anything that only
reports through the log cannot report the log's own failure.

So the reporting has to be somewhere else. Here it is a check annotation, which
is what survived, plus a margin figure printed early enough in every job to
outlive whatever happens later.

## Worth stealing

Count the copies of any rule that protects a shared resource. Not because
duplication is untidy, but because what decides which copy goes stale is which
one somebody happened to have open, and that has nothing to do with which one
matters.

And when a job warns about a resource, write down the number. A warning with a
measurement is a trend. A warning without one is a message that scrolled past.
