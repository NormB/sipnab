+++
title = "An assumption nobody timed"
date = 2026-09-01
description = "The commit hook linted a narrower scope than CI, and widening it stayed on the backlog because it would 'roughly double the wall clock'. Measured: 245 ms against 517 ms — and the middle option nobody chose would have taken 40 seconds."

[extra]
kind = "postmortem"
+++

sipnab's `pre-commit` hook ran:

```sh
cargo clippy --features full -- -D warnings
```

CI and `pre-push` run:

```sh
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

Test binaries are not a default cargo target. So the commit gate never saw a
single test file in this repository, for as long as the hook had run that
command.

Four lints reached CI through that gap. A `needless_splitn` in
`tests/sample_capture_test.rs` and an `items_after_test_module` in
`src/sip/mod.rs` on 2026-08-30, and two more on 2026-09-01 in test files
written that day. Each one costs a push, a CI wait, a fix and another push.

## The sentence that kept it open

The backlog item tracking this, `GATE1`, left the fix as an open question. The
changelog describes it as "deferred for a year of commits", and the reason it
records is that `--all-targets` would "roughly double the hook's wall clock".

That is a plausible sentence. It sounds like the kind of thing somebody
measured. Nobody had.

## Warm, on the machine that runs it

| command | steady state |
|---|---:|
| `--features full` (the old hook) | 245 ms |
| `--workspace --all-features --all-targets` (CI's) | 517 ms |
| `--features full --all-targets` (a middle option) | 40,110 ms |

The assumption was wrong by an order of magnitude in the direction that
mattered. Widening the hook to CI's exact command costs 272 ms.

The third row is the interesting one, and it explains the first two.

## Why CI's command is the cheap one

CI's exact command is cheap **in the hook** because `pre-push` and CI already
run it. It shares their warm build cache. Nothing has to compile for it.

`--features full --all-targets` looks like a reasonable middle ground —
narrower than the strict command, wider than the old hook — and it is 78 times
slower than the strict one, because a feature combination nothing else builds
has a cache nothing else warms. Choosing it would have made the hook unusable
and made the reason look like "linting tests is expensive".

This generalizes past clippy. What dominates the cost of running a check
locally is whether anything else in the workflow shares its inputs. An
approximation of a gate is not merely weaker than the gate. It is usually
slower too, because it is the only thing that ever asks for that exact
combination of inputs.

Run the gate. Do not approximate it.

## Scope is only half of a lint gate

`tests/clippy_scope_parity_test.rs` holds `pre-commit`, `pre-push` and `ci.yml`
to one scope, and separately asserts that each denies warnings.

The second half matters as much as the first. A clippy invocation without
`-D warnings` prints everything it found and exits 0. Same scope, same output,
and nothing stops.

Writing those tests found a defect in the scanner before it found anything in
the hooks. It read a hook's `printf` of a `--fix` suggestion as an invocation
and reported it as missing `-D warnings`:

```rust
fn is_invocation(line: &str) -> bool {
    let l = line.trim();
    l.contains("cargo clippy")
        && !l.starts_with('#')
        && !l.starts_with("//")
        && !l.starts_with("printf")
        && !l.starts_with("echo")
        && !l.contains("--fix")
        && !l.contains("Reproduce:")
}
```

A gate that reports a help message as a violation is a gate somebody switches
off, and the first hit a new scanner produces is more often the scanner's than
the tree's.

## The shape of the mistake

This is not a story about a slow hook. It is a story about a number that sat in
a backlog entry, read like a measurement, and had never been one.

The tell is in the phrasing. "Roughly double" is an estimate wearing a
measurement's clothes. So are "should be", "presumably" and "about". Each of
them marks a place where somebody stopped and the next person read a conclusion.

Timing three commands took a few minutes. It reversed a standing decision that
had already cost four CI cycles across two days.

## Worth stealing

When cost is the reason a fix waits, check whether anybody measured the cost.
Deferring is a decision, and a decision resting on an unmeasured number is a
guess that age has promoted.

And when you do measure, measure the option you would actually pick alongside
the ones you would not. The middle option here was the intuitive compromise,
and it was 78 times worse than the strict answer.
