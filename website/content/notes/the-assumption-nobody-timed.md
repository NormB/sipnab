+++
title = "The sipnab commit check did not lint test files until 0.5.143"
date = 2026-09-01
updated = 2026-10-11
description = "Why lint errors in sipnab's test files passed the commit check and failed CI, why the project postponed widening the check, what the measurement showed, and what now keeps the two checks the same."

[extra]
kind = "postmortem"
+++

## In short

sipnab's repository checks code automatically before each commit. It checks
again on the CI servers after each push.

- Before release 0.5.143, the commit check ran the Rust linter on the library
  and the programs.
  - It did not run it on the test files.
  - CI ran it on everything.
  - So lint errors in test files passed locally and failed in CI.
- The project had postponed making the commit check match CI.
  - It expected the change to double the check's run time.
  - Measured, the matching command took 517 milliseconds against 245.
- The commit check now runs CI's command.
- A test keeps the two the same.

This is about the project's own development checks. It does not affect how
sipnab behaves for users.

## What happened

Commit `e294c880` added the commit check on 2026-04-15. From then, the
`pre-commit` hook ran:

```text
cargo clippy --features full -- -D warnings
```

CI and the `pre-push` hook ran:

```text
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

Without `--all-targets`, `cargo clippy` checks only cargo's default targets.
Those are the library and the program binaries.

- The files under `tests/` were not checked at commit time.
- The test code built with them was not checked either.

Four lint errors passed the commit check and failed CI as a result:

- on 2026-08-30 (release 0.5.135):
  - a `needless_splitn` in a test file,
  - an `items_after_test_module` in `src/sip/mod.rs`;
- on 2026-09-01, two more in test files written that day.

Each one cost a push, a CI run, a fix and another push.

## Why it happened

The project knew about the difference between the two commands.

- The item that tracked it was `GATE1`.
- It left the fix as an open question.
- It assumed that widening the commit check would "roughly double its wall
  clock". Those are the words recorded in the 0.5.143 release notes.
- Nobody had measured the run time.

A measurement ran on 2026-09-01.

- It ran with a warm build cache.
- It ran on the machine that runs the hooks.
- `.githooks/pre-commit` and the 0.5.143 release notes record the figures:

| Command | Time |
|---|---:|
| `cargo clippy --features full` (the old commit check) | 245 ms |
| `cargo clippy --workspace --all-features --all-targets` (CI's command) | 517 ms |
| `cargo clippy --features full --all-targets` (a narrower alternative) | 40,110 ms |

- CI's command took 2.1 times as long as the old check.
  - That is close to the estimate.
  - It added 272 ms.
- It is fast because `pre-push` and CI run the same command.
  - So its build output is already in the cache.
- The narrower alternative uses a combination of features that no other step
  builds.
  - So the cache holds nothing for it.
  - It took 78 times as long as CI's command.

## What changed

In release 0.5.143 (2026-09-02), the `pre-commit` hook runs CI's command. It
adds `--color never` so the hook can search the output:

```text
cargo clippy --workspace --all-features --all-targets --color never -- -D warnings
```

`tests/clippy_scope_parity_test.rs` reads `.githooks/pre-commit`,
`.githooks/pre-push` and `.github/workflows/ci.yml` and asserts that:

- the commit check lints test targets;
- all three run the same clippy scope;
- every clippy invocation denies warnings (`-D warnings`).
  - Without it, clippy prints what it finds and exits with status 0.
  - So the check passes.

The test counts only the clippy commands a file runs. It skips:

- comments;
- lines that print a suggested command (`printf`, `echo`, a `--fix`
  suggestion, a `Reproduce:` hint);
- the separate `pre-push` run that lints for the other Linux processor
  architecture.
  - That run has its own rule and test.

The first version of the scan counted a printed `--fix` suggestion as a clippy
run without `-D warnings`. The skip list exists for that reason.

## What you can check yourself

From the root of a sipnab checkout, list every line in the three files that
names CI's clippy scope:

```bash
grep -n 'clippy --workspace' .github/workflows/ci.yml .githooks/pre-commit .githooks/pre-push
```

```text
.github/workflows/ci.yml:321:        run: cargo clippy --workspace --all-features --all-targets -- -D warnings
.githooks/pre-commit:230:#     cargo clippy --workspace --all-features --all-targets  517 ms
.githooks/pre-commit:243:CLIPPY_OUTPUT=$(cargo clippy --workspace --all-features --all-targets --color never -- -D warnings 2>&1)
.githooks/pre-commit:257:    echo "  Reproduce: cargo clippy --workspace --all-features --all-targets -- -D warnings"
.githooks/pre-push:7:#   * `cargo clippy --workspace --all-features --all-targets -- -D warnings`,
.githooks/pre-push:111:# (`cargo clippy --workspace --all-features --all-targets -- -D warnings`) so a
.githooks/pre-push:122:printf '  cargo clippy --workspace --all-features --all-targets -- -D warnings ... '
.githooks/pre-push:123:if cargo clippy --workspace --all-features --all-targets -- -D warnings; then
.githooks/pre-push:130:	printf '    cargo clippy --workspace --all-features --all-targets --fix\n'
```

The lines that run clippy are `ci.yml:321`, `pre-commit:243` and
`pre-push:123`. The others are comments and printed hints.

## Terms used here

- **Lint, linter**: a check that reports code which compiles but matches a
  known pattern of error or poor style. `clippy` is the Rust linter.
- **Commit check, `pre-commit` hook**: a script git runs before it records a
  commit. If the script fails, the commit is not made.
- **`pre-push` hook**: a script git runs before it sends commits to the
  server.
- **CI**: continuous integration, the servers that build and test every push.
- **Target**: one thing cargo builds. It is the library, a program, or a
  test.
- **Build cache**: compiled output kept from earlier builds, so unchanged code
  is not compiled again.
- **`-D warnings`**: makes clippy exit with an error when it finds anything.

## Related guides

- [Contributing: Git hooks](@/docs/contributing.md#git-hooks)
- [Build, CI and release: Hooks](@/docs/internals/build-ci-release.md#hooks)
