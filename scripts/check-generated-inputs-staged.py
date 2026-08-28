#!/usr/bin/env python3
"""Refuse a commit that stages a GENERATED file without its inputs.

This is the defect that broke `main` four times in one session, wearing four
different faces:

  1. `--features vcon` did not compile. The pre-push feature matrix builds the
     WORKING TREE, which held the fix; only the commit lacked it.
  2. `docs/design/testing-matrix.md` lost seven flags -- the generator reads the
     built binary and it was not rebuilt, so it described an older program.
  3. The same file then gained two flags that do not exist on `main`, because it
     WAS rebuilt, from a tree carrying other agents' unfinished work.
  4. `EXPECTED_WIKI_LINKS` was raised for documentation that never got
     committed.

Every one is the same mistake: committing a SUBSET of a dirty tree, so the
commit is a different program from the one on disk, while a generated artifact
describes the disk.

**No test can catch this after the fact, because locally the tree is
self-consistent.** `coverage_matrix_test` passed on my machine both times it was
wrong: my `cli.rs` and my matrix agreed with each other, and only CI -- checking
out the commit alone -- disagreed. The check has to happen at STAGING time,
against the index, which is what this does.

The rule: if a generated artifact is staged, then every input it derives from
must be either unmodified or staged too. Staging the output of a generator while
its input sits back in the working tree is the bug, precisely.
"""

import subprocess
import sys

# artifact -> the paths it derives from. Prefixes, matched by `startswith`.
DERIVED = {
    "docs/design/testing-matrix.md": ("src/cli.rs", "src/output/api.rs", "src/mcp/"),
    "website/content/docs/": ("docs/",),
    "Cargo.lock": ("Cargo.toml",),
    "fuzz/Cargo.lock": ("Cargo.toml", "fuzz/Cargo.toml"),
}


def _git(*args: str) -> list[str]:
    out = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    ).stdout
    return [line for line in out.split("\n") if line]


def staged() -> list[str]:
    """Paths in the index, relative to the repository root."""
    return _git("diff", "--cached", "--name-only")


def modified_unstaged() -> list[str]:
    """Paths changed in the worktree but NOT staged, untracked files included.

    Untracked matters: a brand-new module under `src/mcp/` is an input to the
    testing matrix just as much as an edited one, and it is exactly what a
    concurrent agent produces.
    """
    return _git("diff", "--name-only") + _git(
        "ls-files", "--others", "--exclude-standard"
    )


def main() -> int:
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if inside.returncode != 0:
        # Cannot answer is not the same as nothing wrong.
        print("not a git work tree; cannot check staged inputs", file=sys.stderr)
        return 2

    in_index = staged()
    if not in_index:
        print("nothing staged")
        return 0

    dirty = modified_unstaged()
    problems = []
    for artifact, inputs in DERIVED.items():
        if not any(p == artifact or p.startswith(artifact) for p in in_index):
            continue
        for path in dirty:
            if not any(path.startswith(src) for src in inputs):
                continue
            problems.append(
                f"  {artifact} is staged, but its input {path} is modified and "
                f"NOT staged.\n"
                f"    The committed {artifact} would describe your working "
                f"tree rather than this commit."
            )

    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked {len(DERIVED)} generated artifacts against the index")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
