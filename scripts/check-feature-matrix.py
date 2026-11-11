#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Run CI's feature-matrix lint checks locally, before the push.

Why this exists as a gate rather than a habit: the pre-commit hook builds
`--features full`, and a break that only appears when a feature is ABSENT is
structurally invisible to it. `--all-features` cannot see it either -- it turns
everything ON. The only build that catches it is one combo at a time, which
until now happened solely in CI, so the feedback loop for that class was a full
push-and-wait cycle.

The combo list is read from .github/feature-combos.txt, the file ci.yml's
`features` job runs from, rather than restated here. A gate that duplicates
its source of truth drifts from it, and a local gate that checks a stale set
of combos is worse than none: it reports a pass CI will contradict.

    check-feature-matrix.py                         lint every combo
    check-feature-matrix.py --group I --pool P      CI: run group I on pool P

CI folds the combos into a few groups (ci.yml's `features` job), each on a
pool of self-hosted runners. `GROUPS` names
each group's pool, `POOLS` what each pool can run, and `partition` is the
one rule for which group runs what: every combo in exactly one group, with
the tests the file lists beside it, on a pool that has what it needs. A
group first checks that the machine has what its pool promises, then lints
its combos as this script always has, runs those tests, and fails if
anything failed.

Exit codes follow the convention the other pre-push gates use:
  0  every combo checked and passed
  1  a combo failed to compile
  2  could not run (no cargo, workflow file missing or unparsable)
"""
import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

def _root() -> Path:
    """The crate being pushed, not the crate this script lives in.

    Resolved from the working directory rather than `__file__` so the hook's
    BDD suite -- which runs the real hook with cwd set to a throwaway fixture
    crate -- exercises this gate against THAT crate. Anchoring on `__file__`
    would make every scenario re-check the real sipnab tree instead: slow, and
    a verdict about the wrong code.
    """
    r = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if r.returncode == 0 and r.stdout.strip():
        return Path(r.stdout.strip())
    return Path.cwd()


ROOT = _root()
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMBOS = ROOT / ".github/feature-combos.txt"

# A combo's lint, or one test target, costs about one unit; a full suite
# costs SUITE_WEIGHT. Measured on run 41729921358: the leg that ran the
# headless recipe's whole suite took 13.1 minutes, the others 1.6 to 4.6
# with about 1.5 of setup each.
SUITE_WEIGHT = 8


# What each pool of runners can run beyond a lint: `tests` (test targets
# and the full suite), and the tools a combination may need. `overflow` is
# the aarch64 host's two lowest-priority runners, with clippy, the wasm32
# target and cmake installed. Nothing is installed: a group that finds a
# tool missing stops and says which.
#
# The x86_64 runner was a third pool for one lint-only group on PR #626's
# run 41768214411 (2026-11-04), and is not one now. A 4-core virtual
# machine with about 2.5 GB of memory in use and up to 2.2 GB swapped while
# it built, it took 19 minutes for its first combination from a cold build
# directory and was canceled at its 45-minute timeout during the eighth of
# its ten, while the two overflow groups finished theirs (23 weight units)
# in 12.3 and 13.6 minutes.
POOLS: dict[str, set[str]] = {
    "overflow": {"tests", "wasm32", "cmake"},
}
# The pool each group runs on, by index; ci.yml runs each index once, on
# that pool. Two groups, because two runners carry `overflow`.
GROUPS: list[str] = ["overflow", "overflow"]

# The runner labels ci.yml's `features` job asks for. Pull request runs use
# the two runners labeled `overflow`. A push to main uses any of the host's
# four aarch64 runners (all carry `jetson`; the overflow pair carries both
# labels): on 2026-11-11 the run for a push to main (run 42977445618) had its
# two groups queued for 34 and 68 minutes behind pull request and Dependabot
# runs that held the overflow pair. The pool a group names stays `overflow`
# either way: the four runners are one host with one toolchain.
MAIN_RUNNER: list[str] = ["self-hosted", "jetson"]
OVERFLOW_RUNNER: list[str] = ["self-hosted", "overflow"]
MAIN_EVENT = "push"
MAIN_REF = "refs/heads/main"


def runner_labels(event_name: str, ref: str) -> list[str]:
    """The labels the `features` job runs on for one event and ref.

    Case is ignored, as GitHub's `==` ignores it in a workflow expression.
    """
    if not isinstance(event_name, str) or not isinstance(ref, str):
        raise TypeError("event_name and ref are the text GitHub gives a workflow")
    main = event_name.casefold() == MAIN_EVENT and ref.casefold() == MAIN_REF
    return list(MAIN_RUNNER if main else OVERFLOW_RUNNER)


def runs_on_expression() -> str:
    """`runner_labels` as the expression after `runs-on: ` in ci.yml.

    scripts/tests/test_feature_matrix_runner.py holds the workflow to this
    text and evaluates it against `runner_labels`.
    """
    def array(labels: list[str]) -> str:
        return "fromJSON('" + json.dumps(labels, separators=(",", ":")) + "')"

    return (
        f"${{{{ github.event_name == '{MAIN_EVENT}' && github.ref == '{MAIN_REF}' "
        f"&& {array(MAIN_RUNNER)} || {array(OVERFLOW_RUNNER)} }}}}"
    )


@dataclass
class Combo:
    """One feature combination and what CI runs with it beyond the lint."""

    features: str
    tests: list[str] = field(default_factory=list)
    suite: bool = False
    needs: list[str] = field(default_factory=list)
    # The library's unit tests (`cargo test --lib`) with these features. The
    # test targets above never include them, and nothing else runs them with
    # features off.
    lib: bool = False

    def requires(self) -> set[str]:
        """What a pool must have to run this combination."""
        out = set(self.needs)
        if self.tests or self.suite or self.lib:
            out.add("tests")
        return out

    def weight(self) -> int:
        return 1 + len(self.tests) + int(self.lib) + (SUITE_WEIGHT if self.suite else 0)


def parse_combos(text: str) -> list[Combo]:
    """The combinations of a feature-combos file, in file order.

    One per line: the comma-separated features, then optionally `suite` (run
    the whole test suite with them), `lib` (run the library's unit tests with
    them), `test=NAME` (run that test target with them) or `needs=TOOL` (only
    a pool with TOOL can run it), separated by spaces. `#` starts a comment.
    """
    out: list[Combo] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        combo = Combo(words[0].strip('"').strip("'"))
        for word in words[1:]:
            if word == "suite":
                combo.suite = True
            elif word == "lib":
                if combo.lib:
                    raise ValueError(f"line {n}: `lib` is listed twice")
                combo.lib = True
            elif word.startswith("test=") and len(word) > len("test="):
                combo.tests.append(word[len("test="):])
            elif word.startswith("needs=") and len(word) > len("needs="):
                combo.needs.append(word[len("needs="):])
            else:
                raise ValueError(f"line {n}: unknown annotation {word!r}")
        if any(c.features == combo.features for c in out):
            raise ValueError(f"line {n}: {combo.features!r} is listed twice")
        out.append(combo)
    if not out:
        raise ValueError("no feature combination listed")
    return out


def combos() -> list[str]:
    """The combinations, read off .github/feature-combos.txt."""
    if not COMBOS.is_file():
        return []
    try:
        return [c.features for c in parse_combos(COMBOS.read_text(encoding="utf-8"))]
    except ValueError:
        return []


def partition(
    items: list[Combo],
    groups_pools: list[str] | None = None,
    pools: dict[str, set[str]] | None = None,
) -> list[list[Combo]]:
    """Split the combinations into groups: the one rule for CI's jobs.

    `groups_pools` names each group's pool (GROUPS by default), and `pools`
    what each pool can run (POOLS). Heaviest first (name order on a tie),
    each combination goes to the group with the least weight so far, the
    lowest index on a tie, among the groups whose pool has what it requires.
    The result depends only on the set of combinations; every one is in
    exactly one group; and a combination no group can run, or a group that
    would run nothing, is refused.
    """
    groups_pools = GROUPS if groups_pools is None else groups_pools
    pools = POOLS if pools is None else pools
    count = len(groups_pools)
    if count < 1:
        raise ValueError("there must be at least one group")
    unknown = sorted(set(groups_pools) - set(pools))
    if unknown:
        raise ValueError(f"unknown pool(s) {unknown}")
    groups: list[list[Combo]] = [[] for _ in range(count)]
    load = [0] * count
    for combo in sorted(items, key=lambda c: (-c.weight(), c.features)):
        able = [k for k in range(count) if combo.requires() <= pools[groups_pools[k]]]
        if not able:
            raise ValueError(f"no group's pool can run {combo.features!r} (it requires {sorted(combo.requires())})")
        i = min(able, key=lambda k: (load[k], k))
        groups[i].append(combo)
        load[i] += combo.weight()
    empty = [i for i, g in enumerate(groups) if not g]
    if empty:
        raise ValueError(f"group(s) {empty} of {count} would run nothing")
    return groups


def lint_command(features: str) -> list[str]:
    if features == "wasm":
        # wasm is lib-only, and only the wasm32 target makes the check mean
        # anything: on the host the wasm32-only dependencies and rustflags
        # never apply.
        return ["cargo", "check", "--target", "wasm32-unknown-unknown",
                "--no-default-features", "--features", features, "--lib"]
    # `--tests` is not optional. Without it no test file is built, and a
    # break that lives in a test compiles nowhere -- the gate stays green
    # while CI, which passes it, goes red. Clippy, not `cargo check`: a lint
    # that fires only in one combination (a `return` left as a function's
    # tail once a `#[cfg]` block compiled out) passes `cargo check`.
    return ["cargo", "clippy", "--no-default-features", "--features", features,
            "--tests", "--", "-D", "warnings"]


def group_commands(group: list[Combo]) -> list[list[str]]:
    """What one group runs, in order: each combo's lint, then its tests."""
    cmds = []
    for combo in group:
        cmds.append(lint_command(combo.features))
        if combo.lib:
            cmds.append(["cargo", "test", "--no-default-features", "--features",
                         combo.features, "--lib"])
        for test in combo.tests:
            cmds.append(["cargo", "test", "--no-default-features", "--features",
                         combo.features, "--test", test])
        if combo.suite:
            # The suite's binaries side by side, as the Test job runs them.
            cmds.append(["python3", "scripts/parallel-tests.py", "--",
                         "--no-default-features", "--features", combo.features])
    return cmds


def workflow_env() -> dict[str, str]:
    """The workflow-level `env:` block, so this gate runs CI's flags.

    `RUSTFLAGS: -Dwarnings` lives there, and without it `cargo check` reports a
    dead-code warning and exits 0 -- so a break that turns CI red passes here.
    That happened: this gate was written, run against the real break it was
    built for, and SURVIVED, because the combos were right and the flags were
    not. Read them from the same file for the same reason the combos are read
    from it.
    """
    if not WORKFLOW.is_file():
        return {}
    text = WORKFLOW.read_text(encoding="utf-8")
    m = re.search(r"(?m)^env:\n((?:[ \t]+[A-Za-z_][A-Za-z0-9_]*:[^\n]*\n)+)", text)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        k, _, v = line.strip().partition(":")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def has_wasm_target() -> bool:
    r = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.returncode == 0 and "wasm32-unknown-unknown" in r.stdout


# An ANSI escape sequence: CSI codes such as `\x1b[1m`, which cargo writes
# around every diagnostic when CARGO_TERM_COLOR=always, as CI's workflows set.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def report_lines(out: str) -> list[str]:
    """The lines of a failing combination's cargo output worth printing.

    The color codes come off first. A colored `error: ...` line starts with
    an escape, not with `error`, so matching the raw line kept only the
    `-->` location and dropped the lint's name.
    """
    plain = (ANSI.sub("", line) for line in out.splitlines())
    return [line for line in plain
            if line.startswith(("error", "warning:")) or "-->" in line]


def ci_env() -> dict[str, str] | None:
    env = dict(os.environ)
    wf = workflow_env()
    if "RUSTFLAGS" not in wf:
        return None
    env.update({k: v for k, v in wf.items() if k in ("RUSTFLAGS", "RUSTDOCFLAGS")})
    return env


def missing_tools(pool: str) -> list[str]:
    """What this machine lacks of what `pool` promises, by name."""
    caps = POOLS[pool]
    missing = []
    if subprocess.run(["cargo", "clippy", "--version"], cwd=ROOT,
                      capture_output=True).returncode != 0:
        missing.append("clippy (rustup component add clippy)")
    if "wasm32" in caps and not has_wasm_target():
        missing.append("the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown)")
    if "cmake" in caps:
        try:
            ok = subprocess.run(["cmake", "--version"], capture_output=True).returncode == 0
        except OSError:
            ok = False
        if not ok:
            missing.append("cmake, which the opus combination builds libopus with")
    return missing


def run_group(index: int, pool: str) -> int:
    """Run group `index` on `pool`, as ci.yml's feature jobs do.

    Every command runs even after one fails; the exit status is 1 if any
    failed. Nothing is skipped and nothing is installed: a tool the pool
    promises and the machine lacks stops the group before it builds.
    """
    if not 0 <= index < len(GROUPS):
        print(f"check-feature-matrix: group index {index} is outside 0..{len(GROUPS) - 1}")
        return 2
    if GROUPS[index] != pool:
        print(f"check-feature-matrix: group {index} runs on the {GROUPS[index]!r} pool, "
              f"not {pool!r}; ci.yml and GROUPS disagree")
        return 2
    try:
        groups = partition(parse_combos(COMBOS.read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:
        print(f"check-feature-matrix: {e}")
        return 2
    missing = missing_tools(pool)
    if missing:
        for m in missing:
            print(f"::error::this {pool} runner lacks {m}")
        return 2
    env = ci_env()
    if env is None:
        print("no RUSTFLAGS in the workflow env block; refusing to check with "
              "weaker flags than CI")
        return 2
    group = groups[index]
    print(f"check-feature-matrix: group {index} of {len(GROUPS)} ({pool}): "
          + "; ".join(c.features for c in group), flush=True)
    failed = []
    for cmd in group_commands(group):
        print(f"::group::{' '.join(cmd)}", flush=True)
        rc = subprocess.run(cmd, cwd=ROOT, env=env, check=False).returncode
        print("::endgroup::", flush=True)
        if rc != 0:
            failed.append(" ".join(cmd))
    for cmd in failed:
        print(f"::error::failed: {cmd}")
    return 1 if failed else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--group", type=int)
    p.add_argument("--pool", choices=sorted(POOLS))
    a = p.parse_args()
    if (a.group is None) != (a.pool is None):
        p.error("--group and --pool go together")
    if subprocess.run(["cargo", "--version"], cwd=ROOT,
                      capture_output=True).returncode != 0:
        print("cargo is not on PATH")
        return 2
    if a.group is not None:
        return run_group(a.group, a.pool)
    names = combos()
    if not names:
        print(f"no feature combinations found in {COMBOS.relative_to(ROOT)}")
        return 2

    env = ci_env()
    if env is None:
        # Refuse rather than run a weaker check than CI. A gate that silently
        # drops `-Dwarnings` reports a pass CI will contradict, which is worse
        # than not running at all.
        print("no RUSTFLAGS in the workflow env block; refusing to check with "
              "weaker flags than CI")
        return 2

    failed, unchecked = [], []
    for f in names:
        if f == "wasm" and not has_wasm_target():
            unchecked.append((f, "wasm32-unknown-unknown target not installed"))
            continue
        cmd = lint_command(f)
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            failed.append((f, r.stdout + r.stderr))

    for f, why in unchecked:
        print(f"  {f}: NOT CHECKED -- {why}")
    if failed:
        for f, out in failed:
            print(f"\n  --- --features {f} ---")
            for line in report_lines(out):
                print(f"  {line}")
        print(f"\n{len(failed)} of {len(names)} feature combos failed.")
        return 1
    print(f"{len(names) - len(unchecked)} of {len(names)} combos checked, all clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
