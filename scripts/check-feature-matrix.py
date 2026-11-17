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
#
# A release pull request (head branch `release/...` in this repository) asks
# for the four runners too: on 2026-11-14 release PR #808's two Features jobs
# queued from 23:15Z while another pull request's job held one of the
# overflow pair. A fork's branch never does, whatever it is named: the check
# is on the head repository, not only on the name. This is capacity, not
# priority: GitHub documents no order among queued jobs.
MAIN_RUNNER: list[str] = ["self-hosted", "jetson"]
OVERFLOW_RUNNER: list[str] = ["self-hosted", "overflow"]
MAIN_EVENT = "push"
MAIN_REF = "refs/heads/main"
RELEASE_EVENT = "pull_request"
RELEASE_PREFIX = "release/"


def runner_labels(
    event_name: str,
    ref: str,
    head_ref: str = "",
    head_repo: "str | None" = None,
    repository: str = "",
) -> list[str]:
    """The labels the `features` job runs on for one event.

    `head_ref` is `github.head_ref`, `head_repo` is
    `github.event.pull_request.head.repo.full_name` (None when the event has
    no pull request or the fork was deleted) and `repository` is
    `github.repository`. Case is ignored, as GitHub's `==` and `startsWith`
    ignore it in a workflow expression.
    """
    texts = (event_name, ref, head_ref, repository)
    if not all(isinstance(t, str) for t in texts) or not (head_repo is None or isinstance(head_repo, str)):
        raise TypeError("the values are the text GitHub gives a workflow")
    main = event_name.casefold() == MAIN_EVENT and ref.casefold() == MAIN_REF
    release = (
        event_name.casefold() == RELEASE_EVENT
        and head_ref.casefold().startswith(RELEASE_PREFIX)
        and head_repo is not None
        and head_repo.casefold() == repository.casefold()
    )
    return list(MAIN_RUNNER if main or release else OVERFLOW_RUNNER)


def runs_on_expression() -> str:
    """`runner_labels` as the expression after `runs-on: ` in ci.yml.

    scripts/tests/test_feature_matrix_runner.py holds the workflow to this
    text and evaluates it against `runner_labels`.
    """
    def array(labels: list[str]) -> str:
        return "fromJSON('" + json.dumps(labels, separators=(",", ":")) + "')"

    return (
        f"${{{{ (github.event_name == '{MAIN_EVENT}' && github.ref == '{MAIN_REF}' "
        f"|| github.event_name == '{RELEASE_EVENT}' && startsWith(github.head_ref, '{RELEASE_PREFIX}') "
        "&& github.event.pull_request.head.repo.full_name == github.repository) "
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
    # `.githooks/pre-push` lints this row before every push (`hook_rows`).
    # CI runs the row the same with or without the mark.
    hook: bool = False

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
    them), `test=NAME` (run that test target with them), `needs=TOOL` (only
    a pool with TOOL can run it) or `hook` (the pre-push hook lints the row,
    see `hook_rows`), separated by spaces. `#` starts a comment.
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
            elif word == "hook":
                if combo.hook:
                    raise ValueError(f"line {n}: `hook` is listed twice")
                combo.hook = True
            else:
                raise ValueError(f"line {n}: unknown annotation {word!r}")
        if combo.hook:
            why = hook_refusal(combo)
            if why:
                raise ValueError(f"line {n}: {combo.features!r} cannot be marked `hook`: {why}")
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


# ── The rows the pre-push hook lints ──────────────────────────────────────
#
# The pre-commit hook builds only `--features full`, so a warning that exists
# only with a feature off passes it. In pull request #763 a binding read only
# under `#[cfg(feature = "hep")]` did, and would have failed this lint in CI
# for every feature set without `hep`. A row marked `hook` in
# .github/feature-combos.txt is linted by .githooks/pre-push with
# `lint_command`, the command CI runs for it, under a pass stamp of its own
# (scripts/gate-cache.py reads the rows through `hook_rows` as well). The
# mark is the one rule for which rows; the rest of the matrix stays in CI.

# A feature set whose step name is unambiguous: features of lower-case
# letters, digits and single hyphens, separated by commas.
_HOOK_FEATURES = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*(,[a-z0-9]+(-[a-z0-9]+)*)*$")
HOOK_STEP_PREFIX = "lint-"


def hook_refusal(combo: Combo) -> str:
    """Why this row cannot be marked `hook`; empty when it can."""
    if combo.needs:
        return f"it needs {', '.join(combo.needs)}, which the pushing machine may lack"
    if combo.features == "wasm":
        return "it is a check for another target, which the hook runs as its own step"
    if not _HOOK_FEATURES.match(combo.features):
        return "a step name holds lower-case letters, digits and single hyphens"
    return ""


def hook_step(features: str) -> str:
    """The pass-stamp step of one marked row.

    `--` between features, because a feature name may hold one hyphen
    (`mcp-http`): with one, `native,mcp-http` and `native,mcp,http` would
    share a step, and one's stamp would skip the other's lint.
    """
    return HOOK_STEP_PREFIX + features.replace(",", "--")


def hook_rows(items: list[Combo]) -> list[tuple[str, str, list[str]]]:
    """The marked rows in file order: (step, features, command)."""
    return [(hook_step(c.features), c.features, lint_command(c.features)) for c in items if c.hook]


def read_hook_rows() -> list[tuple[str, str, list[str]]]:
    """`hook_rows` of this tree's file; OSError or ValueError when unreadable."""
    return hook_rows(parse_combos(COMBOS.read_text(encoding="utf-8")))


def print_hook_rows() -> int:
    """One marked row per line for the hook: step, features, command, tab-separated."""
    try:
        rows = read_hook_rows()
    except (OSError, ValueError) as e:
        print(f"check-feature-matrix: .github/feature-combos.txt: {e}")
        return 2
    for step, features, command in rows:
        print(f"{step}\t{features}\t{' '.join(command)}")
    return 0


def lintable(items: list[Combo]) -> list[Combo]:
    """The rows the hook can lint: those `hook_refusal` accepts, in file order."""
    return [c for c in items if not hook_refusal(c)]


def lint_row(features: str) -> int:
    """Run one row's lint, as the hook's step for it.

    In the caller's environment, as the hook's other clippy steps run: the
    command itself carries `-D warnings`. A row the file does not list, or
    one the hook cannot lint (`hook_refusal`), is refused, so the hook cannot
    be pointed at a set the file does not name.
    """
    try:
        items = parse_combos(COMBOS.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"check-feature-matrix: .github/feature-combos.txt: {e}")
        return 2
    for combo in lintable(items):
        if combo.features == features:
            command = lint_command(features)
            return 1 if subprocess.run(command, cwd=ROOT, check=False).returncode != 0 else 0
    print(f"check-feature-matrix: {features!r} is not a row of .github/feature-combos.txt the hook can lint")
    return 2


# ── The rows a push lints (PREPUSH-LINTS-3-OF-22-FEATURE-ROWS) ───────────────
#
# Pull request #826 passed every local gate and failed CI's
# `cargo clippy --no-default-features --features g729 --tests`: a function
# only vcon/api callers reached was "never used" with g729 alone. The hook
# linted the 3 rows marked `hook`. `rows_for` picks the rows from the push's
# changed files and the feature gates on the `mod` lines that lead to them:
#
# * no Rust or Cargo file changed: the rows marked `hook`;
# * every changed Rust file is behind a feature gate: for each gate, the rows
#   with the fewest features that compile it, plus the rows marked `hook`;
# * otherwise, or when the changes cannot be read: every single-feature row
#   the hook can lint, plus the rows marked `hook`. A defect that needs two
#   features in an ungated file is then left to CI.
#
# Each row keeps a pass stamp of its own (scripts/gate-cache.py reads the rows
# through `lintable`). The rest of the matrix stays in CI.

_CFG_TOKEN = re.compile(r'\s*(?:(?P<word>[A-Za-z_][A-Za-z0-9_]*)|(?P<str>"[^"]*")|(?P<punct>[(),=]))')


def _minimal(alternatives) -> list[frozenset[str]]:
    """Distinct alternatives, none a superset of another, in a stable order."""
    unique = sorted(set(alternatives), key=lambda s: (len(s), sorted(s)))
    return [a for a in unique if not any(b < a for b in unique)]


def cfg_alternatives(expr: str) -> list[frozenset[str]]:
    """The feature sets, any one of which compiles code under `cfg(expr)`.

    `[frozenset()]` means no feature is needed. A predicate other than
    `feature = "..."` (a platform, `test`) needs no feature. `not(...)` is
    read as needing none: code compiled with a feature off is linted by the
    fallback, never left out. ValueError when the expression does not parse.
    """
    tokens = []
    pos = 0
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = _CFG_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot read cfg({expr})")
        tokens.append(m.group(m.lastgroup))
        pos = m.end()
    at = [0]

    def peek():
        return tokens[at[0]] if at[0] < len(tokens) else None

    def take(want=None):
        tok = peek()
        if tok is None or (want is not None and tok != want):
            raise ValueError(f"cannot read cfg({expr})")
        at[0] += 1
        return tok

    def predicate():
        word = take()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
            raise ValueError(f"cannot read cfg({expr})")
        if word in ("all", "any", "not") and peek() == "(":
            take("(")
            parts = []
            while peek() != ")":
                parts.append(predicate())
                if peek() == ",":
                    take(",")
                elif peek() != ")":
                    raise ValueError(f"cannot read cfg({expr})")
            take(")")
            if word == "not":
                if len(parts) != 1:
                    raise ValueError(f"cannot read cfg({expr})")
                return [frozenset()]
            if word == "any":
                return _minimal([a for part in parts for a in part]) if parts else [frozenset()]
            out = [frozenset()]
            for part in parts:
                out = _minimal([a | b for a in out for b in part])
            return out
        if peek() == "=":
            take("=")
            value = take()
            if not value.startswith('"'):
                raise ValueError(f"cannot read cfg({expr})")
            return [frozenset({value[1:-1]})] if word == "feature" else [frozenset()]
        return [frozenset()]

    result = predicate()
    if peek() is not None:
        raise ValueError(f"cannot read cfg({expr})")
    return result


def feature_closure(table: dict[str, list[str]], names) -> set[str]:
    """The features `names` turn on through Cargo's [features] table."""
    out: set[str] = set()
    todo = list(names)
    while todo:
        name = todo.pop()
        if name in out:
            continue
        out.add(name)
        todo.extend(e for e in table.get(name, []) if ":" not in e and "/" not in e)
    return out


def cargo_features(manifest: dict) -> dict[str, list[str]]:
    """The [features] table of a parsed Cargo.toml."""
    table = manifest.get("features", {})
    return {k: list(v) for k, v in table.items() if isinstance(v, list)}


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", text)


_ATTR_OR_MOD = re.compile(
    r"#(?P<inner>!?)\[\s*(?P<name>cfg|path)\b|"
    r"(?P<mod>(?<![A-Za-z0-9_])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<modname>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<end>[;{]))"
)
# An attribute the gate does not read (`#[doc(hidden)]`), between a cfg and its `mod`.
_OTHER_ATTR = re.compile(r"#\[[^\[\]]*\]")


def _bracket(text: str, start: int) -> tuple[str, int]:
    """The text inside the `[...]` that opens at or after `start`, and the end."""
    open_at = text.index("[", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[open_at + 1:i], i + 1
    raise ValueError("an attribute is not closed")


def _file_items(text: str):
    """The inner cfg alternatives of a file and its `mod x;` lines as
    (name, cfg alternatives, #[path] or None)."""
    text = _strip_comments(text)
    inner = [frozenset()]
    mods = []
    pending_cfg = [frozenset()]
    pending_path = None
    pos = 0
    while True:
        m = _ATTR_OR_MOD.search(text, pos)
        if not m:
            break
        if _OTHER_ATTR.sub("", text[pos:m.start()]).strip():
            # Another item came between: the pending attributes were its.
            pending_cfg = [frozenset()]
            pending_path = None
        if m.group("name"):
            body, pos = _bracket(text, m.start())
            if m.group("name") == "cfg":
                inside = body.strip()[len("cfg"):].strip()
                if not (inside.startswith("(") and inside.endswith(")")):
                    raise ValueError(f"cannot read #[{body}]")
                alts = cfg_alternatives(inside[1:-1])
                if m.group("inner"):
                    inner = _minimal([a | b for a in inner for b in alts])
                else:
                    pending_cfg = _minimal([a | b for a in pending_cfg for b in alts])
            else:
                pm = re.search(r'"([^"]*)"', body)
                pending_path = pm.group(1) if pm else None
            continue
        pos = m.end()
        if m.group("end") == ";":
            mods.append((m.group("modname"), pending_cfg, pending_path))
        pending_cfg = [frozenset()]
        pending_path = None
    return inner, mods


def module_gates(sources: dict[str, str]) -> dict[str, list[frozenset[str]]]:
    """Each Rust file's feature gate: the alternatives of `cfg_alternatives`
    that compile it, from the `mod` lines that lead from src/lib.rs and
    src/main.rs to it, and for a test target (tests/NAME.rs) from its
    `#![cfg(...)]`. A file no `mod` line reaches is absent: ungated.
    A file whose attributes do not parse is ungated."""
    gates: dict[str, list[frozenset[str]]] = {}

    def visit(path: str, outer: list[frozenset[str]]):
        if path in gates or path not in sources:
            return
        try:
            inner, mods = _file_items(sources[path])
        except ValueError:
            gates[path] = [frozenset()]
            return
        here = _minimal([a | b for a in outer for b in inner])
        gates[path] = here
        directory = path.rsplit("/", 1)[0]
        stem = path.rsplit("/", 1)[1][:-len(".rs")]
        child_dir = directory if stem in ("mod", "lib", "main") else f"{directory}/{stem}"
        for name, cfg, attr_path in mods:
            gate = _minimal([a | b for a in here for b in cfg])
            if attr_path is not None:
                candidates = [f"{directory}/{attr_path}"]
            else:
                candidates = [f"{child_dir}/{name}.rs", f"{child_dir}/{name}/mod.rs"]
            for c in candidates:
                if c in sources:
                    visit(c, gate)
                    break

    for root in ("src/lib.rs", "src/main.rs"):
        visit(root, [frozenset()])
    for path, text in sources.items():
        if re.fullmatch(r"tests/[^/]+\.rs", path):
            try:
                inner, _mods = _file_items(text)
            except ValueError:
                inner = [frozenset()]
            gates[path] = inner
    return gates


# Changed paths that can change what a feature row compiles.
_BUILD_ROOTS = ("src/", "tests/", "benches/", "examples/", ".cargo/")
_BUILD_FILES = ("Cargo.toml", "Cargo.lock", "build.rs")


def _is_build_input(path: str) -> bool:
    if path in _BUILD_FILES:
        return True
    return path.startswith(_BUILD_ROOTS) and (path.endswith(".rs") or path.startswith(".cargo/"))


def rows_for(changed, gates, items: list[Combo], table: dict[str, list[str]]) -> tuple[list[Combo], str]:
    """The rows a push lints and the one line that says why.

    `changed` is the list of changed paths, or None when it could not be
    read. `gates` is `module_gates`. `table` is Cargo's [features] table."""
    able = lintable(items)
    marked = [c for c in items if c.hook]
    singles = [c for c in able if "," not in c.features]
    chosen: list[Combo]
    if changed is None:
        why = "the pushed changes could not be read"
        chosen, kind = marked + singles, "fallback"
    else:
        build = [p for p in changed if _is_build_input(p)]
        ungated = [p for p in build if frozenset() in gates.get(p, [frozenset()])]
        if not build:
            chosen, kind = list(marked), "none"
        elif ungated:
            why = f"a changed file is outside every feature-gated module ({ungated[0]})"
            chosen, kind = marked + singles, "fallback"
        else:
            picked = []
            needs = sorted({"+".join(sorted(a)) for p in build for a in gates[p]})
            for p in build:
                for alt in gates[p]:
                    able_rows = [c for c in able if alt <= feature_closure(table, c.features.split(","))]
                    if able_rows:
                        fewest = min(len(c.features.split(",")) for c in able_rows)
                        picked += [c for c in able_rows if len(c.features.split(",")) == fewest]
            chosen, kind = marked + picked, "gated"
    seen = {id(c) for c in chosen}
    rows = [c for c in items if id(c) in seen]
    others = [c for c in items if id(c) not in seen and c.features != "wasm"]

    def n(count, one, many):
        return f"{count} {one if count == 1 else many}"

    tail = f"the other {n(len(others), 'combination stays', 'combinations stay')} in CI"
    if any(c.features == "wasm" for c in items):
        tail += " (`wasm` has its own step)"
    hook_part = f"the {n(len(marked), 'row', 'rows')} marked `hook`"
    if kind == "none":
        note = f"  feature rows: no Rust or Cargo file changed; linting {hook_part}; {tail}"
    elif kind == "fallback":
        note = (f"  feature rows: {why}; linting the {n(len(singles), 'single-feature row', 'single-feature rows')} "
                f"and {hook_part}; {tail}")
    else:
        extra = len([c for c in rows if not c.hook])
        note = (f"  feature rows: every changed Rust file is behind a feature gate ({', '.join(needs)}); "
                f"linting {n(extra, 'row', 'rows')} that compile them and {hook_part}; {tail}")
    return rows, note


def changed_files(refs_text: str, git) -> list[str] | None:
    """The paths the pushed commits change, from pre-push's input; `git(*args)`
    returns standard output or None. None when a line or a range cannot be
    read: a new branch is measured from origin/main, an update from the
    remote's commit when this clone has it."""
    out: list[str] = []
    for line in refs_text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            return None
        _local_ref, local, _remote_ref, remote = fields
        if local == "0" * 40:
            continue
        base = None
        if remote != "0" * 40 and git("cat-file", "-e", f"{remote}^{{commit}}") is not None:
            base = remote
        if base is None:
            base = git("merge-base", local, "refs/remotes/origin/main")
        if not base:
            return None
        diff = git("diff", "--name-only", base, local)
        if diff is None:
            return None
        out += [p for p in diff.splitlines() if p]
    return list(dict.fromkeys(out))


def _git_out(*args) -> str | None:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else None


def print_push_rows(refs_text: str) -> int:
    """`--push-rows`: the rows this push lints, as `--hook-rows` prints them;
    the line that says why goes to standard error."""
    try:
        items = parse_combos(COMBOS.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"check-feature-matrix: .github/feature-combos.txt: {e}")
        return 2
    try:
        import tomllib
        table = cargo_features(tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        table = {}
    sources = {}
    for p in list((ROOT / "src").rglob("*.rs")) + list((ROOT / "tests").glob("*.rs")):
        try:
            sources[p.relative_to(ROOT).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    rows, note = rows_for(changed_files(refs_text, _git_out), module_gates(sources), items, table)
    print(note, file=sys.stderr)
    for c in rows:
        print(f"{hook_step(c.features)}\t{c.features}\t{' '.join(lint_command(c.features))}")
    return 0


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
    p.add_argument("--hook-rows", action="store_true",
                   help="print the rows marked `hook`: step, features, command")
    p.add_argument("--lint-row", metavar="FEATURES",
                   help="lint one row the hook can lint, as .githooks/pre-push does")
    p.add_argument("--push-rows", action="store_true",
                   help="read pre-push's input; print the rows this push lints")
    a = p.parse_args()
    if (a.group is None) != (a.pool is None):
        p.error("--group and --pool go together")
    if sum([a.group is not None, a.hook_rows, a.lint_row is not None, a.push_rows]) > 1:
        p.error("--group, --hook-rows, --lint-row and --push-rows are separate modes")
    if a.hook_rows:
        return print_hook_rows()
    if a.push_rows:
        return print_push_rows(sys.stdin.read())
    if subprocess.run(["cargo", "--version"], cwd=ROOT,
                      capture_output=True).returncode != 0:
        print("cargo is not on PATH")
        return 2
    if a.lint_row is not None:
        return lint_row(a.lint_row)
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
