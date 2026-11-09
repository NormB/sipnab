#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Is a change exactly a release bump, so the hooks may run the release gates alone?

    release-only.py staged              the index against HEAD (the pre-commit hook)
    release-only.py push < <stdin>      every branch range pre-push's stdin names (the pre-push hook)
    release-only.py range BASE HEAD     every commit in BASE..HEAD
    release-only.py tests               the release gates' test targets, as `--test` flags

The 0.5.238 release commit f151b38d8 spent 14 minutes in the pre-commit hook
and 15 in the pre-push hook, running the whole suite and every tree gate, on a
diff of 24 changed lines: the version moving from 0.5.237 to 0.5.238 in 13
files and the CHANGELOG heading `## [Unreleased]` becoming
`## [0.5.238] - 2026-11-08`. The release pull request's CI then ran the whole
suite on the same tree (33 minutes), and that run stays: it is what proves the
tree before the tag.

THE RULE (`classify`, the one place it is written). A change is release-only
when, and only when:

* the version in Cargo.toml's [package] table moves forward, x.y.z to a
  larger x.y.z, and Cargo.toml changes that line;
* every changed file is modified in place: no file is added, deleted,
  renamed, binary, or given a new mode;
* every changed file is one a release bump touches (RELEASE_FILES and the
  Markdown under docs/ and website/content/docs/);
* every hunk replaces as many lines as it removes, and each new line is the
  old line with every whole old version token replaced by the new version;
  or, in the CLI reference and its copies (SINCE_FILES), a Since cell
  `| Unreleased |` becoming `| <new> |` (scripts/flag-since.py --write);
* website/config.toml changes only `version = "<old>"`. `published_version`
  moves after the assets exist, never in the release commit;
* CHANGELOG.md changes exactly one line: `## [Unreleased]` becomes
  `## [<new>] - YYYY-MM-DD`, with a real date.

Anything else -- a line that changes more than the version, a CHANGELOG entry
edited beside the heading (the 0.5.237 commit removed a `**Held:**` line), a
diff this cannot parse, git failing -- is not release-only: exit 1, and the
hooks run every gate. A range is release-only when it holds at least one
commit, no merge commit, and every commit is release-only against its parent.

Exit 0 and one line naming the proof when the change is release-only, exit 1
and one line saying why not otherwise.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
import subprocess
import sys

# The files a release bump changes, besides Markdown under DOC_ROOTS.
RELEASE_FILES = frozenset({
    "Cargo.toml",
    "Cargo.lock",
    "fuzz/Cargo.lock",
    "website/config.toml",
    "man/sipnab.1",
    "CHANGELOG.md",
    "website/static/llms-full.txt",
    "website/static/llms.txt",
})
DOC_ROOTS = ("docs/", "website/content/docs/")
# The CLI reference, where flag-since.py moves the Since column, and the copies
# scripts/build-site-pages.py makes of it.
SINCE_FILES = frozenset({"docs/cli-reference.md", "website/content/docs/cli.md", "website/static/llms-full.txt"})

# The test targets a release-only commit runs in the pre-commit hook in place
# of the suite: the version markers and the man page (docs_drift_test), the
# site copies (dev_docs_drift_test, site_journey_test), the Since column
# (cli_flag_since_test), the MCP since-versions (mcp_since_version_test), the
# CHANGELOG against the tags (release_delivery_test), the advertised release
# (release_completeness_test) and the release surface (release_surface_test).
# The pull request's CI still runs every test on the same tree.
RELEASE_TESTS = (
    "cli_flag_since_test",
    "dev_docs_drift_test",
    "docs_drift_test",
    "mcp_since_version_test",
    "bpf_load_verification_test",
    "release_completeness_test",
    "release_delivery_test",
    "release_gate_visibility_test",
    "release_surface_test",
    "site_journey_test",
)

ZERO = "0" * 40

_SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_HEADING = re.compile(r"## \[(?P<v>[^\]]+)\] - (?P<d>\d{4}-\d{2}-\d{2})")


@dataclasses.dataclass(frozen=True)
class FileChange:
    """One file of a diff: `kind` is modify, add, delete, rename, mode,
    binary or reshape; `pairs` are (removed line, added line), hunk by hunk;
    `adds` are the lines of hunks that only add."""

    path: str
    kind: str
    pairs: list
    adds: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class Commit:
    sha: str
    parents: int
    changes: list | None
    old: str | None
    new: str | None
    published_old: str | None = None
    published_new: str | None = None


@dataclasses.dataclass(frozen=True)
class Verdict:
    ok: bool
    line: str


def _version(text: str | None) -> tuple[int, int, int] | None:
    m = _SEMVER.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(g) for g in m.groups()) if m else None


def _token(version: str) -> re.Pattern:
    """`version` as a whole token: not inside a longer number or version."""
    return re.compile(r"(?<![0-9A-Za-z.])" + re.escape(version) + r"(?![0-9A-Za-z]|\.[0-9])")


def _in_bump_set(path: str) -> bool:
    return path in RELEASE_FILES or (path.startswith(DOC_ROOTS) and path.endswith(".md"))


def _line_moves(path: str, removed: str, added: str, old: str, new: str) -> bool:
    """Whether `added` is `removed` with the version moved, as the rule allows."""
    if path == "website/config.toml":
        return removed == f'version = "{old}"' and added == f'version = "{new}"'
    tok = _token(old)
    if tok.search(removed) and tok.sub(new, removed) == added:
        return True
    cell = "| Unreleased |"
    return path in SINCE_FILES and removed.count(cell) == 1 and removed.replace(cell, f"| {new} |") == added


def classify(changes: list | None, old: str | None, new: str | None) -> Verdict:
    """The rule. `changes` is `parse_diff`'s answer (None: unreadable); `old`
    and `new` are the [package] versions before and after."""
    full = "release-only: no --"
    if changes is None:
        return Verdict(False, f"{full} the diff could not be read")
    if not changes:
        return Verdict(False, f"{full} nothing changed")
    vo, vn = _version(old), _version(new)
    if vo is None or vn is None:
        return Verdict(False, f"{full} the crate version is not x.y.z ({old!r} -> {new!r})")
    if vn <= vo:
        return Verdict(False, f"{full} the crate version does not move forward ({old} -> {new})")
    by_path = {c.path: c for c in changes}
    for c in changes:
        if c.kind == "reshape":
            return Verdict(False, f"{full} {c.path} adds or removes lines")
        if c.kind != "modify":
            return Verdict(False, f"{full} {c.path} is a {c.kind}, not a modification in place")
        if c.adds:
            return Verdict(False, f"{full} {c.path} adds lines")
        if not _in_bump_set(c.path):
            return Verdict(False, f"{full} {c.path} is not a file a release bump changes")
        if c.path == "CHANGELOG.md":
            continue
        for removed, added in c.pairs:
            if not _line_moves(c.path, removed, added, old, new):
                return Verdict(False, f"{full} {c.path} changes more than the version: {added[:80]!r}")
    cargo = by_path.get("Cargo.toml")
    if cargo is None or (f'version = "{old}"', f'version = "{new}"') not in cargo.pairs:
        return Verdict(False, f"{full} Cargo.toml does not move the crate version")
    log = by_path.get("CHANGELOG.md")
    if log is None:
        return Verdict(False, f"{full} CHANGELOG.md does not name the release")
    if len(log.pairs) != 1:
        return Verdict(False, f"{full} CHANGELOG.md changes {len(log.pairs)} lines, not the heading alone")
    removed, added = log.pairs[0]
    m = _HEADING.fullmatch(added)
    if removed != "## [Unreleased]" or not m or m.group("v") != new:
        return Verdict(False, f"{full} CHANGELOG.md's change is not `## [Unreleased]` -> `## [{new}] - <date>`")
    try:
        datetime.date.fromisoformat(m.group("d"))
    except ValueError:
        return Verdict(False, f"{full} CHANGELOG.md's release date {m.group('d')} is not a date")
    lines = sum(len(c.pairs) for c in changes)
    return Verdict(
        True,
        f"release-only: {old} -> {new}, {lines} lines in {len(changes)} files, every one the version, "
        "a Since cell or the CHANGELOG heading",
    )


# ── The advertisement commit (RELEASE-FAST C) ───────────────────────────────
#
# The phase-two pull request is gone. Its changes ride in the next release
# pull request as one commit, made by `scripts/release-records.py write
# <previous>` before the bump: published_version, release_date and the
# download markers move to the release before, the binary-ceiling line and the
# eBPF ledger row for that release are added, and the mirrors follow.

# The files scripts/release-records.py write changes.
ADVERTISE_FILES = frozenset({
    "website/config.toml",
    "docs/install.md",
    "website/content/docs/install.md",
    "docs/internals/uprobe-capture.md",
    "website/content/docs/internals/uprobe-capture.md",
    "website/static/llms-full.txt",
})
# The eBPF ledger and its copies: each adds exactly the new release's row.
LEDGER_FILES = frozenset({
    "docs/internals/uprobe-capture.md",
    "website/content/docs/internals/uprobe-capture.md",
})
_CEILING_LINE = re.compile(r"#   (\d+\.\d+\.\d+)  [0-9]{1,3}(?:,[0-9]{3})+ bytes   \((?:unchanged|[+-][0-9,]+), "
                           r"leaving [0-9,]+ bytes of headroom under \d+ MB\)")
_RELEASE_DATE = re.compile(r'release_date = "(\d{4}-\d{2}-\d{2})"')


def _ledger_row(line: str, version: str) -> bool:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return (line.startswith("| ") and line.endswith(" |") and len(cells) == 6 and cells[0] == version
            and cells[5].startswith("attached"))


def _real_date(text: str) -> bool:
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def classify_advertise(changes: list | None, crate_old: str | None, crate_new: str | None,
                       pub_old: str | None, pub_new: str | None) -> Verdict:
    """Whether a commit is exactly an advertisement commit (see above)."""
    full = "release-only: no --"
    if changes is None:
        return Verdict(False, f"{full} the diff could not be read")
    if not changes:
        return Verdict(False, f"{full} nothing changed")
    if crate_old is None or crate_old != crate_new:
        return Verdict(False, f"{full} an advertisement does not move the crate version ({crate_old} -> {crate_new})")
    po, pn = _version(pub_old), _version(pub_new)
    if po is None or pn is None or pn <= po:
        return Verdict(False, f"{full} published_version does not move forward ({pub_old} -> {pub_new})")
    if pub_new != crate_new:
        return Verdict(False, f"{full} published_version moves to {pub_new}, not the crate version {crate_new}")
    by_path = {c.path: c for c in changes}
    # A whole token, or a tag name: install.md names `refs/tags/v<version>`.
    tok = re.compile(r"(?:(?<=\bv)|(?<![0-9A-Za-z.]))" + re.escape(pub_old) + r"(?![0-9A-Za-z]|\.[0-9])")
    for c in changes:
        if c.kind != "modify":
            return Verdict(False, f"{full} {c.path} is a {c.kind}, not a modification in place")
        if c.path not in ADVERTISE_FILES:
            return Verdict(False, f"{full} {c.path} is not a file an advertisement changes")
        for removed, added in c.pairs:
            if c.path == "website/config.toml" and removed.startswith("release_date = "):
                m = _RELEASE_DATE.fullmatch(added)
                if _RELEASE_DATE.fullmatch(removed) and m and _real_date(m.group(1)):
                    continue
            if not (tok.search(removed) and tok.sub(pub_new, removed) == added):
                return Verdict(False, f"{full} {c.path} changes more than the advertised version: {added[:80]!r}")
        if c.path == "website/config.toml":
            ceilings = [a for a in c.adds if (m := _CEILING_LINE.fullmatch(a)) and m.group(1) == pub_new]
            if len(c.adds) != 1 or len(ceilings) != 1:
                return Verdict(False, f"{full} website/config.toml must add exactly the {pub_new} binary-ceiling "
                                      f"line, and adds {len(c.adds)} line(s)")
        elif c.path in LEDGER_FILES or c.path == "website/static/llms-full.txt":
            if c.path in LEDGER_FILES and len(c.adds) != 1:
                return Verdict(False, f"{full} {c.path} must add exactly the {pub_new} uprobe ledger row")
            if len(c.adds) > 1 or not all(_ledger_row(a, pub_new) for a in c.adds):
                return Verdict(False, f"{full} {c.path} adds a line that is not the {pub_new} ledger row, attached")
        elif c.adds:
            return Verdict(False, f"{full} {c.path} adds lines")
    config = by_path.get("website/config.toml")
    if config is None or (f'published_version = "{pub_old}"', f'published_version = "{pub_new}"') not in config.pairs:
        return Verdict(False, f"{full} website/config.toml does not move published_version")
    if "docs/internals/uprobe-capture.md" not in by_path:
        return Verdict(False, f"{full} docs/internals/uprobe-capture.md does not record the {pub_new} uprobe load")
    lines = sum(len(c.pairs) + len(c.adds) for c in changes)
    return Verdict(
        True,
        f"release-only: advertises {pub_new} in place of {pub_old}, {lines} lines in {len(changes)} files, "
        "every one the advertised version or a release record",
    )


def classify_range(commits: list) -> Verdict:
    """Every commit release-only against its parent (a bump or an
    advertisement), none a merge, at least one."""
    if not commits:
        return Verdict(False, "release-only: no -- no commits to judge")
    for c in commits:
        if c.parents != 1:
            return Verdict(False, f"release-only: no -- {c.sha[:9]} is a merge commit")
        v = classify(c.changes, c.old, c.new)
        if not v.ok:
            a = classify_advertise(c.changes, c.old, c.new, c.published_old, c.published_new)
            if a.ok:
                continue
            return Verdict(False, f"{v.line} (in {c.sha[:9]})")
    names = ", ".join(c.sha[:9] for c in commits)
    return Verdict(True, f"release-only: {names}, each {commits[0].old} -> {commits[-1].new} and nothing else")


def decide_push(refs: list, ranges: dict) -> Verdict:
    """A push is release-only when it updates branches only, creates or moves
    at least one, and every pushed branch's range is release-only. `refs` are
    pre-push's (local ref, local sha, remote ref, remote sha); `ranges` maps a
    local sha to its range's Verdict (missing: it could not be judged)."""
    full = "release-only push: no --"
    if not refs:
        return Verdict(False, f"{full} nothing is being pushed")
    tags = [r[2] for r in refs if not r[2].startswith("refs/heads/")]
    if tags:
        return Verdict(False, f"{full} the push updates {tags[0]}, not a branch")
    moved = [r for r in refs if r[1] != ZERO]
    if not moved:
        return Verdict(False, f"{full} the push only deletes branches")
    for _local_ref, local, remote, _remote_sha in moved:
        v = ranges.get(local)
        if v is None:
            return Verdict(False, f"{full} the commits pushed to {remote} could not be judged")
        if not v.ok:
            return Verdict(False, f"{full} {remote}: {v.line}")
    names = ", ".join(r[2].removeprefix("refs/heads/") for r in moved)
    return Verdict(True, f"release-only push: {names} carry only release bumps ({ranges[moved[0][1]].line})")


def push_base(ref: tuple, has_commit, merge_base) -> str | None:
    """Where a pushed branch's new commits start: the remote sha when the
    branch exists there and this clone has that commit, else the merge base
    of the local sha with origin/main; None when neither is known."""
    remote_sha = ref[3]
    if remote_sha != ZERO and has_commit(remote_sha):
        return remote_sha
    return merge_base(ref[1])


# ── Reading the inputs ─────────────────────────────────────────────────────

_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def parse_diff(text: str) -> list | None:
    """`git diff -U0 --no-renames --full-index` output as FileChanges, or None
    when a line does not fit that shape."""
    files: list[FileChange] = []
    cur = None
    removed: list[str] = []
    added: list[str] = []
    want = (0, 0)

    def close_hunk() -> bool:
        nonlocal removed, added
        if (len(removed), len(added)) != want:
            return False
        if not removed and added:
            # A hunk that only adds: the advertisement's release records.
            files[-1].adds.extend(added)
        elif len(removed) != len(added):
            # A hunk that removes lines, or replaces a different number of
            # them, is no version substitution.
            files[-1] = dataclasses.replace(files[-1], kind="reshape")
        else:
            files[-1].pairs.extend(zip(removed, added))
        removed, added = [], []
        return True

    for line in text.split("\n"):
        if line.startswith("diff --git "):
            if cur is not None and not close_hunk():
                return None
            m = re.fullmatch(r"diff --git a/(\S+) b/(\S+)", line)
            if not m:
                return None
            cur = m.group(2)
            files.append(FileChange(cur, "modify" if m.group(1) == m.group(2) else "rename", []))
            want = (0, 0)
            continue
        if cur is None:
            if line.strip():
                return None
            continue
        if line.startswith(("new file mode", "deleted file mode", "old mode", "new mode", "Binary files",
                            "rename from", "rename to", "similarity index", "copy from", "copy to")):
            kind = {"new": "add", "del": "delete", "old": "mode", "Bin": "binary"}.get(line[:3], "rename")
            if files[-1].kind == "modify":
                files[-1] = dataclasses.replace(files[-1], kind=kind)
            continue
        if line.startswith(("index ", "--- ", "+++ ")):
            continue
        m = _HUNK.match(line)
        if m:
            if not close_hunk():
                return None
            want = (int(m.group(1) or 1), int(m.group(2) or 1))
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("\\"):
            continue  # "\ No newline at end of file"
        elif line == "":
            continue
        else:
            return None
    if cur is not None and not close_hunk():
        return None
    return files


def package_version(toml_text: str | None) -> str | None:
    """The `version` of Cargo.toml's [package] table, None when it has none."""
    if toml_text is None:
        return None
    table = None
    for raw in toml_text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            table = line
            continue
        if table == "[package]":
            m = re.fullmatch(r'version\s*=\s*"([^"]*)"', line)
            if m:
                return m.group(1)
    return None


def _git(*args: str) -> str | None:
    out = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return out.stdout if out.returncode == 0 else None


_DIFF = ("-U0", "--no-color", "--no-ext-diff", "--no-renames", "--full-index")


def published(toml_text: str | None) -> str | None:
    """website/config.toml's `published_version`, None when it has none."""
    m = re.search(r'(?m)^published_version = "([^"]*)"$', toml_text) if toml_text else None
    return m.group(1) if m else None


def staged() -> Verdict:
    diff = _git("diff", "--cached", *_DIFF)
    changes = parse_diff(diff) if diff is not None else None
    old, new = package_version(_git("show", "HEAD:Cargo.toml")), package_version(_git("show", ":Cargo.toml"))
    v = classify(changes, old, new)
    if v.ok:
        return v
    a = classify_advertise(changes, old, new, published(_git("show", "HEAD:website/config.toml")),
                           published(_git("show", ":website/config.toml")))
    return a if a.ok else v


def commit_range(base: str, head: str) -> Verdict:
    shas = _git("rev-list", "--reverse", f"{base}..{head}")
    if shas is None:
        return Verdict(False, f"release-only: no -- git could not list {base}..{head}")
    commits = []
    for sha in shas.split():
        parents = _git("rev-list", "--parents", "-n", "1", sha)
        diff = _git("diff", *_DIFF, f"{sha}^", sha)
        commits.append(Commit(
            sha,
            len(parents.split()) - 1 if parents else 0,
            parse_diff(diff) if diff is not None else None,
            package_version(_git("show", f"{sha}^:Cargo.toml")),
            package_version(_git("show", f"{sha}:Cargo.toml")),
            published(_git("show", f"{sha}^:website/config.toml")),
            published(_git("show", f"{sha}:website/config.toml")),
        ))
    return classify_range(commits)


def push(text: str) -> Verdict:
    refs = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            return Verdict(False, "release-only push: no -- a pushed ref line could not be read")
        refs.append(tuple(fields))

    def has_commit(sha: str) -> bool:
        return _git("cat-file", "-e", f"{sha}^{{commit}}") is not None

    def merge_base(local: str) -> str | None:
        out = _git("merge-base", "origin/main", local)
        return out.strip() if out and out.strip() else None

    ranges = {}
    for ref in refs:
        if ref[1] == ZERO or not ref[2].startswith("refs/heads/"):
            continue
        base = push_base(ref, has_commit, merge_base)
        if base is not None:
            ranges[ref[1]] = commit_range(base, ref[1])
    return decide_push(refs, ranges)


def main(argv: list[str]) -> int:
    if argv == ["tests"]:
        print(" ".join(f"--test {t}" for t in RELEASE_TESTS))
        return 0
    if argv == ["push"]:
        v = push(sys.stdin.read())
    elif argv == ["staged"]:
        v = staged()
    elif len(argv) == 3 and argv[0] == "range":
        v = commit_range(argv[1], argv[2])
    else:
        print("usage: release-only.py staged | push | range BASE HEAD | tests", file=sys.stderr)
        return 2
    print(v.line)
    return 0 if v.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
