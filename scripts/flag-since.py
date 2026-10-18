#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Write the Since column of docs/cli-reference.md from the release tags.

Every flag row of the page's flag tables names the first release whose command
line accepted the flag. The version comes from the tagged history of
src/cli.rs, never from CHANGELOG.md.

The rules:

- A release is a tag of the form vX.Y.Z, the same rule scripts/doc-history.py
  applies. Pre-release tags (v0.1.0-alpha, v0.2.0-beta) and any other tag are
  not releases. Releases are ordered by version number, not by tag date.
- A flag is an `#[arg(...)]` field of src/cli.rs with a long name: `long = "x"`
  names it, and a bare `long` takes the field's name with `_` written `-`.
  `alias`, `aliases`, `visible_alias` and `visible_aliases` are the same flag
  under another name. A positional argument (no `long`, no `short`) is named
  `<VALUE_NAME>`, from its `value_name` or else its upper-cased field name.
- The current flags are the ones the working tree's src/cli.rs declares.
- A flag's Since is the oldest release whose src/cli.rs declares the flag
  under any of its current names. A flag removed and later restored keeps
  that first release. A version that was bumped but never tagged was never
  released, so a flag first declared there is Since the next tagged release,
  the one users first received it in.
- A flag no release declares is `Unreleased` while CHANGELOG.md's first
  `## [` heading is `[Unreleased]`. On the release commit, where that heading
  is a cut `[X.Y.Z]` equal to Cargo.toml's version and no vX.Y.Z tag exists
  yet, it is `X.Y.Z`: the release that commit becomes when tagged. Tagging it
  changes nothing, because the tag's history then gives the same X.Y.Z. A cut
  heading that differs from Cargo.toml's version is refused.

A clone without vX.Y.Z tags cannot answer, and the script refuses rather than
calling every flag Unreleased.

Usage:
    flag-since.py [--repo DIR] (--write | --check)

--write rewrites the column in place (adding it before Description where a
flag table lacks it). --check changes nothing and exits 1 when the page differs
from what --write would produce, naming each row. Both exit 2 on an error,
including a clone without tags. Neither writes to git.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tomllib

RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
SOURCE = "src/cli.rs"
DOC = "docs/cli-reference.md"
UNRELEASED = "Unreleased"
FLAG_HEADER = "| Flag | Value | Default | Description |"
SINCE_HEADER = "| Flag | Value | Default | Since | Description |"
SINCE_RULE = "|------|-------|---------|-------|-------------|"
SINCE = 3  # index of the Since cell among a row's cells
WIDTH = 5  # cells in a flag row that has the Since cell


class FlagSinceError(Exception):
    """The history or the page cannot answer."""


# -- reading src/cli.rs ------------------------------------------------------

def strip_comments(src: str) -> str:
    """`src` with every Rust comment blanked; string and char literals kept."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif literal_at(src, i) is not None:
            j = literal_at(src, i)
            out.append(src[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def literal_at(src: str, i: int):
    """Index just past a string or char literal starting at `i`, else None."""
    c = src[i]
    starts_raw = (c == "r" and re.match(r'r#*"', src[i:i + 8])
                  and not (i and (src[i - 1].isalnum() or src[i - 1] == "_")))
    if c == '"' or starts_raw:
        return literal_end(src, i)
    if c == "'":
        m = re.match(r"'(\\.[^']*|[^'\\])'", src[i:])
        return i + len(m.group(0)) if m else None
    return None


def literal_end(src: str, i: int) -> int:
    """Index just past the string literal (plain or raw) starting at `i`."""
    if src[i] == "r":
        hashes = re.match(r"r(#*)\"", src[i:]).group(1)
        close = '"' + hashes
        j = src.find(close, i + 2 + len(hashes))
        if j < 0:
            raise FlagSinceError(f"unterminated raw string at offset {i}")
        return j + len(close)
    j = i + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
        elif src[j] == '"':
            return j + 1
        else:
            j += 1
    raise FlagSinceError(f"unterminated string at offset {i}")


def balanced_end(src: str, i: int) -> int:
    """Index just past the bracket group opening at `i` (strings skipped)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    j = i
    while j < len(src):
        c = src[j]
        end = literal_at(src, j)
        if end is not None:
            j = end
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif stack and c == stack[-1]:
            stack.pop()
            if not stack:
                return j + 1
        j += 1
    raise FlagSinceError(f"unbalanced bracket at offset {i}")


def split_top(body: str) -> list:
    """`body` split on the commas outside any bracket or string."""
    items, depth, start, j = [], 0, 0, 0
    while j < len(body):
        c = body[j]
        end = literal_at(body, j)
        if end is not None:
            j = end
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            items.append(body[start:j].strip())
            start = j + 1
        j += 1
    items.append(body[start:].strip())
    return [i for i in items if i]


def string_value(expr: str):
    m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', expr.strip())
    return m.group(1) if m else None


FIELD = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:r#)?([A-Za-z_]\w*)\s*:")


def declared_args(src: str) -> list:
    """Every flag the source declares, as a tuple of its long names.

    The flag's own name comes first, then its aliases in declaration order.
    A positional argument is the one-tuple `("<VALUE_NAME>",)`. Short-only
    arguments are not flags and are left out.
    """
    text = strip_comments(src)
    out = []
    pos = 0
    while True:
        start = text.find("#[arg(", pos)
        if start < 0:
            return out
        items = []
        j = start
        # This attribute, any others on the same field, then the field.
        while True:
            while j < len(text) and text[j].isspace():
                j += 1
            if text.startswith("#[arg(", j):
                end = balanced_end(text, j + 5)
                items += split_top(text[j + 6:end - 1])
                j = balanced_end(text, j + 1)
            elif text.startswith("#[", j) or text.startswith("#![", j):
                j = balanced_end(text, text.index("[", j))
            else:
                break
        pos = j
        m = FIELD.match(text, j)
        if not m:
            continue
        names = arg_names(items, m.group(1))
        if names:
            out.append(names)


def arg_names(items: list, field: str):
    long, aliases, short, value_name = None, [], False, None
    for item in items:
        key, _, expr = item.partition("=")
        key, expr = key.strip(), expr.strip()
        if key == "long":
            long = string_value(expr) if expr else field.replace("_", "-")
        elif key == "short":
            short = True
        elif key in ("alias", "visible_alias"):
            aliases.append(string_value(expr))
        elif key in ("aliases", "visible_aliases"):
            aliases += [string_value(e) for e in split_top(expr.strip()[1:-1])]
        elif key == "value_name":
            value_name = string_value(expr)
    if long:
        return (long, *[a for a in aliases if a])
    if not short:
        return (f"<{value_name or field.upper()}>",)
    return None


# -- dating flags against the release tags -----------------------------------

def git(repo, *args, stdin=None) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                       text=True, input=stdin)
    if r.returncode != 0:
        raise FlagSinceError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def releases(repo) -> list:
    """`(tag, "X.Y.Z")` for every vX.Y.Z tag, oldest version first."""
    out = []
    for tag in git(repo, "tag", "--list", "v*").split():
        m = RELEASE.match(tag)
        if m:
            out.append((tuple(int(g) for g in m.groups()), tag))
    if not out:
        raise FlagSinceError("no v* tags in this clone; fetch tags "
                             "(git fetch --tags, or fetch-depth: 0 with fetch-tags: true)")
    return [(tag, tag[1:]) for _, tag in sorted(out)]


def sources_at(repo, tags: list, source: str) -> dict:
    """`{tag: text of source at tag}`; a tag without the file maps to ""."""
    request = "".join(f"{tag}:{source}\n" for tag in tags)
    r = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], input=request.encode(),
                       capture_output=True)
    if r.returncode != 0:
        raise FlagSinceError(f"git cat-file --batch: {r.stderr.decode().strip()}")
    data, out, i = r.stdout, {}, 0
    for tag in tags:
        nl = data.index(b"\n", i)
        header = data[i:nl].decode()
        i = nl + 1
        if header.endswith(" missing"):
            out[tag] = ""
            continue
        size = int(header.split()[2])
        out[tag] = data[i:i + size].decode()
        i += size + 1
    return out


def pending_release(repo, tags: list):
    """The version the working tree is the release commit of, or None.

    CHANGELOG.md's first `## [` heading is `[Unreleased]` between releases,
    and None is the answer. Cutting a release renames it `[X.Y.Z]` in the
    same commit that sets Cargo.toml's version to X.Y.Z; until the tag
    vX.Y.Z exists, that commit is the release and X.Y.Z is the answer. Once
    the tag exists, its history answers instead, with the same X.Y.Z.
    """
    try:
        changelog = (repo / "CHANGELOG.md").read_text()
        manifest = tomllib.loads((repo / "Cargo.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise FlagSinceError(f"cannot read CHANGELOG.md and Cargo.toml: {e}") from e
    m = re.search(r"^## \[([^\]]+)\]", changelog, re.M)
    if not m:
        raise FlagSinceError("CHANGELOG.md has no `## [` heading")
    heading = m.group(1)
    if heading == UNRELEASED:
        return None
    version = manifest.get("package", {}).get("version")
    if heading != version:
        raise FlagSinceError(
            f"CHANGELOG.md's first heading is [{heading}] but Cargo.toml's version is "
            f"{version}: a release commit names the same version in both, and between "
            "releases the first heading is [Unreleased]")
    return None if f"v{heading}" in tags else heading


def flag_since(repo, source: str = SOURCE) -> dict:
    """`{name: "X.Y.Z" | "Unreleased"}` for every name of every current flag."""
    repo = pathlib.Path(repo)
    tagged = releases(repo)
    unreleased = pending_release(repo, [t for t, _ in tagged]) or UNRELEASED
    texts = sources_at(repo, [t for t, _ in tagged], source)
    declared = [(version, {n for a in declared_args(texts[tag]) for n in a})
                for tag, version in tagged]
    current = declared_args((repo / source).read_text())
    out = {}
    for names in current:
        first = next((v for v, seen in declared if seen.intersection(names)), unreleased)
        for n in names:
            out[n] = first
    return out


# -- the table in docs/cli-reference.md --------------------------------------

def cells(row: str) -> list:
    """`row` split on unescaped `|`, each cell's text kept as written."""
    parts, cell, escaped = [], [], False
    for c in row:
        if c == "|" and not escaped:
            parts.append("".join(cell))
            cell = []
        else:
            cell.append(c)
        escaped = c == "\\" and not escaped
    parts.append("".join(cell))
    return parts  # leading "" and trailing "" around the cells


def row_names(first: str) -> list:
    names = []
    for tok in first.split("`")[1::2]:
        if tok.startswith("--"):
            names.append(re.split(r"[= \[]", tok[2:], maxsplit=1)[0])
        elif tok.startswith("<"):
            names.append(tok.rstrip("."))
    return names


def rewrite(doc: str, since: dict):
    """`(doc with every flag row's Since cell set, errors)`."""
    out, errors = [], []
    in_table = False
    for line in doc.split("\n"):
        if line.rstrip() in (FLAG_HEADER, SINCE_HEADER):
            in_table = True
            out.append(SINCE_HEADER)
            continue
        if not in_table or not line.startswith("|"):
            in_table = False
            out.append(line)
            continue
        parts = cells(line)
        if line.startswith("|-"):
            out.append(SINCE_RULE)
            continue
        first = parts[1].strip()
        names = row_names(first)
        found = {since[n] for n in names if n in since}
        if not names or any(n not in since for n in names):
            errors.append(f"{first}: the row names no flag src/cli.rs declares")
            out.append(line)
            continue
        if len(found) > 1:
            errors.append(f"{first}: the row names flags of different releases")
            out.append(line)
            continue
        cell = f" {found.pop()} "
        width = len(parts) - 2
        if width == WIDTH:
            parts[1 + SINCE] = cell
        elif width == WIDTH - 1:
            parts.insert(1 + SINCE, cell)
        else:
            errors.append(f"{first}: the row has {width} cells; a flag row has "
                          f"{WIDTH - 1} without Since or {WIDTH} with it")
        out.append("|".join(parts))
    return "\n".join(out), errors


def differences(have: str, want: str) -> list:
    rows = []
    for a, b in zip(have.split("\n"), want.split("\n")):
        if a != b:
            ca, cb = cells(a), cells(b)
            flag = cb[1].strip() if len(cb) > 2 else b
            old = ca[1 + SINCE].strip() if a.startswith("|") and len(ca) == len(cb) else "(no Since column)"
            rows.append(f"  {flag}: {old} -> {cb[1 + SINCE].strip() if len(cb) > 2 else b}")
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=".", help="the git checkout (default: .)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="rewrite the column in place")
    mode.add_argument("--check", action="store_true", help="exit 1 if the column is stale")
    args = ap.parse_args(argv)
    repo = pathlib.Path(args.repo)
    doc_path = repo / DOC
    try:
        have = doc_path.read_text()
        want, errors = rewrite(have, flag_since(repo))
    except (FlagSinceError, OSError) as e:
        print(f"flag-since: {e}", file=sys.stderr)
        return 2
    if errors:
        print("flag-since: " + DOC + ":\n  " + "\n  ".join(errors), file=sys.stderr)
        return 2
    if args.write:
        if want != have:
            doc_path.write_text(want)
            print(f"flag-since: wrote {DOC}")
        else:
            print(f"flag-since: {DOC} already agrees with the release tags")
        return 0
    if want != have:
        print(f"{DOC}: the Since column disagrees with the release tags:")
        print("\n".join(differences(have, want)))
        print("Fix: python3 scripts/flag-since.py --write")
        return 1
    print(f"flag-since: {DOC} agrees with the release tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())
