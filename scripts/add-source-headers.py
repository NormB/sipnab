#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Give every source file its license and copyright statement.

The fixer for `tests/source_file_headers_test.rs` (OpenSSF Gold
`license_per_file` and `copyright_per_file`). Both read the scope, the
exclusions and the two statements from `.config/source-headers.txt`; neither
keeps its own copy.

    python3 scripts/add-source-headers.py           # list what would change
    python3 scripts/add-source-headers.py --apply   # change it

What an insert preserves, because a careless one breaks the file:

- a shebang stays on line 1, and a Python encoding declaration stays on line
  1 or 2 (PEP 263 ignores it anywhere else);
- an HTML `<!DOCTYPE>` stays first, so the rendered page still starts with it,
  and so does a Tera template's `{% extends %}` (`site_journey_test` holds every
  page template to opening with it) with the `{% import %}` lines under it,
  which Tera reads only before any other content;
- the file's mode: the file is rewritten in place, never replaced, so an
  executable script stays executable;
- an existing, correct license line: the copyright line is added beside it
  rather than a second license line above it.

The new header is followed by a blank line, so it never runs into whatever
comment came first. That matters in Go, where a comment directly above
`package` becomes the package's documentation.

A license line naming a DIFFERENT expression is never rewritten: changing a
file's license is a decision, not a fix. The file is reported and the run
fails until someone makes that decision by hand.

Idempotent: a file that already passes is not touched.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

CONFIG = Path(".config/source-headers.txt")
CODING = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*[-_.a-zA-Z0-9]+")


@dataclass
class Rule:
    kind: str  # ext | name | prefix | shebang
    value: str
    open: str
    close: str


@dataclass
class Config:
    license: str
    copyright: str
    window: int
    rules: list[Rule]
    excludes: set[str]


def parse_config(text: str) -> Config:
    values: dict[str, str] = {}
    rules: list[Rule] = []
    excludes: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, rest = line.partition(" ")
        rest = rest.strip()
        fields = rest.split()
        if key in ("license", "copyright", "window"):
            values[key] = rest
        elif key in ("ext", "name", "prefix"):
            rules.append(Rule(key, fields[0], fields[1], fields[2] if len(fields) > 2 else ""))
        elif key == "shebang":
            rules.append(Rule(key, "", fields[0], fields[1] if len(fields) > 1 else ""))
        elif key == "exclude":
            excludes.add(rest)
        else:
            sys.exit(f"{CONFIG}:{n}: unknown directive `{key}`")
    return Config(
        values["license"], values["copyright"], int(values["window"]), rules, excludes
    )


def rule_for(config: Config, path: str, first_line: str) -> Rule | None:
    """Same matching as the gate: name-based rules first, then shebang."""
    base = path.rsplit("/", 1)[-1]
    for r in config.rules:
        if (
            (r.kind == "ext" and base.endswith(r.value))
            or (r.kind == "name" and base == r.value)
            or (r.kind == "prefix" and base.startswith(r.value))
        ):
            return r
    if first_line.startswith("#!"):
        for r in config.rules:
            if r.kind == "shebang":
                return r
    return None


def comment(rule: Rule, statement: str) -> str:
    return f"{rule.open} {statement}" + (f" {rule.close}" if rule.close else "")


def states(rule: Rule, line: str, statement: str) -> bool:
    """Does this line hold exactly `statement` inside a comment?"""
    body = line.lstrip()
    if not body.startswith(rule.open):
        return False
    body = body[len(rule.open):].strip()
    if rule.close and body.endswith(rule.close):
        body = body[: -len(rule.close)].strip()
    return body == statement


def fix(config: Config, rule: Rule, text: str) -> tuple[str, str | None]:
    """Return (new text, refusal). Unchanged text means nothing to do."""
    license_ = f"SPDX-License-Identifier: {config.license}"
    copyright_ = f"SPDX-FileCopyrightText: {config.copyright}"
    lines = text.split("\n")
    head = lines[: config.window]
    for line in head:
        if "SPDX-License-Identifier:" in line and not states(rule, line, license_):
            return text, f"a different license statement `{line.strip()}`; decide by hand"
    lic_at = next((i for i, l in enumerate(head) if states(rule, l, license_)), None)
    cop_at = next((i for i, l in enumerate(head) if states(rule, l, copyright_)), None)
    if lic_at is not None and cop_at is not None:
        return text, None
    if lic_at is not None:
        lines.insert(lic_at + 1, comment(rule, copyright_))
        return "\n".join(lines), None
    if cop_at is not None:
        lines.insert(cop_at, comment(rule, license_))
        return "\n".join(lines), None

    # Lines a format requires on top stay on top.
    keep = 0
    if lines and lines[0].startswith("#!"):
        keep = 1
    if rule.value == ".py":
        for i in range(keep, min(2, len(lines))):
            if CODING.match(lines[i]):
                keep = i + 1
    if rule.value == ".html" and lines and lines[0].lower().startswith("<!doctype"):
        keep = 1
    # Tera reads `{% import %}` only directly after `{% extends %}`, before any
    # other content, a comment included, so the header goes under the run.
    if rule.value == ".html" and lines and lines[0].startswith("{% extends"):
        keep = 1
        while keep < len(lines) and lines[keep].startswith("{% import"):
            keep += 1
    header = [comment(rule, license_), comment(rule, copyright_)]
    rest = lines[keep:]
    if rest and rest[0].strip():
        header.append("")
    return "\n".join(lines[:keep] + header + rest), None


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--apply", action="store_true", help="rewrite the files")
    args = parser.parse_args()
    config = parse_config(CONFIG.read_text(encoding="utf-8"))

    changed: list[str] = []
    refused: list[str] = []
    for path in tracked():
        p = Path(path)
        if path in config.excludes or not p.is_file():
            continue
        raw = p.read_bytes()
        first = raw.split(b"\n", 1)[0].decode("utf-8", "replace")
        rule = rule_for(config, path, first)
        if rule is None:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            refused.append(f"{path}: not UTF-8")
            continue
        new, refusal = fix(config, rule, text)
        if refusal:
            refused.append(f"{path}: {refusal}")
        elif new != text:
            changed.append(path)
            if args.apply:
                # Write through the existing inode: the mode bits survive.
                with open(p, "r+", encoding="utf-8", newline="") as f:
                    f.seek(0)
                    f.write(new)
                    f.truncate()

    verb = "updated" if args.apply else "would update"
    for path in changed:
        print(f"{verb} {path}")
    for r in refused:
        print(f"REFUSED {r}", file=sys.stderr)
    print(f"{len(changed)} file(s) {verb}, {len(refused)} refused", file=sys.stderr)
    if refused:
        return 1
    return 1 if changed and not args.apply else 0


if __name__ == "__main__":
    sys.exit(main())
