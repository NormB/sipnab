#!/usr/bin/env python3
"""A ratchet must not write its expected value twice.

A ratchet is an assertion carrying a maintained count -- tracked markdown
files, documentation tables, Cli fields -- raised by hand as the repository
grows. The idiom here writes the number once as the assertion's expected value
and again inside its own failure message:

    assert_eq!(
        files.len(), 163,
        "found {} tracked markdown files, expected 159. More is fine -- bump this."
    );

Raising one and not the other is a single keystroke, produces no error, and
leaves the gate telling whoever it fails next to expect a number nobody expects.
That is not hypothetical: this checker was written after finding exactly that in
`no_documentation_table_repeats_a_row`, where the value had been raised 159 ->
163 and the message still said 159. Two more had already been fixed by hand the
same day, in the table-count and packaging-path ratchets.

It is the same defect the ratchets themselves exist to catch -- a documented
value drifting from the thing that produces it -- occurring inside the gates.

# The rule

Name the number once and interpolate it:

    const EXPECTED_MARKDOWN_FILES: usize = 163;
    assert_eq!(
        files.len(), EXPECTED_MARKDOWN_FILES,
        "found {} tracked markdown files, expected {EXPECTED_MARKDOWN_FILES}."
    );

# What counts as a ratchet

Only assertions whose own text, or the comment block above them, carries the
idiom's own vocabulary: "bump this", "Raised N ->", "More is fine", "FEWER",
"expected at least". A `401` repeated in an HTTP test's message is a protocol
constant that never moves and is none of this checker's business -- scanning
every assertion reported 159 of those and would have taught everyone to ignore
the output.

Numbers below 10 are ignored for the same reason: an index or a small count
appearing in prose is not a maintained figure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

RATCHET = re.compile(
    r"bump this|Raised \d|More is fine|FEWER|LOWERED|ratchet|expected at least|grew to",
    re.I,
)
NUM = re.compile(r"\b(\d[\d_]*)\b")
#: Below this, a shared number is prose rather than a maintained figure.
FLOOR = 10


def macro_calls(text: str):
    """Yield (line, body, offset) for each assert/assert_eq/assert_ne call.

    Balanced-paren scan that knows about string literals, because a `)` inside
    a message would otherwise end the call early and truncate what is scanned.
    """
    for m in re.finditer(r"\bassert(_eq|_ne)?!\s*\(", text):
        i = m.end() - 1
        depth = 0
        j = i
        in_s = esc = False
        while j < len(text):
            c = text[j]
            if in_s:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_s = False
            elif c == '"':
                in_s = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield text[: m.start()].count("\n") + 1, text[i : j + 1], m.start()


def split_strings(body: str) -> tuple[str, str]:
    """Separate a macro body into (code, message text)."""
    out: list[str] = []
    strs: list[str] = []
    cur: list[str] = []
    in_s = esc = False
    for c in body:
        if in_s:
            if esc:
                esc = False
                cur.append(c)
            elif c == "\\":
                esc = True
                cur.append(c)
            elif c == '"':
                in_s = False
                strs.append("".join(cur))
                cur = []
            else:
                cur.append(c)
        elif c == '"':
            in_s = True
        else:
            out.append(c)
    return "".join(out), " ".join(strs)


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    scanned = 0

    for p in sorted(repo.glob("**/*.rs")):
        rel = p.relative_to(repo).as_posix()
        if rel.startswith(("target/", "fuzz/target/")):
            continue
        text = p.read_text(errors="replace")
        for line, body, start in macro_calls(text):
            code, msg = split_strings(body)
            code_nums = {int(n.replace("_", "")) for n in NUM.findall(code)}
            msg_nums = {int(n.replace("_", "")) for n in NUM.findall(msg)}
            shared = {n for n in code_nums & msg_nums if n >= FLOOR}
            if not shared:
                continue
            before = text[max(0, start - 3000) : start]
            ctx = before[before.rfind("\n\n") :] if "\n\n" in before else before
            if not (RATCHET.search(body) or RATCHET.search(ctx)):
                continue
            scanned += 1
            offenders.append(
                f"  {rel}:{line} repeats {sorted(shared)} in its own message"
            )

    # Anti-vacuity, the same shape the ratchets themselves carry: a parser that
    # stopped matching would report a clean tree by reading nothing.
    total = sum(
        1
        for p in repo.glob("**/*.rs")
        if not p.relative_to(repo).as_posix().startswith(("target/", "fuzz/target/"))
        for _ in macro_calls(p.read_text(errors="replace"))
    )
    if total < 500:
        print(
            f"only {total} assertions found in the tree -- this checker's parser "
            f"stopped matching and it is now checking almost nothing",
            file=sys.stderr,
        )
        return 2

    if offenders:
        print(f"{len(offenders)} ratchet(s) write their expected value twice:")
        print("\n".join(offenders))
        print(
            "\nName the number once and interpolate it into the message; see this "
            "script's docstring."
        )
        return 1

    print(f"checked {total} assertions; no ratchet repeats its own value")
    return 0


if __name__ == "__main__":
    sys.exit(main())
