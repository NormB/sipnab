# SPDX-License-Identifier: MIT OR Apache-2.0
"""Markdown structure shared by the three site/wiki generators.

Each generator rewrites repo-relative code links into absolute blob URLs. All
three did it with a bare ``CODE_LINK_RE.sub()`` over the whole document, which
has no idea what a code span or a fenced block is -- so a document that *talks
about* link syntax gets its example rewritten.

That is not hypothetical. ``docs/internals/testing.md`` documents a past bug
with the literal text ``` `](../bench/)` ``` inside a code span; the moment
``bench`` was added to the tree list, the generator turned that example into
``](https://github.com/NormB/sipnab/blob/main/docs/bench)`` -- mangling the
prose *and* producing a dead URL, since ``docs/bench`` does not exist. The
repository already knew this class: ``no_markdown_links_inside_mermaid_blocks``
exists precisely because ``build-wiki.py`` "rewrites links with no fence
awareness".

:func:`sub_outside_code` is that awareness, in one place, for all three.

Fence rules follow CommonMark, and the details are the bug surface:

* a fence is three or more backticks **or** tildes, indented at most three
  spaces;
* it closes only on a run of the **same** character, at least as long;
* an unclosed fence runs to the end of the document.

A scanner that toggles one boolean on ``startswith("```")`` -- the shape three
of this repository's gates shipped with -- reads a ``~~~`` block containing a
```` ``` ```` line as *entering* a fence with nothing to leave it.
"""

from __future__ import annotations

import re
from typing import Callable, Iterator, NamedTuple

__all__ = ["Fence", "code_regions", "fences", "fence_mask", "sub_outside_code"]


class Fence(NamedTuple):
    """One fenced block, in line indices."""

    start: int  #: index of the opening marker line
    end: int  #: index one past the closing marker (or past EOF if unclosed)
    char: str  #: ````` or ``~``
    run: int  #: opening marker length; a closer must be at least this long
    info: str  #: the whole info string, trimmed
    lang: str  #: its first word, lowercased -- `````Bash,ignore`` -> ``bash``
    body: list[str]  #: the lines between the markers


def fences(text: str) -> list[Fence]:
    """Every fenced block in ``text``, in document order."""
    lines = text.splitlines()
    out: list[Fence] = []
    i = 0
    while i < len(lines):
        opened = _fence_open(lines[i])
        if opened is None:
            i += 1
            continue
        char, run = opened
        info = lines[i].lstrip(" ")[run:].strip()
        start, body = i, []
        i += 1
        while i < len(lines) and not _fence_close(lines[i], char, run):
            body.append(lines[i])
            i += 1
        i = min(i + 1, len(lines))
        out.append(
            Fence(
                start=start,
                end=i,
                char=char,
                run=run,
                info=info,
                lang=info.split()[0].rstrip(",").lower() if info.split() else "",
                body=body,
            )
        )
    return out


def fence_mask(text: str) -> list[bool]:
    """Per-line ``True`` where the line belongs to a fenced block.

    Markers included, so a caller iterating "lines outside code" never sees an
    info string either. Use this instead of toggling a boolean on
    ``startswith("```")``: a ``~~~`` block containing a
    ``````` line switches such a toggle *on* with nothing to
    switch it back, and the rest of the document is then read as code.
    """
    mask = [False] * len(text.splitlines())
    for f in fences(text):
        for n in range(f.start, min(f.end, len(mask))):
            mask[n] = True
    return mask

_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)", re.DOTALL)


def _fence_open(line: str) -> tuple[str, int] | None:
    """``(fence_char, run_length)`` if this line opens a fence."""
    stripped = line.lstrip(" ")
    if len(line) - len(stripped) > 3:
        return None  # four spaces is an indented code block, not a fence
    if not stripped[:1] in ("`", "~"):
        return None
    char = stripped[0]
    run = len(stripped) - len(stripped.lstrip(char))
    if run < 3:
        return None
    info = stripped[run:].strip()
    if char == "`" and "`" in info:
        return None  # a backtick fence's info string may not contain a backtick
    return char, run


def _fence_close(line: str, char: str, run: int) -> bool:
    stripped = line.lstrip(" ")
    if len(line) - len(stripped) > 3:
        return False
    n = len(stripped) - len(stripped.lstrip(char))
    return n >= run and not stripped[n:].strip()


def code_regions(text: str) -> Iterator[tuple[int, int]]:
    """Yield ``(start, end)`` character offsets of every code region.

    Covers fenced blocks (markers included, so a rewrite cannot touch an info
    string either) and inline code spans outside them.
    """
    lines = text.splitlines(keepends=True)
    offsets, pos = [], 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)
    offsets.append(pos)

    fenced: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        opened = _fence_open(lines[i])
        if opened is None:
            i += 1
            continue
        char, run = opened
        start = offsets[i]
        i += 1
        while i < len(lines) and not _fence_close(lines[i], char, run):
            i += 1
        # Past the closer, or past the end for an unclosed fence.
        i = min(i + 1, len(lines))
        fenced.append((start, offsets[i]))

    yield from fenced

    # Inline spans, but only in the gaps between fenced blocks: backticks
    # inside a fenced block are body text, not span delimiters.
    cursor = 0
    for start, end in fenced + [(len(text), len(text))]:
        for m in _INLINE_CODE_RE.finditer(text, cursor, start):
            yield m.span()
        cursor = end


def sub_outside_code(
    pattern: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], text: str
) -> str:
    """``pattern.sub(repl, text)``, skipping code spans and fenced blocks.

    Documentation that quotes link syntax as an example keeps its example.
    """
    blocked = sorted(code_regions(text))
    if not blocked:
        return pattern.sub(repl, text)

    # Merge overlaps so a membership test is a simple sweep.
    merged: list[list[int]] = []
    for start, end in blocked:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    out, cursor = [], 0
    for start, end in merged:
        out.append(pattern.sub(repl, text[cursor:start]))
        out.append(text[start:end])
        cursor = end
    out.append(pattern.sub(repl, text[cursor:]))
    return "".join(out)
