"""Link RFC citations, following the convention already used 563 times here.

  RFC 3261 §17.1.1.3  ->  https://www.rfc-editor.org/rfc/rfc3261#section-17.1.1.3
  RFC 3261            ->  https://www.rfc-editor.org/rfc/rfc3261

Two rules, and the second one is the point:

1. EVERY citation carrying a section reference is linked. That is the one a
   reader actually chases -- "§17.1.1.3" is a promise that a specific paragraph
   says a specific thing, and an unlinked one makes the reader find it by hand.

2. Bare "RFC N" is linked only on its FIRST appearance per document. One page
   cites RFC 3261 248 times; linking all of them turns prose into a wall of
   blue and helps nobody.

rfc-editor.org, not datatracker: it is the canonical publisher, and 563
existing links here already use it. A second convention would be worse than
either one alone.

Fenced blocks are skipped -- a citation inside a shell example is part of the
command, and a markdown link pasted into a terminal is a syntax error.

NOTE: linked is not the same as CURRENT. A link to an obsoleted RFC is still a
wrong citation; this makes citations reachable, it does not make them right.
"""
import pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from lib_markdown import fence_mask  # noqa: E402

BASE = "https://www.rfc-editor.org/rfc"

# A section is written "section X" or, in older text, "§X"; an appendix is a
# letter ("§A.1"). Both become a link whose LABEL says what it is, because a
# reader cannot locate "§7" and can locate "RFC 3261 section 7".
_SEC = r"(?:[0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)"
OLD_LINK = re.compile(r"\[RFC ?(\d{3,5}) ?§ ?(" + _SEC + r")\]\(([^)]*)\)")
SECTION = re.compile(r"\bRFC ?(\d{3,5}) ?(?:§ ?|section )(" + _SEC + r")\b")
CONTINUED = re.compile(
    r"(\[RFC (\d{3,5}) (?:section|appendix) [^\]]+\]\([^)]+\))"
    r"((?:,|;|/|,? and|,? or)\s*)§ ?(" + _SEC + r")\b"
)
BARE = re.compile(r"\bRFC ?(\d{3,5})\b(?! ?§)(?! section )")
LINK_SPAN = re.compile(r"\[[^\]]*\]\([^)]*\)")


def _label(num: str, sec: str) -> str:
    """`[RFC 3261 section 7.3.1](...)`, or `appendix` for a lettered one."""
    if sec[0].isalpha():
        return f"[RFC {num} appendix {sec}]({BASE}/rfc{num}#appendix-{sec})"
    return f"[RFC {num} section {sec}]({BASE}/rfc{num}#section-{sec})"


def _outside_links(pattern, text, repl):
    """Apply `pattern` only where it does not fall inside an existing link."""
    spans = [m.span() for m in LINK_SPAN.finditer(text)]

    def sub(m):
        if any(a <= m.start() < b for a, b in spans):
            return m.group(0)
        return repl(m)

    return pattern.sub(sub, text)


def _prose(segment: str, seen: set, counts: list, link_bare: bool) -> str:
    """One stretch of prose with no code span in it."""

    def relabel(m):
        counts[0] += 1
        num, sec, url = m.group(1), m.group(2), m.group(3)
        kind = "appendix" if sec[0].isalpha() else "section"
        return f"[RFC {num} {kind} {sec}]({url})"

    segment = OLD_LINK.sub(relabel, segment)
    for m in re.finditer(r"\[RFC ?(\d{3,5})[^\]]*\]\(", segment):
        seen.add(m.group(1))

    def section(m):
        counts[0] += 1
        seen.add(m.group(1))
        return _label(m.group(1), m.group(2))

    segment = _outside_links(SECTION, segment, section)

    def continued(m):
        counts[0] += 1
        return m.group(1) + m.group(3) + _label(m.group(2), m.group(4))

    while True:
        nxt = CONTINUED.sub(continued, segment)
        if nxt == segment:
            break
        segment = nxt

    if link_bare:

        def bare(m):
            num = m.group(1)
            if num in seen:  # already linked once in this document
                return m.group(0)
            seen.add(num)
            counts[1] += 1
            return f"[RFC {num}]({BASE}/rfc{num})"

        segment = _outside_links(BARE, segment, bare)
    return segment


def _line(line: str, seen: set, counts: list, link_bare: bool) -> str:
    """A prose line, with its inline code spans left exactly as they are."""
    parts = line.split("`")
    for i in range(0, len(parts), 2):  # even indexes are outside code spans
        parts[i] = _prose(parts[i], seen, counts, link_bare)
    return "`".join(parts)


def convert(text: str) -> tuple[str, int, int]:
    seen: set[str] = set()
    counts = [0, 0]
    out: list[str] = []
    # `fence_mask`, not a per-line toggle: a fence is three or MORE markers and
    # only a run at least as long as the opener closes it. A toggle reads the
    # inner ``` of a ```` block as closing it and rewrites the rest of the
    # code block as prose.
    mask = fence_mask(text)
    for n, line in enumerate(text.split("\n")):
        if n < len(mask) and mask[n]:
            out.append(line)
            continue
        out.append(_line(line, seen, counts, link_bare=True))
    return "\n".join(out), counts[0], counts[1]


DOC_COMMENT = re.compile(r"^(\s*//[/!] ?)(.*)$")


def convert_rust(text: str) -> tuple[str, int]:
    """The section rule for the rustdoc in a Rust source file.

    Only `///` and `//!` lines are documentation -- docs.rs renders them --
    and fenced blocks inside them are code. Plain `//` comments and code are
    left alone. Bare `RFC N` mentions are not linked here: rustdoc is read one
    item at a time, and the first-mention rule has no page to count on.
    """
    seen: set[str] = set()
    counts = [0, 0]
    out: list[str] = []
    fence = None
    for line in text.split("\n"):
        m = DOC_COMMENT.match(line)
        if not m:
            fence = None
            out.append(line)
            continue
        body = m.group(2)
        marker = re.match(r"(`{3,}|~{3,})", body.strip())
        if marker:
            tick = marker.group(1)
            if fence is None:
                fence = tick
            elif tick.startswith(fence) and body.strip() == tick:
                fence = None
            out.append(line)
            continue
        if fence is not None:
            out.append(line)
            continue
        out.append(m.group(1) + _line(body, seen, counts, link_bare=False))
    return "\n".join(out), counts[0]


def _generated(text: str) -> bool:
    """A mirror or report another script writes; it is fixed at its source."""
    head = text[:600]
    return "Generated by" in head or "do not edit" in head.lower()


def _tracked(root: pathlib.Path, pattern: str) -> list:
    import subprocess

    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", pattern],
        capture_output=True, check=True,
    ).stdout.decode()
    return [root / f for f in out.split("\0") if f]


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    # Derived from this file's location, like every sibling script
    # (`check-line-drift.py` uses the same `parents[1]`). It was an absolute
    # `/srv/sipnab`, which exists on exactly one machine:
    # everywhere else `root / "docs"` matched nothing, the glob yielded no
    # files, and the script reported "0 section citations across 0 files" and
    # exited 0. A no-op that reports success is worse than a crash, because the
    # gate that points people here kept pointing them at a script that could
    # not do anything.
    root = pathlib.Path(__file__).resolve().parents[1]
    tot_s = tot_b = files = 0
    # Every tracked markdown page that is not generated, and the rustdoc of
    # src/: the same scope `tests/section_references_test.rs` reads.
    for f in sorted(_tracked(root, "*.md")):
        orig = f.read_text()
        if _generated(orig):
            continue
        out, s, b = convert(orig)
        if out != orig:
            files += 1
            tot_s += s
            tot_b += b
            print(f"  {f.relative_to(root)}: {s} section, {b} first-mention")
            if apply:
                f.write_text(out)
    for f in sorted(_tracked(root, ":(glob)src/**/*.rs")):
        orig = f.read_text()
        out, s = convert_rust(orig)
        if out != orig:
            files += 1
            tot_s += s
            print(f"  {f.relative_to(root)}: {s} section (rustdoc)")
            if apply:
                f.write_text(out)
    verb = "LINKED" if apply else "WOULD LINK"
    print(f"{verb} {tot_s} section citations + {tot_b} first mentions across {files} files")
