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
# Not preceded by "[" (already a link label) and not already inside a link.
SECTION = re.compile(r"(?<!\[)\bRFC ?(\d{3,5}) ?§ ?(\d+(?:\.\d+)*)")
BARE    = re.compile(r"(?<!\[)\bRFC ?(\d{3,5})\b(?! ?§)")


def convert(text: str) -> tuple[str, int, int]:
    seen: set[str] = set()
    n_sec = n_bare = 0
    out: list[str] = []

    def sub_section(m):
        nonlocal n_sec
        num, sec = m.group(1), m.group(2)
        seen.add(num)
        n_sec += 1
        return f"[RFC {num} §{sec}]({BASE}/rfc{num}#section-{sec})"

    def sub_bare(m):
        nonlocal n_bare
        num = m.group(1)
        if num in seen:            # already linked once in this document
            return m.group(0)
        seen.add(num)
        n_bare += 1
        return f"[RFC {num}]({BASE}/rfc{num})"

    # `fence_mask`, not a per-line toggle: a fence is three or MORE markers and
    # only a run at least as long as the opener closes it. A toggle reads the
    # inner ``` of a ```` block as closing it and rewrites the rest of the
    # code block as prose.
    mask = fence_mask(text)
    for n, line in enumerate(text.split("\n")):
        if n < len(mask) and mask[n]:
            out.append(line)
            continue
        # Record RFCs already linked by hand so rule 2 does not double up.
        for m in re.finditer(r"\[RFC ?(\d{3,5})[^\]]*\]\(", line):
            seen.add(m.group(1))
        line = SECTION.sub(sub_section, line)
        line = BARE.sub(sub_bare, line)
        out.append(line)
    return "\n".join(out), n_sec, n_bare


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
    for f in sorted((root / "docs").rglob("*.md")):
        orig = f.read_text()
        out, s, b = convert(orig)
        if out != orig:
            files += 1
            tot_s += s
            tot_b += b
            print(f"  {f.relative_to(root)}: {s} section, {b} first-mention")
            if apply:
                f.write_text(out)
    verb = "LINKED" if apply else "WOULD LINK"
    print(f"{verb} {tot_s} section citations + {tot_b} first mentions across {files} files")
