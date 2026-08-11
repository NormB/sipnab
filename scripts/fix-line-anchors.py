"""Make a cited line number actually go to that line.

The docs cite lines constantly, in two shapes:

    [`dialog_store.rs:595`](../../src/sip/dialog_store.rs)
    [`:993`](../../src/sip/dialog_store.rs)

Both are broken in the same way: the LABEL promises a line and the HREF has no
fragment, so the click lands at the top of a 3,500-line file and the reader is
left scrolling for the thing the sentence just told them the exact position of.
A citation that does not land is worse than a bare line number, because it
looks like it worked.

All 405 line-bearing links in docs/ had this defect. 394 were also relative,
which resolves on GitHub and nowhere else -- docs/ is mirrored to the website
and published to the GitHub wiki, and from either one `../../src/...` points
outside the tree at nothing.

This rewrites both shapes to an absolute blob URL with an #L fragment, keeping
the label exactly as written: the label is the author's citation and this only
fixes where it goes.
"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path("/home/gator/Development/sipnab")
BASE = "https://github.com/NormB/sipnab"
LINK = re.compile(r"\[`([^`]*?):(\d+(?:-\d+)?)`\]\(([^)]+)\)")

tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True).stdout.split())


def repo_path(doc: pathlib.Path, href: str) -> str | None:
    """Resolve an href to a repo-relative path, or None if it is not one."""
    href = href.split("#")[0].strip()
    if href.startswith(("http://", "https://")):
        m = re.search(r"/(?:blob|raw|tree)/main/(.+)$", href)
        return m.group(1) if m and m.group(1) in tracked else None
    if not href or href.startswith(("mailto:", "#")):
        return None
    try:
        p = (doc.parent / href).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return None                      # escaped the repo entirely
    return p if p in tracked else None


def convert(doc: pathlib.Path, text: str) -> tuple[str, int]:
    n = 0

    def sub(m):
        nonlocal n
        label, lines, href = m.group(1), m.group(2), m.group(3)
        p = repo_path(doc, href)
        if p is None:
            return m.group(0)
        start, _, end = lines.partition("-")
        frag = f"#L{start}" + (f"-L{end}" if end else "")
        new = f"{BASE}/blob/main/{p}{frag}"
        if new == href:
            return m.group(0)
        n += 1
        return f"[`{label}:{lines}`]({new})"

    out, fence = [], None
    for line in text.split("\n"):
        t = line.lstrip()
        marker = "```" if t.startswith("```") else ("~~~" if t.startswith("~~~") else None)
        if marker:
            fence = marker if fence is None else (None if fence == marker else fence)
            out.append(line)
            continue
        out.append(line if fence else LINK.sub(sub, line))
    return "\n".join(out), n


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    total = files = 0
    for f in sorted((ROOT / "docs").rglob("*.md")):
        orig = f.read_text()
        out, n = convert(f, orig)
        if n:
            files += 1
            total += n
            print(f"  {f.relative_to(ROOT)}: {n}")
            if apply:
                f.write_text(out)
    print(f"{'FIXED' if apply else 'WOULD FIX'} {total} line citations across {files} files")
