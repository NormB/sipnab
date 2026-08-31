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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from lib_markdown import fence_mask  # noqa: E402

# Derived from this file's location, like every sibling script
# (`check-line-drift.py` and `rfc-links.py` both use the same `parents[1]`).
# It was an absolute `/srv/sipnab`, which exists on exactly
# one machine. Measured 2026-08-19 on macOS/aarch64, in a checkout under a
# different $HOME: `git ls-files` ran with `cwd=` a path that
# is not there and the script died with
# `FileNotFoundError: ... PosixPath('/srv/sipnab')`, before
# reading a single doc. `tests/doc_link_hygiene_test.rs:321` fails with "Run
# scripts/fix-line-anchors.py --apply", so the gate's only remedy was a script
# that could not start anywhere but one checkout. Same defect, same fix, as
# `rfc-links.py` -- which failed the QUIETER way: its glob matched nothing and
# it reported success over zero files.
ROOT = pathlib.Path(__file__).resolve().parents[1]
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

    out: list[str] = []
    # `fence_mask`, not a per-line toggle: a fence is three or MORE markers and
    # only a run at least as long as the opener closes it. A toggle reads the
    # inner ``` of a ```` block as closing it and rewrites the rest of the
    # code block as prose.
    mask = fence_mask(text)
    for idx, line in enumerate(text.split("\n")):
        inside = idx < len(mask) and mask[idx]
        out.append(line if inside else LINK.sub(sub, line))
    return "\n".join(out), n


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    total = files = scanned = 0
    for f in sorted((ROOT / "docs").rglob("*.md")):
        scanned += 1
        orig = f.read_text()
        out, n = convert(f, orig)
        if n:
            files += 1
            total += n
            print(f"  {f.relative_to(ROOT)}: {n}")
            if apply:
                f.write_text(out)
    # `scanned` is reported because "0 across 0 files" cannot otherwise be told
    # apart from "the glob matched nothing" -- and the second is exactly how the
    # hardcoded ROOT hid in `rfc-links.py` for as long as it did. 85 files here
    # on 2026-08-19; a zero is a broken ROOT, not a clean tree.
    print(f"{'FIXED' if apply else 'WOULD FIX'} {total} line citations "
          f"across {files} of {scanned} files scanned under {ROOT}/docs")
