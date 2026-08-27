"""Make bare repo-path code spans clickable, with the form the target needs.

This is the fixer `repo_paths_in_docs_are_clickable` names in its failure
message, so it must produce exactly what that gate demands -- no more:

  tracked file      -> a link
  directory         -> LEFT ALONE. The gate keys on `git ls-files`, so a
                       directory is never a tracked path and never demanded.
                       Linking one anyway is how a run of this script rewrote
                       `tests/pcap-samples` in docs/mcp.md that nothing had
                       asked for.
  untracked path    -> left alone; there is nothing to link to.

Outside `docs/internals/`, the link is ABSOLUTE:

  text file  -> /blob/main/...   renders in the browser
  binary     -> /raw/main/...    a blob URL for a binary is a page saying it
                                 cannot be shown; raw IS the file

An absolute URL because those pages are published to the website AND to the
GitHub wiki, and from the flat wiki a relative hop out of the docs tree
resolves to nothing.

Under `docs/internals/` the rule inverts, and the link is RELATIVE:

  * Those pages are wiki-and-site only, and both generators rewrite a relative
    code link into an absolute repo URL on publish
    (`lib_markdown.code_link_re`). An absolute `blob/main/` URL written into
    the source pins a branch, and `linked_code_uses_relative_paths` rejects it.
  * The rewrite only fires for a path whose first component is a tree in
    `.config/code-trees.txt`. A link it cannot rewrite reaches the flat wiki
    relative and resolves to nothing -- so a path outside those trees
    (`Cargo.toml`, `README.md`, `docs/design/`) is LEFT as a code span here,
    exactly as the gate exempts it there.
  * No `#L` fragment: the generators' code-link rewrite has no fragment group,
    so a line number would vanish on publish.
    `cited_line_numbers_link_to_the_line` exempts internals for that same
    reason.

Linking exposes nothing -- every path matched is already tracked, so it is
already public; the link only makes it findable.
"""
import pathlib, re, subprocess, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from lib_markdown import code_trees, fence_mask, repo_root  # noqa: E402

# Derived from __file__, never hardcoded: this script runs inside git
# worktrees, and an absolute root makes a fixer invoked from a worktree edit
# the other checkout's documents.
ROOT = repo_root()
BASE = "https://github.com/NormB/sipnab"

def git_files() -> list[str]:
    return subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout.split()

tracked = set(git_files())

# Path roots a code span may be anchored on -- every tracked top-level
# directory, derived rather than hand-listed. The hand-listed version held 18
# of the 22 and had no `docker`, `.vale`, `LICENSES` or `.cargo`, so a span
# naming a file in any of those was one the gate demanded and this script
# could not fix. `docs` belongs here and NOT in code-trees.txt: a `docs/...`
# span is a tracked file the gate wants linked, it is simply not a tree the
# wiki generators rewrite links into.
ROOTS = tuple(sorted({f.split("/", 1)[0] for f in tracked if "/" in f}))

# The trees whose relative links the wiki and site generators can rewrite --
# the ONE list, shared with build-wiki.py, the two site generators and the
# Rust gates. Under docs/internals/ this decides what may be linked at all.
WIKI_TREES = frozenset(code_trees())

# Root-level files carry no directory to anchor on, so they are matched by
# name -- derived from git rather than hand-listed. A hardcoded list and the
# gate that enforces it drift apart the moment someone adds a root file, and
# they did: the gate demanded links for build.rs, SUPPORT.md and Cross.toml
# that the list had never heard of.
ROOT_FILES = tuple(sorted(f for f in tracked if "/" not in f))

BINARY = {".pcap", ".pcapng", ".png", ".webp", ".gif", ".gz", ".zip", ".tar",
          ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".pdf",
          # `.bin` reached here as a captured `ng` control reply used as a test
          # fixture, and got a /blob/ URL -- the page that says it cannot be
          # shown. Any suffix missing from this set fails that way silently,
          # because the link resolves and only a human notices it renders
          # nothing.
          ".bin"}


def split_lines(p: str) -> tuple[str, str]:
    """`src/x.rs:12-20` -> `("src/x.rs", "#L12-L20")`."""
    if ":" not in p:
        return p, ""
    path, _, lines = p.partition(":")
    if not lines or not lines[0].isdigit():
        return p, ""
    a, _, b = lines.partition("-")
    return path, f"#L{a}" + (f"-L{b}" if b else "")


def absolute_url(p: str) -> str | None:
    """The published URL for a span outside `docs/internals/`."""
    path, frag = split_lines(p)
    if path not in tracked:
        return None
    kind = "raw" if pathlib.Path(path).suffix.lower() in BINARY else "blob"
    return f"{BASE}/{kind}/main/{path}{frag}"


def relative_url(p: str, depth: int) -> str | None:
    """The repo-relative target for a span inside `docs/internals/`.

    `depth` is how many directories the page sits below the repo root, so the
    link climbs back out to the root before descending. Returns None for
    anything the generators cannot rewrite, which is the same set the gate
    exempts there.
    """
    path, _ = split_lines(p)
    if path not in tracked or path.split("/", 1)[0] not in WIKI_TREES:
        return None
    return "../" * depth + path


# A path span, or a bare root-level filename. The (?<!\[) keeps already-linked
# spans -- [`x`](url) -- from being wrapped twice.
SPAN = re.compile(
    r"(?<!\[)`((?:(?:" + "|".join(re.escape(r) for r in ROOTS) + r")/[A-Za-z0-9/._-]+"
    r"|(?:" + "|".join(re.escape(f) for f in ROOT_FILES) + r"))(?::[0-9-]+)?)`"
)

def convert(text: str, depth: int = 0, internals: bool = False) -> tuple[str, int]:
    """Link paths in PROSE only.

    Fenced blocks are skipped: a command a reader copies must stay copyable,
    and a markdown link pasted into a shell is a syntax error. This is not
    hypothetical -- without the skip, 7 links landed inside fenced blocks,
    including one in the middle of a shell pipeline.
    """
    n = 0
    def sub(m):
        nonlocal n
        u = relative_url(m.group(1), depth) if internals else absolute_url(m.group(1))
        if not u:
            return m.group(0)
        n += 1
        return f"[`{m.group(1)}`]({u})"

    out: list[str] = []
    # `fence_mask`, not a per-line toggle: a fence is three or MORE markers and
    # only a run at least as long as the opener closes it. A toggle reads the
    # inner ``` of a ```` block as closing it and rewrites the rest of the
    # code block as prose.
    mask = fence_mask(text)
    for idx, line in enumerate(text.split("\n")):
        inside = idx < len(mask) and mask[idx]
        out.append(line if inside else SPAN.sub(sub, line))
    return "\n".join(out), n

if __name__ == "__main__":
    dry = "--apply" not in sys.argv
    total, files = 0, 0
    targets = sorted(ROOT.glob("docs/*.md")) + sorted(ROOT.glob("docs/**/*.md"))
    for f in dict.fromkeys(targets):
        # superpowers/ is dated planning history, excluded by decision.
        # research/ is analysis a reader follows, so it IS linked.
        #
        # testing-matrix.md is GENERATED by scripts/coverage-matrix.py and
        # cites a test file per row. Linking those would fight the generator
        # forever -- this script rewrites the file, the next generator run
        # overwrites the rewrite -- and it would add several hundred links to
        # ratchets that count them. The gate skips it for the same reason and
        # the two must agree, or the gate demands what its fixer will not
        # produce.
        if "/superpowers/" in str(f) or f.name == "testing-matrix.md":
            continue
        rel = f.relative_to(ROOT)
        s = f.read_text()
        out, n = convert(s, depth=len(rel.parent.parts),
                         internals="internals" in rel.parts)
        if n:
            total += n; files += 1
            print(f"  {rel}: {n}")
            if not dry:
                f.write_text(out)
    print(f"{'WOULD LINK' if dry else 'LINKED'} {total} paths across {files} files")
