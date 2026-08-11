"""Make bare repo-path code spans clickable, with the form the target needs.

  text file  -> /blob/main/...   renders in the browser
  binary     -> /raw/main/...    a blob URL for a binary is a page saying it
                                 cannot be shown; raw IS the file
  directory  -> /tree/main/...

Absolute URLs, never relative: a relative path resolves on GitHub and breaks on
the website. Linking exposes nothing — every path matched is already tracked,
so it is already public; the link only makes it findable.
"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path("/home/gator/Development/sipnab")
BASE = "https://github.com/NormB/sipnab"
ROOTS = ("tests", "bench", "benches", "packaging", "harness", "demos", "scripts",
         "fuzz", "src", "docs", "website", "man", "contrib", "ops", "crates",
         ".github", ".githooks", ".config")
# Root-level files carry no directory to anchor on, so they are matched by
# name -- derived from git rather than hand-listed. A hardcoded list and the
# gate that enforces it drift apart the moment someone adds a root file, and
# they did: the gate demanded links for build.rs, SUPPORT.md and Cross.toml
# that the list had never heard of.
ROOT_FILES = tuple(sorted(
    f for f in subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                              text=True).stdout.split()
    if "/" not in f
))

BINARY = {".pcap", ".pcapng", ".png", ".webp", ".gif", ".gz", ".zip", ".tar",
          ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".pdf"}

tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True).stdout.split())

def url_for(p: str) -> str | None:
    frag = ""
    if ":" in p:
        p, _, lines = p.partition(":")
        if lines and lines[0].isdigit():
            a, _, b = lines.partition("-")
            frag = f"#L{a}" + (f"-L{b}" if b else "")
    fp = ROOT / p
    if p in tracked:
        kind = "raw" if fp.suffix.lower() in BINARY else "blob"
        return f"{BASE}/{kind}/main/{p}{frag}"
    if fp.is_dir() and any(t.startswith(p.rstrip('/') + '/') for t in tracked):
        return f"{BASE}/tree/main/{p.rstrip('/')}"
    return None

# A path span, or a bare root-level filename. The (?<!\[) keeps already-linked
# spans -- [`x`](url) -- from being wrapped twice.
SPAN = re.compile(
    r"(?<!\[)`((?:(?:" + "|".join(re.escape(r) for r in ROOTS) + r")/[A-Za-z0-9/._-]+"
    r"|(?:" + "|".join(re.escape(f) for f in ROOT_FILES) + r"))(?::[0-9-]+)?)`"
)

def convert(text: str) -> tuple[str, int]:
    """Link paths in PROSE only.

    Fenced blocks are skipped: a command a reader copies must stay copyable,
    and a markdown link pasted into a shell is a syntax error. This is not
    hypothetical -- without the skip, 7 links landed inside fenced blocks,
    including one in the middle of a shell pipeline.
    """
    n = 0
    def sub(m):
        nonlocal n
        u = url_for(m.group(1))
        if not u:
            return m.group(0)
        n += 1
        return f"[`{m.group(1)}`]({u})"

    out, fence = [], None
    for line in text.split("\n"):
        t = line.lstrip()
        marker = "```" if t.startswith("```") else ("~~~" if t.startswith("~~~") else None)
        if marker:
            # Close only on the same marker: a ``` inside a ~~~ block is content.
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            out.append(line)
            continue
        out.append(line if fence else SPAN.sub(sub, line))
    return "\n".join(out), n

if __name__ == "__main__":
    dry = "--apply" not in sys.argv
    total, files = 0, 0
    targets = sorted(ROOT.glob("docs/*.md")) + sorted(ROOT.glob("docs/**/*.md"))
    for f in dict.fromkeys(targets):
        # superpowers/ is dated planning history, excluded by decision.
        # research/ is analysis a reader follows, so it IS linked.
        if "/superpowers/" in str(f):
            continue
        s = f.read_text()
        out, n = convert(s)
        if n:
            total += n; files += 1
            print(f"  {f.relative_to(ROOT)}: {n}")
            if not dry:
                f.write_text(out)
    print(f"{'WOULD LINK' if dry else 'LINKED'} {total} paths across {files} files")
