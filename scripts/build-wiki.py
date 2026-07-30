#!/usr/bin/env python3
"""Generate the GitHub Wiki tree from the in-repo `docs/` source of truth.

`docs/` is the single source of truth; the wiki is a generated mirror. This
script transforms the Markdown so it renders correctly as a GitHub wiki:

  * Maps each source file to a wiki page name (hyphenated -> spaced title).
  * Strips the leading H1 (the wiki renders the page title itself).
  * Rewrites inter-doc `*.md` links to wiki page links; unknown `.md` links
    fall back to the repo blob URL.
  * Emits Home / _Sidebar / _Footer navigation pages.

Run from the repo root:  python3 scripts/build-wiki.py [OUTPUT_DIR]
Default OUTPUT_DIR is `build/wiki`.
"""

from __future__ import annotations

import posixpath
import re
import sys
from pathlib import Path

# The generators are also loaded by tests via importlib, which does not put
# their directory on sys.path -- so add it explicitly rather than relying on
# being run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib_markdown import sub_outside_code  # noqa: E402

REPO = "NormB/sipnab"
SITE = "https://www.sipnab.com"
BLOB = f"https://github.com/{REPO}/blob/main"

# Source doc (path relative to docs/) -> wiki page name. Hyphens render as
# spaces in the wiki title; the URL keeps the hyphens.
PAGES: dict[str, str] = {
    "install.md": "Installation",
    "examples.md": "Cookbook",
    "troubleshooting.md": "Troubleshooting",
    "tui-walkthrough.md": "TUI-Walkthrough",
    "backers.md": "Backers",
    "keybindings.md": "Keybindings",
    "theme-guide.md": "Theme-Guide",
    "cli-reference.md": "CLI-Reference",
    "filter-dsl.md": "Filter-DSL",
    "output-formats.md": "Output-Formats",
    "config-reference.md": "Configuration",
    "rest-api.md": "REST-API",
    "mcp.md": "MCP",
    "mcp-walkthrough.md": "MCP-Walkthrough",
    "auth.md": "Authentication",
    "library.md": "Library-API",
    "benchmarks.md": "Benchmarks",
    "fault-model.md": "Fault-Model",
    "architecture.md": "Architecture",
    "internals/README.md": "Internals-Index",
    "internals/subsystem-guide.md": "Internals-Subsystem-Guide",
    "internals/invariants.md": "Internals-Invariants",
    "internals/testing.md": "Internals-Testing",
    "internals/walkthroughs.md": "Internals-Walkthroughs",
    "internals/build-ci-release.md": "Internals-Build-CI-Release",
    "internals/domain-primer.md": "Internals-Domain-Primer",
    "internals/threading.md": "Internals-Threading",
    "internals/tui-testing.md": "Internals-TUI-Testing",
    "internals/zero-copy-payloads.md": "Internals-Zero-Copy-Payloads",
}

# Sidebar grouping: (section title, [source paths]), ordered by user journey —
# install first, internals last. Order within a group is the reading order.
GROUPS: list[tuple[str, list[str]]] = [
    ("Getting started", ["install.md", "examples.md", "troubleshooting.md",
                         "backers.md"]),
    ("Using the TUI", ["tui-walkthrough.md", "keybindings.md", "theme-guide.md"]),
    ("CLI & automation", ["cli-reference.md", "filter-dsl.md", "output-formats.md"]),
    ("Configuration", ["config-reference.md"]),
    ("Integrations (API & MCP)", ["rest-api.md", "auth.md", "mcp.md",
                                  "mcp-walkthrough.md"]),
    ("Development & internals", ["internals/README.md",
                                 "internals/subsystem-guide.md",
                                 "internals/invariants.md",
                                 "internals/testing.md",
                                 "internals/walkthroughs.md",
                                 "internals/build-ci-release.md",
                                 "internals/domain-primer.md", "library.md",
                                 "benchmarks.md", "fault-model.md",
                                 "architecture.md",
                                 "internals/threading.md", "internals/tui-testing.md",
                                 "internals/zero-copy-payloads.md"]),
]

LINK_RE = re.compile(r"\]\(\s*([^)\s]+?\.md)(#[^)\s]*)?\s*\)")

# Links into the code tree. LINK_RE only matches .md, so without this a
# relative `../../src/pipeline.rs` link survives verbatim into the flat wiki
# and resolves to nothing. Anchored on the top-level trees so a bare
# `foo.txt` in prose is not mistaken for a repo path. The path after the tree
# name is optional: a subsystem is often cited as a bare directory
# (`../../harness`), and dev_docs_drift_test counts that as a code link too,
# so both forms must rewrite or the bare one reaches the wiki dead.
CODE_LINK_RE = re.compile(
    r"\]\(\s*((?:\.{1,2}/)*(?:\.githooks|packaging|\.config|\.github|\.vale|benches|contrib|harness|scripts|website"
    r"|\.cargo|crates|docker|bench|demos|tests|fuzz|man|ops|src)(?:/[^)\s]*)?)\s*\)"
)


def wiki_bullet(page: str) -> str:
    """A `- [[…]]` sidebar/index bullet with a spaced display label."""
    label = page.replace("-", " ")
    return f"- [[{page}]]" if label == page else f"- [[{label}|{page}]]"


def resolve_target(src_rel: str, target: str) -> tuple[str | None, str]:
    """Resolve a link written in `src_rel` to a repo path.

    Returns `(docs_relative, repo_path)`. `docs_relative` is set only when the
    target lands inside `docs/`, which is what PAGES is keyed on; anything that
    climbs out of the tree gets `None` and belongs on a blob URL.

    Resolution is relative to the SOURCE FILE's directory. It used to key on
    `Path(target).stem` alone, which discards the directory entirely — so every
    `README.md` in the repo collapsed onto whichever page `internals/README.md`
    maps to. A `../bench/README.md` link silently published as a link to the
    internals index: not a broken link that anyone would notice, a working link
    to the wrong page.
    """
    src_dir = posixpath.dirname(src_rel)
    repo_path = posixpath.normpath(posixpath.join("docs", src_dir, target))
    if repo_path.startswith("docs/"):
        return repo_path[len("docs/"):], repo_path
    return None, repo_path


def rewrite_link(src_rel: str):
    """Build the LINK_RE substitution for one source document."""
    def sub(m: re.Match) -> str:
        target, anchor = m.group(1), (m.group(2) or "")
        if target.startswith(("http://", "https://")):
            return m.group(0)
        docs_rel, repo_path = resolve_target(src_rel, target)
        if docs_rel is not None and docs_rel in PAGES:
            return f"]({PAGES[docs_rel]}{anchor})"
        return f"]({BLOB}/{repo_path}{anchor})"
    return sub


def rewrite_code_link(src_rel: str):
    """Build the CODE_LINK_RE substitution for one source document."""
    def sub(m: re.Match) -> str:
        _, repo_path = resolve_target(src_rel, m.group(1))
        return f"]({BLOB}/{repo_path})"
    return sub


def strip_leading_h1(text: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "":
            continue
        if line.startswith("# "):
            rest = lines[i + 1:]
            while rest and rest[0].strip() == "":
                rest = rest[1:]
            return "\n".join(rest) + "\n"
        break
    return text


def transform(src_text: str, src_rel: str) -> str:
    body = strip_leading_h1(src_text)
    body = LINK_RE.sub(rewrite_link(src_rel), body)
    return sub_outside_code(CODE_LINK_RE, rewrite_code_link(src_rel), body)


def build_home() -> str:
    out = [
        "# sipnab",
        "",
        "**SIP & RTP capture, analysis, and security for VoIP** — one Rust "
        "binary covering an interactive TUI, CLI batch mode, NDJSON, a REST "
        "API, and an MCP server.",
        "",
        f"This wiki mirrors the in-repo [`docs/`]({BLOB}/docs) directory and is "
        "regenerated automatically on every change to `main`. For the polished "
        f"documentation site see **[{SITE}]({SITE})**.",
        "",
        "## Quick start",
        "",
        # Was a `curl -LO .../releases/latest/download/
        # sipnab-x86_64-unknown-linux-musl`. Every release asset is versioned,
        # so that URL had always 404'd on the wiki's own front page. The
        # installer one-liner is version-independent, so it cannot rot the same
        # way; `published_download_urls_name_versioned_assets` keeps a bare
        # artifact URL from coming back. Kept as a source comment rather than an
        # emitted one: the Quick Start is the first thing a visitor reads and
        # should not carry archaeology, least of all a URL that does not work.
        "```bash",
        "# Install: detects OS/CPU/glibc, verifies the sha256, installs to",
        "# /usr/local/bin (see Installation for .deb, .rpm and manual options)",
        "curl -fsSL https://www.sipnab.com/install.sh | sh",
        "",
        "sudo sipnab --setup-caps      # one-time: live capture without sudo (Linux)",
        "",
        "sipnab                        # live TUI on the default interface",
        "sipnab -I capture.pcap        # open a pcap in the TUI",
        "sipnab -N -I capture.pcap --problems   # headless: only problem calls",
        "```",
        "",
        "## Start here",
        "",
        "New to sipnab? Read in this order:",
        "",
        "1. [[Installation]] — packages, capture permissions, feature flags",
        "2. [[Cookbook]] — copy-paste recipes for triage, filtering, "
        "recording, security",
        "3. [[Keybindings]] — driving the TUI: call list, call flow, "
        "RTP streams, search",
        "4. [[Filter DSL|Filter-DSL]] — narrowing to the calls you care about",
        "5. [[CLI Reference|CLI-Reference]] and "
        "[[Output Formats|Output-Formats]] — headless use and NDJSON pipelines",
        "6. [[Troubleshooting]] — symptom → command when a call misbehaves",
        "7. [[REST API|REST-API]] and [[MCP]] — programmatic access and "
        "AI-agent integration",
        "",
        "## All pages",
        "",
    ]
    for title, srcs in GROUPS:
        out.append(f"### {title}")
        out.append("")
        for src in srcs:
            out.append(wiki_bullet(PAGES[src]))
        out.append("")
    return "\n".join(out)


def build_sidebar() -> str:
    out = [f"### [sipnab]({SITE})", "", "[[Home]]", ""]
    for title, srcs in GROUPS:
        out.append(f"**{title}**")
        out.append("")
        for src in srcs:
            out.append(wiki_bullet(PAGES[src]))
        out.append("")
    return "\n".join(out)


def build_footer() -> str:
    return (
        f"[Website]({SITE}) · "
        f"[Repository](https://github.com/{REPO}) · "
        f"[Issues](https://github.com/{REPO}/issues) · "
        "Generated from `docs/` — edit there, not here.\n"
    )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    docs = root / "docs"
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "build" / "wiki"
    out_dir.mkdir(parents=True, exist_ok=True)

    missing = [s for s in PAGES if not (docs / s).is_file()]
    if missing:
        print(f"ERROR: missing source docs: {missing}", file=sys.stderr)
        return 1

    # And the other direction. PAGES -> disk catches a registered page that was
    # deleted; disk -> PAGES catches the far quieter case, a page that exists
    # and is published nowhere. This script had only the first check, so a new
    # docs/ page simply never appeared on the wiki and nothing said so —
    # build-site-internals.py errored on the same page while this exited 0.
    #
    # Scoped to the trees the wiki serves: docs/ top level and docs/internals/.
    # docs/design|research|superpowers are planning records, deliberately
    # unpublished, and are excluded here rather than registered.
    published = {p.relative_to(docs).as_posix() for p in docs.glob("*.md")} | {
        p.relative_to(docs).as_posix() for p in (docs / "internals").rglob("*.md")
    }
    # docs/README.md is the one deliberate exemption: build_home() below
    # generates the wiki's front page, so publishing the index as a second page
    # would duplicate it. Named here with its reason rather than silently
    # skipped, so the exemption is visible to whoever reads this next.
    WIKI_EXEMPT = {"README.md"}
    unregistered = sorted(published - set(PAGES) - WIKI_EXEMPT)
    if unregistered:
        for name in unregistered:
            print(
                f"ERROR: docs/{name} exists but is in no PAGES entry — it would "
                f"publish nowhere. Register it, or move it under "
                f"docs/design|research|superpowers if it is not for readers.",
                file=sys.stderr,
            )
        return 1

    for src, page in PAGES.items():
        text = (docs / src).read_text(encoding="utf-8")
        (out_dir / f"{page}.md").write_text(transform(text, src), encoding="utf-8")
        print(f"  {src:40s} -> {page}.md")

    (out_dir / "Home.md").write_text(build_home(), encoding="utf-8")
    (out_dir / "_Sidebar.md").write_text(build_sidebar(), encoding="utf-8")
    (out_dir / "_Footer.md").write_text(build_footer(), encoding="utf-8")
    print(f"Wrote {len(PAGES) + 3} pages to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
