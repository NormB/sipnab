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

import re
import sys
from pathlib import Path

REPO = "NormB/sipnab"
SITE = "https://www.sipnab.com"
BLOB = f"https://github.com/{REPO}/blob/main"

# Source doc (path relative to docs/) -> wiki page name. Hyphens render as
# spaces in the wiki title; the URL keeps the hyphens.
PAGES: dict[str, str] = {
    "install.md": "Installation",
    "examples.md": "Cookbook",
    "troubleshooting.md": "Troubleshooting",
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
    "internals/README.md": "Internals-Index",
    "internals/threading.md": "Internals-Threading",
    "internals/tui-testing.md": "Internals-TUI-Testing",
    "internals/zero-copy-payloads.md": "Internals-Zero-Copy-Payloads",
}

# Sidebar grouping: (section title, [source paths]), ordered by user journey —
# install first, internals last. Order within a group is the reading order.
GROUPS: list[tuple[str, list[str]]] = [
    ("Getting started", ["install.md", "examples.md", "troubleshooting.md"]),
    ("Using the TUI", ["keybindings.md", "theme-guide.md"]),
    ("CLI & automation", ["cli-reference.md", "filter-dsl.md", "output-formats.md"]),
    ("Configuration", ["config-reference.md"]),
    ("Integrations (API & MCP)", ["rest-api.md", "auth.md", "mcp.md",
                                  "mcp-walkthrough.md"]),
    ("Development & internals", ["internals/README.md", "library.md",
                                 "benchmarks.md", "fault-model.md",
                                 "internals/threading.md", "internals/tui-testing.md",
                                 "internals/zero-copy-payloads.md"]),
]

# basename (without .md) -> wiki page, for link rewriting. Source links use the
# bare filename regardless of subdir, so key on the basename.
SLUG_TO_PAGE = {Path(src).stem: page for src, page in PAGES.items()}

LINK_RE = re.compile(r"\]\(\s*([^)\s]+?\.md)(#[^)\s]*)?\s*\)")

# Links into the code tree. LINK_RE only matches .md, so without this a
# relative `../../src/pipeline.rs` link survives verbatim into the flat wiki
# and resolves to nothing. Anchored on the top-level trees so a bare
# `foo.txt` in prose is not mistaken for a repo path.
CODE_LINK_RE = re.compile(
    r"\]\(\s*((?:\.{1,2}/)*(?:src|tests|crates|benches|fuzz|scripts|contrib"
    r"|harness|ops|man|demos|\.github|\.githooks)/[^)\s]*)\s*\)"
)


def wiki_bullet(page: str) -> str:
    """A `- [[…]]` sidebar/index bullet with a spaced display label."""
    label = page.replace("-", " ")
    return f"- [[{page}]]" if label == page else f"- [[{label}|{page}]]"


def rewrite_link(m: re.Match) -> str:
    target, anchor = m.group(1), (m.group(2) or "")
    if target.startswith(("http://", "https://")):
        return m.group(0)
    stem = Path(target).stem
    if stem in SLUG_TO_PAGE:
        return f"]({SLUG_TO_PAGE[stem]}{anchor})"
    # Unknown doc: point at the repo blob. Source links are relative to
    # docs/; each leading "../" climbs one level toward the repo root.
    parts = [p for p in target.split("/") if p not in ("", ".")]
    prefix = ["docs"]
    while parts and parts[0] == "..":
        parts.pop(0)
        if prefix:
            prefix.pop()
    return f"]({BLOB}/{'/'.join(prefix + parts)}{anchor})"


def rewrite_code_link(m: re.Match) -> str:
    target = m.group(1)
    parts = [p for p in target.split("/") if p not in ("", ".")]
    prefix = ["docs"]
    while parts and parts[0] == "..":
        parts.pop(0)
        if prefix:
            prefix.pop()
    return f"]({BLOB}/{'/'.join(prefix + parts)})"


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


def transform(src_text: str) -> str:
    body = strip_leading_h1(src_text)
    body = LINK_RE.sub(rewrite_link, body)
    return CODE_LINK_RE.sub(rewrite_code_link, body)


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
        "```bash",
        "# Install: grab a .deb / static binary from the latest release",
        "# (see Installation for all options)",
        "curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab-x86_64-unknown-linux-musl",
        "chmod +x sipnab-x86_64-unknown-linux-musl",
        "sudo mv sipnab-x86_64-unknown-linux-musl /usr/local/bin/sipnab",
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

    for src, page in PAGES.items():
        text = (docs / src).read_text(encoding="utf-8")
        (out_dir / f"{page}.md").write_text(transform(text), encoding="utf-8")
        print(f"  {src:40s} -> {page}.md")

    (out_dir / "Home.md").write_text(build_home(), encoding="utf-8")
    (out_dir / "_Sidebar.md").write_text(build_sidebar(), encoding="utf-8")
    (out_dir / "_Footer.md").write_text(build_footer(), encoding="utf-8")
    print(f"Wrote {len(PAGES) + 3} pages to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
