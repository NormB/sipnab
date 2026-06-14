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
# spaces in the wiki title; the URL keeps the hyphens. Order here defines the
# sidebar order within each group.
PAGES: dict[str, str] = {
    "install.md": "Installation",
    "cli-reference.md": "CLI-Reference",
    "config-reference.md": "Configuration",
    "filter-dsl.md": "Filter-DSL",
    "keybindings.md": "Keybindings",
    "theme-guide.md": "Theme-Guide",
    "output-formats.md": "Output-Formats",
    "examples.md": "Examples",
    "mcp-overview.md": "MCP-Overview",
    "mcp-setup.md": "MCP-Setup",
    "mcp-tools.md": "MCP-Tools",
    "fault-model.md": "Fault-Model",
    "internals/tui-testing.md": "Internals-TUI-Testing",
    "internals/zero-copy-payloads.md": "Internals-Zero-Copy-Payloads",
}

# Sidebar grouping: (section title, [source paths]).
GROUPS: list[tuple[str, list[str]]] = [
    ("Getting started", ["install.md", "cli-reference.md", "examples.md"]),
    ("Configuration", ["config-reference.md", "keybindings.md", "theme-guide.md"]),
    ("Filtering & output", ["filter-dsl.md", "output-formats.md"]),
    ("MCP server", ["mcp-overview.md", "mcp-setup.md", "mcp-tools.md"]),
    ("Internals", ["fault-model.md", "internals/tui-testing.md",
                   "internals/zero-copy-payloads.md"]),
]

# basename (without .md) -> wiki page, for link rewriting. Source links use the
# bare filename regardless of subdir, so key on the basename.
SLUG_TO_PAGE = {Path(src).stem: page for src, page in PAGES.items()}

LINK_RE = re.compile(r"\]\(\s*([^)\s]+?\.md)(#[^)\s]*)?\s*\)")


def rewrite_link(m: re.Match) -> str:
    target, anchor = m.group(1), (m.group(2) or "")
    cleaned = target.lstrip("./")
    stem = Path(cleaned).stem
    if stem in SLUG_TO_PAGE:
        return f"]({SLUG_TO_PAGE[stem]}{anchor})"
    # Unknown doc (e.g. a root-level plan): point at the repo blob.
    return f"]({BLOB}/{cleaned}{anchor})"


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
    return LINK_RE.sub(rewrite_link, body)


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
    ]
    for title, srcs in GROUPS:
        out.append(f"## {title}")
        out.append("")
        for src in srcs:
            page = PAGES[src]
            out.append(f"- [[{page.replace('-', ' ')}|{page}]]")
        out.append("")
    return "\n".join(out)


def build_sidebar() -> str:
    out = [f"### [sipnab]({SITE})", ""]
    for title, srcs in GROUPS:
        out.append(f"**{title}**")
        out.append("")
        for src in srcs:
            page = PAGES[src]
            out.append(f"- [[{page.replace('-', ' ')}|{page}]]")
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
