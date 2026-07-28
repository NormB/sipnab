#!/usr/bin/env python3
"""Mirror hand-written operator docs from `docs/` into the Zola site.

`docs/` is the single source of truth. The cookbook used to exist twice, by
hand: a 740-line site page and a 122-line `docs/examples.md`, sharing two of
their 36 commands. The wiki renders from `docs/`, so wiki readers were getting
roughly a third of the recipes — not as a stated subset, but as a page that
looked complete.

The transform is the same shape as `build-site-internals.py` and deliberately
imports that script's `DOCS_TO_SITE` map rather than restating it. Two copies
of one mapping is how the cookbook drifted in the first place, and this repo
has already deleted one duplicated rule for the same reason (see the removed
step 5c in `.githooks/pre-commit`).

Every page here had the same defect: two hand-maintained copies that drifted.
Add a page by registering it in PAGES — never by copying this file.

Run from the repo root:  python3 scripts/build-site-pages.py [OUTPUT_DIR]
Default OUTPUT_DIR is `website/content/docs`.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

# (docs source, site filename, expected H1, title, weight, description)
PAGES: list[tuple[str, str, str, str, int, str]] = [
    (
        "docs/examples.md",
        "cookbook.md",
        "Cookbook",
        "Cookbook",
        2,
        "Step-by-step recipes for every major sipnab feature: triage, "
        "filtering, HEP, TLS decryption, MCP, observability, security, audio "
        "export.",
    ),
    (
        "docs/rest-api.md",
        "api.md",
        "REST API & Metrics",
        # Title and weight are the site's originals: they set the sidebar
        # label and its position, so changing them here silently reorders the
        # docs nav. The description is deliberately not the original — the
        # page now covers far more than "REST API endpoints and Prometheus
        # metrics" and that string is what search results and cards show.
        "REST API & Metrics",
        11,
        "REST API and Prometheus metrics: authentication, every endpoint with "
        "its response shape, status codes, curl recipes, and the security "
        "model.",
    ),
    (
        "docs/mcp.md",
        "mcp.md",
        # Source H1 is "MCP server"; the site's title (and sidebar label and
        # weight) are the originals — changing them here silently relabels and
        # reorders the docs nav.
        "MCP server",
        "MCP Server",
        14,
        "Drive sipnab from an AI agent over the Model Context Protocol: "
        "stdio and HTTP transports, every tool, the security model, and "
        "client configuration.",
    ),
    # The remaining ten operator pages, merged and registered together. Each
    # was two hand-maintained copies holding content the other did not, which
    # is worse than a stale page: the wiki renders from docs/, so a reader got
    # the thinner side presented as the whole thing. filter-dsl was the sharpest
    # case — fourteen operational recipes existed only on the site.
    #
    # Every title and weight below is the value the site page already carried.
    # They set the sidebar label and its order, so changing one here silently
    # relabels or reorders the docs nav.
    (
        "docs/install.md",
        "install.md",
        "Installing sipnab",
        "Installation",
        1,
        "Install sipnab from pre-built binaries, cargo, or package managers.",
    ),
    (
        "docs/troubleshooting.md",
        "troubleshooting.md",
        "Troubleshooting",
        "Troubleshooting",
        3,
        "Real-world VoIP diagnostic workflows with exact commands.",
    ),
    (
        "docs/tui-walkthrough.md",
        "tui.md",
        "TUI Walkthrough",
        "TUI Walkthrough",
        4,
        "Your first analysis in the interactive TUI, step by step -- open a "
        "capture, read the ladder, measure a delay, and inspect RTP.",
    ),
    (
        "docs/keybindings.md",
        "keybindings.md",
        "Keybindings",
        "Keybindings",
        5,
        "Complete TUI keyboard shortcut reference for all views.",
    ),
    (
        "docs/theme-guide.md",
        "theme.md",
        "Theme Customization Guide",
        "Theme Guide",
        6,
        "Customize sipnab's TUI colors with 11 semantic color slots and "
        "preset themes.",
    ),
    (
        "docs/cli-reference.md",
        "cli.md",
        "CLI Reference",
        "CLI Reference",
        7,
        "Complete flag reference for sipnab, organized by functional group.",
    ),
    (
        "docs/filter-dsl.md",
        "filter-dsl.md",
        # Source H1 is "Filter DSL Reference"; the sidebar label is the
        # shorter site original.
        "Filter DSL Reference",
        "Filter DSL",
        8,
        "Declarative filter language for matching SIP dialogs and RTP "
        "streams.",
    ),
    (
        "docs/output-formats.md",
        "output-formats.md",
        "Output formats",
        "Output Formats",
        9,
        "Machine-readable output: NDJSON, summary reports, dialog/stream "
        "JSON, and pcap/pcapng.",
    ),
    (
        "docs/config-reference.md",
        "config.md",
        "Config Reference",
        "Config Reference",
        10,
        "TOML configuration file format and all configurable sections.",
    ),
    (
        "docs/mcp-walkthrough.md",
        "mcp-walkthrough.md",
        "MCP walkthrough — every deployment scenario, step by step",
        "MCP Walkthrough",
        15,
        "Step-by-step MCP deployment scenarios: same-box stdio, remote "
        "production servers over SSH or HTTP, HEP capture hosts, TLS "
        "endpoints, fleets, and headless automation.",
    ),
]

BANNER = (
    "<!-- Generated by scripts/build-site-pages.py from {src} — do not edit. "
    "Edit the source page and re-run the script; site_pages_mirror_is_current "
    "fails if this file is stale. -->\n\n"
)


def _internals():
    """Load `build-site-internals.py` for the shared doc->site page mapping.

    The filename has hyphens, so it is not importable as a module name; this is
    the supported way to load it by path. Importing is side-effect free — the
    script guards `main()` behind `__name__`.
    """
    path = Path(__file__).resolve().parent / "build-site-internals.py"
    spec = importlib.util.spec_from_file_location("_sipnab_site_internals", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_INT = _internals()
DOCS_TO_SITE: dict[str, str] = _INT.DOCS_TO_SITE
BLOB: str = _INT.BLOB

LINK_RE = re.compile(r"\]\(\s*(?:\./)?([^)\s]+?\.md)(#[^)\s]*)?\s*\)")

# Links into the code tree; a relative `packaging/deb/build-deb.sh` would
# otherwise survive verbatim onto a site page and resolve to nothing.
CODE_LINK_RE = re.compile(
    r"\]\(\s*((?:\.{1,2}/)*(?:src|tests|crates|benches|fuzz|scripts|contrib"
    r"|packaging|harness|ops|man|demos|\.github|\.githooks)(?:/[^)\s]*)?)\s*\)"
)


def rewrite_link(m: re.Match) -> str:
    target, anchor = m.group(1), (m.group(2) or "")
    if target.startswith(("http://", "https://")):
        return m.group(0)
    site = DOCS_TO_SITE.get(target)
    if site:
        return f"](@/docs/{site}{anchor})"
    return f"]({BLOB}/docs/{target}{anchor})"


def rewrite_code_link(m: re.Match) -> str:
    parts = [p for p in m.group(1).split("/") if p not in ("", ".")]
    while parts and parts[0] == "..":
        parts.pop(0)
    return f"]({BLOB}/{'/'.join(parts)})"


def render(src: str, text: str, want_h1: str, title: str, weight: int,
           description: str) -> str:
    h1, body = _INT.strip_leading_h1(text)
    if h1 != want_h1:
        raise SystemExit(f"{src} H1 is {h1!r}, expected {want_h1!r}")
    body = LINK_RE.sub(rewrite_link, body)
    body = CODE_LINK_RE.sub(rewrite_code_link, body)
    head = "\n".join(
        [
            "+++",
            f"title = {_INT.toml_str(title)}",
            f"weight = {weight}",
            f"description = {_INT.toml_str(description)}",
            "+++",
            "",
        ]
    )
    return head + BANNER.format(src=src) + body


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    out_dir = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else root / "website" / "content" / "docs"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    for src, site_name, want_h1, title, weight, description in PAGES:
        rendered = render(
            src, (root / src).read_text(encoding="utf-8"), want_h1, title,
            weight, description,
        )
        (out_dir / site_name).write_text(rendered, encoding="utf-8")
        print(f"  {src:22s} -> {site_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
