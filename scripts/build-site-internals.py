#!/usr/bin/env python3
"""Mirror the developer docs (`docs/internals/`) into the Zola site.

`docs/internals/` is the single source of truth. This script renders it into
`website/content/docs/internals/`, which is committed so the site builds with
Zola alone; `dev_docs_drift_test` re-runs this script and fails if the
committed mirror is stale.

The transform differs from `build-wiki.py` in three ways that matter:

  * Front matter. Zola needs `title`/`weight`/`description` per page, and the
    `has_diagrams` flag decides whether a page loads the mermaid bundle.
  * Link targets. Sibling pages become `@/docs/internals/…` (Zola's internal
    link form — a plain relative `.md` link renders as a dead URL and
    `link_integrity_test` rejects it); everything else becomes a repo blob URL.
  * Mermaid fences become `<pre class="mermaid">` HTML blocks. Zola would
    otherwise syntax-highlight the fence into nested `<span>`s, and the
    diagram source would never reach mermaid intact.

Run from the repo root:  python3 scripts/build-site-internals.py [OUTPUT_DIR]
Default OUTPUT_DIR is `website/content/docs/internals`.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

# The generators are also loaded by tests via importlib, which does not put
# their directory on sys.path -- so add it explicitly rather than relying on
# being run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib_markdown import code_link_re, fence_mask, fences, sub_outside_code  # noqa: E402

REPO = "NormB/sipnab"
BLOB = f"https://github.com/{REPO}/blob/main"

# Source page -> (site slug, weight, title, description). The order here is the
# reading order from `docs/internals/README.md`, and weight preserves it in the
# sidebar. Titles are the page H1s; descriptions are written for the site
# (they surface in the docs index, search results and OpenGraph cards), which
# is why they are curated here rather than scraped from the first paragraph.
PAGES: list[tuple[str, str, int, str, str]] = [
    (
        "domain-primer.md",
        "domain-primer.md",
        1,
        "Domain Primer",
        "The SIP and RTP model the code assumes you already have — written for "
        "the Rust engineer who is new to VoIP.",
    ),
    (
        "subsystem-guide.md",
        "subsystem-guide.md",
        2,
        "Subsystem Guide",
        "One packet's journey from the wire to the screen, traced function by "
        "function across all four packet paths.",
    ),
    (
        "invariants.md",
        "invariants.md",
        3,
        "Invariants",
        "The rules that must not break: what each one is, why it exists, what "
        "enforces it, and how it fails when broken.",
    ),
    (
        "testing.md",
        "testing.md",
        4,
        "Test Architecture",
        "The test tiers, what each one asserts, how to regenerate its "
        "fixtures, and the self-enforcing gate tests.",
    ),
    (
        "walkthroughs.md",
        "walkthroughs.md",
        5,
        "Contributor Walkthroughs",
        "Ordered checklists for the changes people actually make: a new TUI "
        "view, a new detector, a new CLI flag, a new MCP tool.",
    ),
    (
        "build-ci-release.md",
        "build-ci-release.md",
        6,
        "Build, CI and Release",
        "What compiles, what gates a merge, what runs on a tag, and which of "
        "those you can safely ignore.",
    ),
    (
        "threading.md",
        "threading.md",
        7,
        "Threading Model",
        "Thread topology, the channels between them, and the lock discipline "
        "that keeps the synchronous packet path synchronous.",
    ),
    (
        "zero-copy-payloads.md",
        "zero-copy-payloads.md",
        8,
        "Zero-Copy Payloads",
        "The bytes::Bytes spine from capture to output — including a "
        "performance claim the page itself refutes.",
    ),
    (
        "tui-testing.md",
        "tui-testing.md",
        9,
        "TUI Testing",
        "Snapshot, state and interaction testing for the terminal UI.",
    ),
    (
        "profiling.md",
        "profiling.md",
        10,
        "Profiling",
        "Where sipnab's time actually goes, and how to find out on this "
        "hardware without guessing.",
    ),
    (
        "uprobe-capture.md",
        "uprobe-capture.md",
        11,
        "Uprobe TLS Capture",
        "Reading SIP plaintext out of a process's TLS library with kernel "
        "uprobes, and why each step refuses rather than guesses.",
    ),
]

# The developer index becomes the Zola section landing page.
INDEX_SRC = "README.md"
INDEX_TITLE = "Internals"
INDEX_DESCRIPTION = (
    "Developer documentation for people changing sipnab: the domain model, "
    "the subsystem trace, the invariants, and the contributor walkthroughs."
)

SRC_TO_SLUG = {src: slug for src, slug, _, _, _ in PAGES}

# Operator docs that have a site page. `docs/<key>.md` -> `@/docs/<value>`.
# Anything not listed (auth.md, library.md, fault-model.md, and everything
# under docs/design/) has no site page and becomes a blob URL, which is
# correct: the reader still gets the document, just on GitHub.
#
# This claim was once false in the silent direction. `tui-walkthrough.md` had
# a site page (website/content/docs/tui.md, a hand-made copy) while being
# absent from this map, so a link to it from any generated page would have
# been rewritten to a blob URL — sending a reader to GitHub past the site page
# that existed.
#
# The invariant that actually holds, and that docs_to_site_map_is_complete
# derives rather than asserts in prose: every value here names a site page that
# EXISTS, and every generated site page appears here. Most entries are pages one
# of the two generators writes; `benchmarks.md` is the deliberate exception —
# both copies are hand-maintained on purpose, because they frame the same
# measured tables differently, so it has a site page without being generated.
# An earlier version of this comment claimed every entry was generator-written,
# which was false for exactly that one and checked by nothing.
DOCS_TO_SITE = {
    "install.md": "install.md",
    "prometheus-metrics.md": "metrics.md",
    "examples.md": "cookbook.md",
    "troubleshooting.md": "troubleshooting.md",
    "tui-walkthrough.md": "tui.md",
    "keybindings.md": "keybindings.md",
    "theme-guide.md": "theme.md",
    "cli-reference.md": "cli.md",
    "sip-response-codes.md": "sip-response-codes.md",
    "sip-parameters.md": "sip-parameters.md",
    "mos-and-codecs.md": "mos-and-codecs.md",
    "sip-methods.md": "sip-methods.md",
    "sip-header-fields.md": "sip-header-fields.md",
    "filter-dsl.md": "filter-dsl.md",
    "output-formats.md": "output-formats.md",
    "config-reference.md": "config.md",
    "rest-api.md": "api.md",
    "mcp.md": "mcp.md",
    "mcp-deploy.md": "mcp-deploy.md",
    "mcp-tools.md": "mcp-tools.md",
    "mcp-protocol.md": "mcp-protocol.md",
    "uprobe-walkthrough.md": "uprobe-walkthrough.md",
    "sip-lint-rules.md": "sip-lint-rules.md",
    "benchmarks.md": "benchmarks.md",
    "plugins.md": "plugins.md",
    "auth.md": "auth.md",
    "tls-capture.md": "tls-capture.md",
    "internals/profiling.md": "internals/profiling.md",
    # Registering the page in build-site-pages.py's PAGES only makes the page
    # exist; this map is what makes other site pages LINK to it. Missing here,
    # troubleshooting.md's three pointers at the drop diagnosis rewrote to
    # GitHub blob URLs and the site's own high-loss workflow ended by leaving
    # the site.
    "tuning-capture.md": "tuning-capture.md",
    "encapsulations.md": "encapsulations.md",
}

LINK_RE = re.compile(r"\]\(\s*([^)\s]+?\.md)(#[^)\s]*)?\s*\)")

# Links into the code tree — same trees `build-wiki.py` recognizes, because
# both now build the pattern from `.config/code-trees.txt` rather than each
# keeping a pasted copy of the alternation. LINK_RE only matches `.md`, so
# without this a relative `../../src/pipeline.rs` survives verbatim onto a site
# page and resolves to nothing.
CODE_LINK_RE = code_link_re()


def blob_url(target: str) -> str:
    """Repo blob URL for a link relative to `docs/internals/`."""
    parts = [p for p in target.split("/") if p not in ("", ".")]
    prefix = ["docs", "internals"]
    while parts and parts[0] == "..":
        parts.pop(0)
        if prefix:
            prefix.pop()
    return f"{BLOB}/{'/'.join(prefix + parts)}"


def rewrite_link(m: re.Match) -> str:
    target, anchor = m.group(1), (m.group(2) or "")
    if target.startswith(("http://", "https://")):
        return m.group(0)

    # Sibling developer page -> Zola internal link.
    if "/" not in target:
        if target == INDEX_SRC:
            return f"](@/docs/internals/_index.md{anchor})"
        if target in SRC_TO_SLUG:
            return f"](@/docs/internals/{SRC_TO_SLUG[target]}{anchor})"

    # Operator doc one level up that has a site page.
    if target.startswith("../") and "/" not in target[3:]:
        site = DOCS_TO_SITE.get(target[3:])
        if site:
            return f"](@/docs/{site}{anchor})"

    return f"]({blob_url(target)}{anchor})"


def rewrite_code_link(m: re.Match) -> str:
    return f"]({blob_url(m.group(1))})"


# Anchors do not survive the docs -> site move unchanged, because GitHub and
# Zola slugify the same heading differently. For
# `## Step 0 — install sipnab (every server, once)`:
#
#   GitHub  step-0--install-sipnab-every-server-once   (drops the em dash,
#                                                       leaving its two spaces)
#   Zola    step-0-install-sipnab-every-server-once    (collapses the whole run)
#
# and for a heading in backticks, `find_problems`, GitHub keeps the underscore
# while Zola's slugifier turns it into a dash. Anchors in `docs/` are written
# for GitHub, because that is where the file is read directly. So a link that
# resolves in the repo and the wiki silently pointed at nothing on the site.
#
# It surfaced as a hard Zola build failure ("14 broken internal anchor links")
# only because `zola build` checks internal anchors. Nothing in the Rust link
# tests catches it: they resolve anchors with their own slug rule, so they
# agree with the source and disagree with the renderer.
_MD_INLINE_RE = re.compile(r"`([^`]*)`|\[([^\]]*)\]\([^)]*\)|[*_]{1,2}")


def _heading_text(line: str) -> str:
    """The rendered text of an ATX heading line, with inline markup removed."""
    text = line.lstrip("#").strip()
    return _MD_INLINE_RE.sub(lambda m: m.group(1) or m.group(2) or "", text)


def github_slug(text: str) -> str:
    """GitHub's heading anchor: drop punctuation, spaces become hyphens."""
    s = text.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return s.replace(" ", "-")


_ATTR_RE = re.compile(r"\s*\{[^{}]*\}\s*$")


def zola_slug(text: str) -> str:
    """Zola's heading anchor: every non-alphanumeric run becomes one hyphen.

    A trailing `{...}` heading-attribute block is stripped first, matching
    `slug_zola` in `tests/link_integrity_test.rs`. This is load-bearing rather
    than cosmetic: `### GET /v1/dialogs/{call_id}` and `### GET /v1/dialogs`
    both reduce to `get-v1-dialogs`, so Zola numbers the second `-1`, and a
    link written to that numbered form is correct.
    """
    return re.sub(r"[^a-z0-9]+", "-", _ATTR_RE.sub("", text).strip().lower()).strip("-")


def anchor_map(text: str) -> dict[str, str]:
    """`{github_slug: zola_slug}` for every ATX heading outside a code fence."""
    out: dict[str, str] = {}
    # fence_mask, not a toggled bool: a `~~~` block containing a ``` line
    # switches a toggle on with nothing to switch it back, and every heading
    # after it drops out of the anchor map.
    mask = fence_mask(text)
    for n, line in enumerate(text.splitlines()):
        if mask[n] or not line.startswith("#"):
            continue
        rendered = _heading_text(line)
        if not rendered:
            continue
        gh, zola = github_slug(rendered), zola_slug(rendered)
        if gh and zola and gh != zola:
            out[gh] = zola
    return out


def strip_leading_h1(text: str) -> tuple[str, str]:
    """Split off the leading `# ` heading. Returns `(title, body)`.

    The Zola page template renders the title itself, so leaving the H1 in the
    body would print it twice.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "":
            continue
        if line.startswith("# "):
            rest = lines[i + 1:]
            while rest and rest[0].strip() == "":
                rest = rest[1:]
            return line[2:].strip(), "\n".join(rest) + "\n"
        break
    return "", text


def convert_mermaid(text: str) -> tuple[str, bool]:
    """Turn ```mermaid fences into raw `<pre class="mermaid">` blocks.

    Returns `(text, had_diagram)`. A CommonMark HTML block opened by `<pre`
    runs verbatim to its closing tag — blank lines included — so the diagram
    source reaches the browser exactly as authored, with no smart-punctuation
    pass mangling `-->>` into an arrow glyph.

    The fence is found by the shared CommonMark lexer, not by comparing the
    line to the string ``"```mermaid"``. That comparison made the exact
    spelling of the marker the proxy for "is a diagram": a ``~~~mermaid``
    fence, or one with a trailing space, was copied through as literal text and
    shipped to the site as raw diagram source.
    """
    lines = text.splitlines()
    blocks = {f.start: f for f in fences(text) if f.lang == "mermaid"}
    out: list[str] = []
    found = False
    i = 0
    while i < len(lines):
        block = blocks.get(i)
        if block is None:
            out.append(lines[i])
            i += 1
            continue
        found = True
        escaped = html.escape("\n".join(block.body), quote=False)
        out.append('<pre class="mermaid">')
        out.append(escaped)
        out.append("</pre>")
        i = block.end
    return "\n".join(out) + "\n", found


def frontmatter(title: str, weight: int, description: str, has_diagrams: bool) -> str:
    lines = [
        "+++",
        f"title = {toml_str(title)}",
        f"weight = {weight}",
        f"description = {toml_str(description)}",
    ]
    if has_diagrams:
        # Read by page.html: only a page that declares this loads the mermaid
        # bundle, so the 3.4 MB payload never reaches a page without a diagram.
        lines += ["", "[extra]", "has_diagrams = true"]
    lines += ["+++", ""]
    return "\n".join(lines)


def toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


BANNER = (
    "<!-- Generated by scripts/build-site-internals.py from {src} — do not "
    "edit. Edit the source page and re-run the script; "
    "dev_docs_drift_test fails if this file is stale. -->\n\n"
)


def render(src_rel: str, src_text: str, title: str, weight: int, description: str) -> str:
    _, body = strip_leading_h1(src_text)
    body = LINK_RE.sub(rewrite_link, body)
    body = sub_outside_code(CODE_LINK_RE, rewrite_code_link, body)
    body, has_diagrams = convert_mermaid(body)
    return (
        frontmatter(title, weight, description, has_diagrams)
        + BANNER.format(src=f"docs/internals/{src_rel}")
        + body
    )


def render_index(src_text: str) -> str:
    _, body = strip_leading_h1(src_text)
    body = LINK_RE.sub(rewrite_link, body)
    body = sub_outside_code(CODE_LINK_RE, rewrite_code_link, body)
    body, _ = convert_mermaid(body)
    head = "\n".join(
        [
            "+++",
            f"title = {toml_str(INDEX_TITLE)}",
            "weight = 18",
            f"description = {toml_str(INDEX_DESCRIPTION)}",
            'sort_by = "weight"',
            'template = "section.html"',
            'page_template = "page.html"',
            "+++",
            "",
        ]
    )
    return head + BANNER.format(src=f"docs/internals/{INDEX_SRC}") + body


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    src_dir = root / "docs" / "internals"
    out_dir = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else root / "website" / "content" / "docs" / "internals"
    )

    # rglob, not glob: the registry check is bidirectional, so a top-level-only
    # scan means a nested page is neither published nor reported as missing —
    # it simply is not seen, and this loop announces that every page on disk is
    # registered. Nested pages have no slug scheme yet, so one surfacing here
    # is a design decision to make, not a file to skip silently.
    on_disk = {p.relative_to(src_dir).as_posix() for p in src_dir.rglob("*.md")}
    registered = set(SRC_TO_SLUG) | {INDEX_SRC}
    if on_disk != registered:
        for name in sorted(on_disk - registered):
            print(f"ERROR: docs/internals/{name} is not registered in PAGES",
                  file=sys.stderr)
        for name in sorted(registered - on_disk):
            print(f"ERROR: PAGES lists {name}, which does not exist",
                  file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    # Remove stale pages so a renamed source cannot leave an orphan behind.
    # rglob for the same reason as the on-disk scan above: a non-recursive
    # cleanup leaves a nested orphan in the mirror, surviving regeneration and
    # reported by nothing.
    for existing in out_dir.rglob("*.md"):
        existing.unlink()

    (out_dir / "_index.md").write_text(
        render_index((src_dir / INDEX_SRC).read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    print(f"  {INDEX_SRC:28s} -> _index.md")

    for src, slug, weight, title, description in PAGES:
        text = (src_dir / src).read_text(encoding="utf-8")
        (out_dir / slug).write_text(
            render(src, text, title, weight, description), encoding="utf-8"
        )
        print(f"  {src:28s} -> {slug}")

    print(f"Wrote {len(PAGES) + 1} pages to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
