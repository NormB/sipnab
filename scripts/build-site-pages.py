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

# The generators are also loaded by tests via importlib, which does not put
# their directory on sys.path -- so add it explicitly rather than relying on
# being run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib_markdown import code_link_re, sub_outside_code  # noqa: E402

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
        "docs/prometheus-metrics.md",
        "metrics.md",
        "Prometheus metrics",
        "Prometheus Metrics",
        # 34, not 12: weight only has to be UNIQUE
        # (`docs_page_weights_are_unique_and_descriptions_present`), and 12 is
        # api-clients.md. Sidebar order comes from the explicit path lists in
        # the nav_group macros, where this sits between the REST API and
        # Integrations -- next to HEP, because both are how sipnab plugs into a
        # monitoring estate, while staying separate pages because one carries
        # SIP and the other carries numbers.
        36,
        "Every metric family sipnab emits, what each one means, which are "
        "counters and which are gauges, and the scrape config -- split out of "
        "the REST API page, which a scrape target's reader never needs.",
    ),
    (
        "docs/rest-api.md",
        "api.md",
        "REST API & metrics",
        # Title and weight are the site's originals: they set the sidebar
        # label and its position, so changing them here silently reorders the
        # docs nav. The description is deliberately not the original — the
        # page now covers far more than "REST API endpoints" and that string is
        # what search results and cards show.
        #
        # No longer "REST API & Metrics". Prometheus got its own page, so a
        # label and description promising metrics here sent a reader looking
        # for them to the wrong page, and competed with the Prometheus Metrics
        # entry directly below in the same nav group. The `/metrics` endpoint
        # is still documented here because the `api` feature is what serves it;
        # what the metric NAMES mean lives on the metrics page.
        "REST API",
        11,
        "sipnab's REST API: authentication, every endpoint with its response "
        "shape, status codes, curl recipes, and the security model. Metric "
        "names and their meaning are on the Prometheus metrics page.",
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
        "Drive sipnab from an AI agent over the Model Context Protocol: what "
        "it is, a first working example, and where to go for deployment, the "
        "tool reference, and the protocol contract.",
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
        "docs/rtpengine.md",
        "rtpengine.md",
        "Attribute media on an rtpengine relay",
        "rtpengine Relays",
        32,
        "Media captured on a standalone rtpengine relay comes back orphaned "
        "because a relay carries no SIP. Read rtpengine's own control plane "
        "to name the calls, with no change to an existing Homer pipeline.",
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
        "Theme customization guide",
        "Theme Guide",
        6,
        "Customize sipnab's TUI colors with 11 semantic color slots and "
        "preset themes.",
    ),
    (
        "docs/cli-reference.md",
        "cli.md",
        "CLI reference",
        "CLI Reference",
        7,
        "Complete flag reference for sipnab, organized by functional group.",
    ),
    (
        "docs/filter-dsl.md",
        "filter-dsl.md",
        # Source H1 is "Filter DSL reference"; the sidebar label is the
        # shorter site original.
        "Filter DSL reference",
        "Filter DSL",
        8,
        "Declarative filter language for matching SIP dialogs and RTP "
        "streams.",
    ),
    (
        "docs/sip-header-fields.md",
        "sip-header-fields.md",
        "SIP header fields",
        "Header Fields",
        22,
        "Every SIP header field in the IANA registry, its compact form, and the "
        "RFC that defines it.",
    ),
    (
        "docs/sip-methods.md",
        "sip-methods.md",
        "SIP request methods",
        "Request Methods",
        21,
        "Every SIP method in the IANA registry, the RFC section defining it, and "
        "which dialog state machine sipnab runs it through.",
    ),
    (
        "docs/sip-parameters.md",
        "sip-parameters.md",
        "SIP parameters",
        "Parameters",
        23,
        "Every SIP URI parameter, header-field parameter and option tag in the "
        "IANA registry, with the RFC that defines it.",
    ),
    (
        "docs/mos-and-codecs.md",
        "mos-and-codecs.md",
        "MOS and codecs",
        "MOS & Codecs",
        24,
        "Where the quality score comes from, which codecs have a published "
        "impairment factor behind it, and which report a placeholder.",
    ),
    (
        "docs/sip-response-codes.md",
        "sip-response-codes.md",
        "SIP response codes",
        "Response Codes",
        20,
        "Every SIP response code in the IANA registry, the RFC section that "
        "defines it, and whether it means the call failed.",
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
        "Config reference",
        "Config Reference",
        10,
        "TOML configuration file format and all configurable sections.",
    ),
    (
        "docs/uprobe-walkthrough.md",
        "uprobe-walkthrough.md",
        "Reading SIP over TLS without keys — step by step",
        "TLS Without Keys",
        28,
        "What uprobe and eBPF capture is and is NOT, its security "
        "implications, whether your kernel supports it at all, and how to "
        "run both backends step by step.",
    ),
    (
        "docs/mcp-deploy.md",
        "mcp-deploy.md",
        "MCP walkthrough — every deployment scenario, step by step",
        "MCP Deployment",
        15,
        "Step-by-step MCP deployment scenarios: same-box stdio, remote "
        "production servers over SSH or HTTP, HEP capture hosts, TLS "
        "endpoints, fleets, and headless automation.",
    ),
    (
        "docs/mcp-estate.md",
        "mcp-estate.md",
        "Run MCP across an estate, not one box",
        "MCP Across an Estate",
        16,
        "Several SIP servers feeding one capture host, reaching sipnab from "
        "outside the network, one agent holding many capture hosts, and "
        "following one call across an SBC, a proxy and a PBX.",
    ),
    (
        "docs/mcp-tools.md",
        "mcp-tools.md",
        "MCP tool reference",
        "MCP Tools",
        17,
        "Every MCP tool sipnab exposes, what question each answers, and the "
        "fields it returns.",
    ),
    (
        "docs/mcp-protocol.md",
        "mcp-protocol.md",
        "MCP protocol",
        "MCP Protocol",
        18,
        "The MCP wire contract: security model, what the write verbs may do, "
        "untrusted capture text, the stdio invariant, and error semantics.",
    ),
    # Registered when the conformance linter reached MCP. The page was in
    # build-wiki.py's PAGES and not this one, so `docs/mcp.md`'s link to it
    # rewrote to a GitHub blob URL: a site reader following the rule catalog
    # from the tool reference left the site. Weight 23 puts it after the other
    # reference pages (18-22) rather than reordering any of them.
    (
        "docs/sip-lint-rules.md",
        "sip-lint-rules.md",
        "SIP conformance rules",
        "SIP Conformance Rules",
        25,
        "Every rule the SIP conformance linter runs, the RFC section behind "
        "it, the severity and basis it reports under, and how to suppress it "
        "in CI.",
    ),
    # Registered with the page itself, for the reason the sip-lint-rules entry
    # above records: `docs/troubleshooting.md` sends a reader here three times
    # for the drop diagnosis, and troubleshooting IS mirrored. Registered in
    # build-wiki.py alone, all three of those rewrote to a GitHub blob URL, so
    # the site's own high-loss workflow ended by leaving the site.
    (
        "docs/tuning-capture.md",
        "tuning-capture.md",
        "Tuning capture on a busy server",
        "Tuning Capture",
        # 24, not 12: weight 12 was already taken by api-clients.md, and
        # `docs_page_weights_are_unique_and_descriptions_present` requires it to
        # be unique. Ordering in the sidebar comes from the explicit path lists
        # in the nav_group macros, not from this number.
        26,
        "Size the kernel capture ring, read the kernel and interface drop "
        "counters, tell the two apart, and decide between the `any` device "
        "and a named interface.",
    ),
    # Registered with the page itself, for the reason the two entries above
    # record. `docs/vcon.md` is the operator page for the vCon exporter and it
    # links `docs/internals/vcon.md`, `docs/library.md` and the three surface
    # reference pages; unregistered here it would exist only on the wiki, and
    # every generated page pointing at it would rewrite to a GitHub blob URL.
    (
        "docs/vcon.md",
        "vcon.md",
        "Export one observed call as a vCon",
        "vCon Export",
        # 29: the next free weight. `docs_page_weights_are_unique_and_
        # descriptions_present` requires uniqueness; sidebar order comes from
        # the nav_group path lists, not from this number.
        29,
        "Export one observed dialog as a vCon container: what the format is, "
        "how to produce one, and what an observer's record does and does not "
        "let a consumer conclude.",
    ),
    (
        "docs/encapsulations.md",
        "encapsulations.md",
        "Encapsulations",
        "Encapsulations",
        # 25: the next free weight. `docs_page_weights_are_unique_and_
        # descriptions_present` requires uniqueness; sidebar order comes from
        # the nav_group path lists, not from this number.
        27,
        "Which link types, EtherTypes and tunnels sipnab can read a SIP dialog "
        "out of, which it cannot, and what it reports when a frame does not "
        "decode.",
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

# Same-page anchors: `](#some-heading)`, which LINK_RE does not match because
# there is no `.md` to key on. These need the same GitHub -> Zola translation
# as a cross-page anchor, and they were the larger half of the breakage.
SELF_ANCHOR_RE = re.compile(r"\]\(\s*(#[^)\s]+)\s*\)")

# `{docs-relative name: {github_slug: zola_slug}}`, built once from the real
# heading text of every docs page, so a heading rename cannot leave this stale.
ANCHORS: dict[str, dict[str, str]] = {}


def _load_anchors(root: Path) -> None:
    """Index every `docs/` page's headings under both slug algorithms."""
    docs = root / "docs"
    for path in docs.rglob("*.md"):
        rel = path.relative_to(docs).as_posix()
        ANCHORS[rel] = _INT.anchor_map(path.read_text(encoding="utf-8"))


def _xlate(target: str, anchor: str) -> str:
    """Translate `#github-slug` to `#zola-slug` for the page it points into."""
    if not anchor:
        return anchor
    return "#" + ANCHORS.get(target, {}).get(anchor[1:], anchor[1:])

# Links into the code tree; a relative `packaging/deb/build-deb.sh` would
# otherwise survive verbatim onto a site page and resolve to nothing. Built
# from `.config/code-trees.txt`, the one list every generator, the fixer and
# the Rust gates share -- the alternation used to be pasted here.
CODE_LINK_RE = code_link_re()


def rewrite_link(m: re.Match) -> str:
    target, anchor = m.group(1), (m.group(2) or "")
    if target.startswith(("http://", "https://")):
        return m.group(0)
    site = DOCS_TO_SITE.get(target)
    if site:
        # Only a site page needs the Zola spelling. A blob URL is read on
        # GitHub, where the anchor is already correct.
        return f"](@/docs/{site}{_xlate(target, anchor)})"
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
    # Same-page anchors resolve against this page's own headings.
    rel = src[len("docs/"):]
    body = SELF_ANCHOR_RE.sub(
        lambda m: f"]({_xlate(rel, m.group(1))})", body
    )
    body = sub_outside_code(CODE_LINK_RE, rewrite_code_link, body)

    # Mermaid, converted with the SAME function the internals generator uses.
    #
    # This page tree had no mermaid handling at all, so a diagram in a
    # user-facing doc shipped to the site as literal fence text — the feature
    # silently did not exist here while working fine one directory over.
    # Reusing `_INT.convert_mermaid` rather than copying it keeps one
    # definition of what a diagram is; the internals generator's own comment
    # explains why the fence is found by the CommonMark lexer instead of by
    # string comparison.
    body, has_diagrams = _INT.convert_mermaid(body)

    lines = [
        "+++",
        f"title = {_INT.toml_str(title)}",
        f"weight = {weight}",
        f"description = {_INT.toml_str(description)}",
    ]
    if has_diagrams:
        # Gates the 3.4 MB mermaid bundle: page.html loads it only when a page
        # declares this, so pages without diagrams pay nothing.
        lines += ["", "[extra]", "has_diagrams = true"]
    head = "\n".join(lines + ["+++", ""])
    return head + BANNER.format(src=src) + body


def write_llms_txt(root: Path, static_dir: Path) -> None:
    """Emit `llms.txt` (a routing index) and `llms-full.txt` (the whole text).

    Both are built from `PAGES`, the same tuple list that drives the site, so
    a page cannot appear on the website and be missing here: the description
    beside each entry is the one the docs nav already shows, not a second copy
    to keep in step.

    # Why plain text at a fixed path

    An agent asked about sipnab has to find the documentation before it can
    read it, and rendered HTML is the worst form to hand it — nav chrome, the
    mermaid bundle, and the reader's theme all arrive with the prose. The
    source is markdown to begin with, so serving it back is free.

    `llms.txt` is the routing file: one line per page, with the description, so
    a fetch of ~50 lines decides which page answers the question.
    `llms-full.txt` is every page concatenated, for the case where the whole
    corpus is wanted in one request.

    # What this does NOT do

    It does not make the site reachable. sipnab.com is fronted by Cloudflare,
    whose managed AI-crawler rules return 403 to `GPTBot`, `ClaudeBot`,
    `CCBot`, `Bytespider`, `Amazonbot`, `Applebot-Extended`, `Google-Extended`
    and `meta-externalagent` — measured 2026-08-19: those two get 403, an
    ordinary browser UA gets 200 on the same URL. The same rule applies to
    these files. Whether an agent may read them is a Cloudflare policy
    decision and is not settled here; this only ensures that anything allowed
    through finds the text rather than the chrome.

    Note also that the managed `robots.txt` block publishes
    `Content-Signal: ai-train=no, use=reference` while the 403 blocks
    reference use too — the enforcement is stricter than the signal. That is
    worth reconciling in the dashboard, not in this script.
    """
    lines = [
        "# sipnab",
        "",
        "> SIP and RTP capture, analysis and diagnosis. One static binary that "
        "reads live traffic, a pcap, or a HEP feed, and reports call flow, RTP "
        "quality, NAT and security findings.",
        "",
        "This file indexes the documentation as plain text. `llms-full.txt` "
        "beside it carries every page concatenated.",
        "",
        "## Docs",
        "",
    ]
    # PAGES order is the docs-nav order, so the index reads the way the site
    # reads rather than alphabetically.
    for src, site_name, _want_h1, title, _weight, description in PAGES:
        url = f"https://sipnab.com/docs/{Path(site_name).stem}/"
        lines.append(f"- [{title}]({url}): {description}")

    # The internals set comes from the OTHER generator. Indexing only PAGES
    # would ship an index that silently omits 21 published pages -- the
    # architecture, threading and domain-primer material an agent asked "why
    # is it built this way" most needs. `_INT` is already imported above for
    # DOCS_TO_SITE, so this costs nothing and cannot drift from what that
    # generator publishes.
    lines += ["", "## Internals", ""]
    for src_name, site_name, _weight, title, description in _INT.PAGES:
        url = f"https://sipnab.com/docs/internals/{Path(site_name).stem}/"
        lines.append(f"- [{title}]({url}): {description}")
    (static_dir / "llms.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    full = [
        "# sipnab documentation",
        "",
        "Every published page, concatenated, in docs-nav order. Generated from "
        "the same source the website is built from; see llms.txt for an index.",
        "",
    ]
    sources = [src for src, *_ in PAGES]
    sources += [f"docs/internals/{n}" for n, *_ in _INT.PAGES]
    for src in sources:
        body = (root / src).read_text(encoding="utf-8")
        full += [f"<!-- source: {src} -->", "", body.rstrip(), "", "---", ""]
    (static_dir / "llms-full.txt").write_text("\n".join(full) + "\n", encoding="utf-8")
    print(f"  llms.txt / llms-full.txt <- {len(sources)} pages")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    out_dir = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else root / "website" / "content" / "docs"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    _load_anchors(root)
    for src, site_name, want_h1, title, weight, description in PAGES:
        rendered = render(
            src, (root / src).read_text(encoding="utf-8"), want_h1, title,
            weight, description,
        )
        (out_dir / site_name).write_text(rendered, encoding="utf-8")
        print(f"  {src:22s} -> {site_name}")
    # Written into static/ so Zola copies them to the site root verbatim,
    # where the llms.txt convention expects them.
    write_llms_txt(root, root / "website" / "static")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
