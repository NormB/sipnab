#!/usr/bin/env python3
"""Enumerate every capability-bearing item on each of the four surfaces (PAR1).

This is the raw material the surface-parity JOIN is validated against. It reads
the FOUR surfaces from their own sources -- never a second hand table -- so a
capability that lands on one surface and not another is visible:

  CLI   long flags, from the binary's own --help plus `hide = true` args in cli.rs
  TUI   variants of the `View` enum in src/tui/state.rs
  REST  `.route("...")` paths registered in src/output/api.rs
  MCP   `#[tool(name = "...")]` across src/mcp/

`--write` renders the four inventories into
`docs/design/surface-capability-inventory.md`, and `tests/capability_matrix_test.rs`
re-derives each surface from its own source and holds that generated doc to the
program (set, not count, with an anti-vacuity floor) -- so the doc cannot rot
into describing a program that no longer exists.

The authored capability<->surface JOIN that this raw material feeds --
`docs/design/surface-capability-matrix.md`, mapping each capability to its
spelling on the surfaces it belongs on and a recorded DECISION where it does not
(per docs/design/surface-parity-definition.md) -- and the parity gate over that
contract are PAR2, and land next to this file.

Run from the repo root, after `cargo build --features full`:

    python3 scripts/capability-matrix.py            # print the four inventories
    python3 scripts/capability-matrix.py --json      # machine-readable, for the gate
    python3 scripts/capability-matrix.py --write     # regenerate the inventory doc
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "target" / "debug" / "sipnab"


def cli_flags():
    """Every long flag: the binary's --help, plus `hide = true` flags in cli.rs.

    The same two-source read `coverage-matrix.py` documents -- a hidden flag is
    still a surface a user can pass, so a matrix that omits it describes the
    advertised program rather than the real one.
    """
    if not BIN.exists():
        sys.exit(f"build the binary first: {BIN} is missing (cargo build --features full)")
    help_text = subprocess.run(
        [str(BIN), "--help"], capture_output=True, text=True, check=False
    ).stdout
    flags = set()
    for line in help_text.splitlines():
        m = re.match(r"^\s{2,6}(?:-[A-Za-z], )?(--[a-z0-9-]+)", line)
        if m:
            flags.add(m.group(1))
    cli_rs = (ROOT / "src" / "cli.rs").read_text()
    for attr in re.findall(r"#\[arg\((.*?)\)\]", cli_rs, re.S):
        if "hide = true" not in attr:
            continue
        long = re.search(r'long\s*=\s*"([a-z0-9-]+)"', attr)
        if long:
            flags.add(f"--{long.group(1)}")
    return sorted(flags)


def tui_views():
    """Variants of the `View` enum -- one per top-level thing the TUI can show.

    The enum is the honest surface: a view a person can reach is a variant here,
    and a variant nobody can reach fails compilation elsewhere. Payload variants
    (`CallFlow(String)`, `RawMessage { .. }`) are named by their variant alone.
    """
    state = (ROOT / "src" / "tui" / "state.rs").read_text()
    m = re.search(r"pub enum View \{(.*?)\n\}", state, re.S)
    if not m:
        sys.exit("could not find `pub enum View` in src/tui/state.rs")
    body = m.group(1)
    views = []
    for line in body.splitlines():
        # A variant line starts with an uppercase identifier at one indent.
        vm = re.match(r"\s+([A-Z][A-Za-z0-9]+)\b", line)
        if vm:
            views.append(vm.group(1))
    return sorted(set(views))


def api_routes():
    text = (ROOT / "src" / "output" / "api.rs").read_text()
    return sorted(set(re.findall(r'\.route\(\s*"([^"]+)"', text)))


def mcp_tools():
    text = "\n".join(
        f.read_text() for f in sorted((ROOT / "src" / "mcp").rglob("*.rs"))
    )
    return sorted(set(re.findall(r'#\[tool\(\s*name\s*=\s*"([^"]+)"', text)))


def inventories():
    return {
        "cli": cli_flags(),
        "tui": tui_views(),
        "rest": api_routes(),
        "mcp": mcp_tools(),
    }


SURFACE_TITLES = {
    "cli": "CLI flags",
    "tui": "TUI views",
    "rest": "REST routes",
    "mcp": "MCP tools",
}
OUT = ROOT / "docs" / "design" / "surface-capability-inventory.md"
BASE = "https://github.com/NormB/sipnab"


def repo_link(path):
    """A clickable link to a tracked repo file, in the exact form the doc-link
    hygiene gate (`scripts/link-repo-paths.py`) demands: docs/ is published to
    the website and the wiki, so a tracked path shown as a bare code span is
    text a reader must retype. Text files get `/blob/main/`. Emitted here rather
    than left for the fixer because the doc is generated -- a fixer's edit would
    not survive the next `--write`.
    """
    return f"[`{path}`]({BASE}/blob/main/{path})"


def render(inv):
    """The generated inventory doc: the four surfaces, each from its own source.

    The freshness gate (`tests/capability_matrix_test.rs`) holds THIS to the
    program, and the authored `surface-capability-matrix.md` (PAR2) must account
    for every item here -- either as a capability's spelling or a declared
    non-capability (invocation/config).
    """
    lines = [
        "# Surface capability inventory (PAR1)",
        "",
        f"**Generated by {repo_link('scripts/capability-matrix.py')} -- "
        "do not edit.**",
        "Regenerate: `cargo build --features full && "
        "python3 scripts/capability-matrix.py --write`.",
        "",
        "Every capability-bearing item on each of the four surfaces, read from the",
        "surface's own source (CLI `--help` + hidden args, the `View` enum, axum",
        "`.route(...)`, `#[tool(...)]`). This is the raw material for the parity",
        "JOIN in `surface-capability-matrix.md` (PAR2, forthcoming); a capability",
        "reachable three ways and not four is visible only once these four are set",
        f"beside one another. {repo_link('tests/capability_matrix_test.rs')} keeps",
        "this current and requires the matrix to account for every row here.",
        "",
        f"Totals: CLI {len(inv['cli'])}, TUI {len(inv['tui'])}, "
        f"REST {len(inv['rest'])}, MCP {len(inv['mcp'])}.",
    ]
    for surface in ("cli", "tui", "rest", "mcp"):
        items = inv[surface]
        lines += ["", f"## {SURFACE_TITLES[surface]} ({len(items)})", ""]
        lines += [f"- `{item}`" for item in items]
    return "\n".join(lines) + "\n"


def main():
    inv = inventories()
    if "--json" in sys.argv[1:]:
        print(json.dumps(inv, indent=2))
        return 0
    if "--write" in sys.argv[1:]:
        OUT.write_text(render(inv), encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)}")
        return 0
    print(render(inv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
