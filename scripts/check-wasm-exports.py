#!/usr/bin/env python3
"""Fail if the built WASM glue is missing an export `src/wasm.rs` declares.

Run from the repo root:  python3 scripts/check-wasm-exports.py
Prints each missing export on stderr and EXITS NON-ZERO when there is any.

This replaces a hand-kept list of twelve names that lived in TWO places --
`.githooks/pre-commit` gate 4 and `tests/wasm_exports_test.rs`, byte-duplicated
-- while `src/wasm.rs` exported sixteen. `new`, `dialog_count`, `packet_count`
and `sip_message_count` were on neither list, so renaming three of them in the
built glue passed the shell gate, passed the Rust test, and committed.

The Rust test's own docstring said it "catches stale WASM builds where new Rust
functions were added but wasm-pack wasn't re-run". A hand-kept list is
structurally incapable of that: a NEW function is, by definition, not on it.
The list has to be derived from the source, which is what this does.

Membership was also tested with `name + '('`, matching anywhere in the file --
so `filter` was satisfied by any JS `.filter(` call. wasm-bindgen emits each
export as a class method at the start of a line, so that is what is matched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WASM_RS = Path("src/wasm.rs")
GLUE = Path("website/static/wasm/sipnab.js")

# `pub fn name` inside the #[wasm_bindgen] impl block. The constructor is
# annotated separately and reaches JS as `constructor`, not by its Rust name.
FN_RE = re.compile(r"^\s*pub fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)


def declared_exports(source: str) -> list[str]:
    """Every `pub fn` in the wasm_bindgen impl block, in declaration order."""
    at = source.find("#[wasm_bindgen]\nimpl ")
    if at == -1:
        # Fall back to the whole file rather than silently returning nothing:
        # an empty list would make every check below pass.
        at = 0
    return FN_RE.findall(source[at:])


def main() -> int:
    if not GLUE.is_file():
        print(f"{GLUE} not found — nothing to check", file=sys.stderr)
        return 0  # the caller decides whether an absent build is fatal

    names = declared_exports(WASM_RS.read_text())
    if len(names) < 10:
        print(
            f"check-wasm-exports: derived only {len(names)} exports from {WASM_RS} "
            f"({names}) — the parse is broken, and finding nothing missing means nothing",
            file=sys.stderr,
        )
        return 2

    js = GLUE.read_text()
    missing = []
    for name in names:
        # wasm-bindgen renames the `#[wasm_bindgen(constructor)]` fn to
        # `constructor` in the emitted class.
        needle = "constructor" if name == "new" else name
        if not re.search(rf"^\s*{re.escape(needle)}\s*\(", js, re.M):
            missing.append(name)

    if missing:
        print(
            "WASM glue is missing exports declared in src/wasm.rs: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    print(f"OK ({len(names)} exports)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
