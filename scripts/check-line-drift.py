#!/usr/bin/env python3
"""Check that a documented line citation still points at the code it names.

`linked_code_targets_exist` proves a citation's FILE exists and
`cited_line_numbers_link_to_the_line` proves the link carries an `#L` fragment.
Neither proves the line still holds the thing the sentence is about, and that is
the failure a reader actually hits: `icid-correlation.md` sent them to
`find_correlated_scored` at :935 when it had moved to :981, and
`maintainability-perf-spec.md` cites `src/main.rs:1996` in a file that is 172
lines long. A precise, confident, wrong citation is worse than no citation --
the reader lands on unrelated code and believes it is the subject.

# One rule, one implementation

This script is BOTH the gate and the fixer: `line_citations_point_at_their_own
_symbol` in tests/dev_docs_drift_test.rs runs it in check mode and asserts exit
0, and `--apply` re-points what it can. A separate Rust reimplementation would
be a second rule that agrees today and drifts tomorrow -- which is exactly the
divergence found between `repo_paths_in_docs_are_clickable` and
`scripts/link-repo-paths.py`, where the fixer would have produced 33 links the
gate never asked for.

# What counts as checkable

A citation is checkable only when the prose names a Rust identifier next to it,
within `CONTEXT_CHARS` either side. Most citations do not, and those are skipped
rather than guessed at: a gate that invents a subject reports faults that are
its own.

Re-pointing targets a DEFINITION (`fn`/`struct`/`enum`/`const`/`static`/`impl`/
`type`/`trait`/`let`), and only when exactly one exists. Matching any mention
would re-point at a call site, which is how the drift starts.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# [`src/foo.rs:123`](url#L123)
CITE = re.compile(r"\[`([A-Za-z0-9_./-]+\.rs):(\d+)`\]\((?:[^)]*)\)")
# A backticked identifier, optionally with a call/gener1c suffix.
IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)")
# Deliberately NOT `let`. A local binding is not a documentable symbol, and
# including it made `cli`, `rtp`, `src` and `guard` look like definitions --
# every one of those is a variable name someone wrote near a citation, and the
# gate then demanded the citation point at an arbitrary `let` site.
DEF = r"(?:fn|struct|enum|const|static|impl|type|trait|mod|macro_rules!)"

CONTEXT_CHARS = 90
TOLERANCE = 15

# Identifiers that name a concept rather than a definition, so finding them
# near a citation says nothing. Kept short and specific on purpose.
NOT_SYMBOLS = {
    "true", "false", "None", "Some", "Ok", "Err", "self", "mut", "pub", "use",
    "if", "let", "fn", "match", "return", "async", "await", "impl", "dyn",
    # `mod tests` is in every Rust file; finding it proves nothing.
    "tests", "test", "main", "new", "default",
}


def symbol_near(text: str, start: int, end: int) -> str | None:
    """The identifier this citation is about, or None if the prose names none."""
    # NEAREST wins, not "after wins". Both forms occur — "`foo` ([src/x.rs:12])"
    # and "([src/x.rs:12]) — `foo` does X" — and a fixed preference reads the
    # wrong one whenever the other is closer. It picked `process_parsed_packet`
    # 75 characters after a citation whose subject, `processor.process`, sat two
    # characters before it, and then reported drift against a symbol the
    # sentence was not citing.
    after = text[end : end + CONTEXT_CHARS]
    before = text[max(0, start - CONTEXT_CHARS) : start]

    def usable(name: str) -> bool:
        return name not in NOT_SYMBOLS and len(name) > 2

    best, best_dist = None, CONTEXT_CHARS + 1
    for m in IDENT.finditer(after):
        if usable(m.group(1)) and m.start() < best_dist:
            best, best_dist = m.group(1), m.start()
    for m in IDENT.finditer(before):
        dist = len(before) - m.end()
        if usable(m.group(1)) and dist < best_dist:
            best, best_dist = m.group(1), dist
    return best


def definition_lines(lines: list[str], sym: str) -> list[int]:
    """1-based lines where `sym` is DEFINED (not merely mentioned).

    `impl` is ranked below the rest and dropped when anything else matches. A
    type has one definition and any number of impl blocks, so `PacketProcessor`,
    `AlertEngine` and `App` each looked ambiguous — `struct X` plus `impl X` —
    when only one of the two is the thing a reader is being sent to. Citing the
    impl block would also be unstable: adding a second one changes which line
    "the definition" means.
    """
    pat = re.compile(rf"\b{DEF}\s+{re.escape(sym)}\b")
    hits = [(i + 1, l) for i, l in enumerate(lines) if pat.search(l)]
    real = [n for n, l in hits if not re.match(r"\s*(?:pub\s+)?impl\b", l)]
    return real if real else [n for n, _ in hits]


def check(apply: bool) -> int:
    problems, fixed, checked = [], 0, 0

    for md in sorted(REPO.glob("docs/**/*.md")):
        if "superpowers" in str(md):
            continue
        text = md.read_text()
        rel = md.relative_to(REPO)
        out, moved = text, False

        for m in CITE.finditer(text):
            path, line = m.group(1), int(m.group(2))
            src = REPO / path
            if not src.is_file():
                continue  # linked_code_targets_exist owns missing files
            lines = src.read_text().splitlines()
            sym = symbol_near(text, m.start(), m.end())

            # Out of range is wrong whether or not a symbol is named.
            if line > len(lines):
                where = definition_lines(lines, sym) if sym else []
                if apply and len(where) == 1:
                    out = out.replace(m.group(0), _repoint(m.group(0), where[0]))
                    moved = True
                    fixed += 1
                else:
                    problems.append(
                        f"{rel}: cites {path}:{line} but that file has "
                        f"{len(lines)} lines"
                        + (f" ({sym} is at {where})" if where else "")
                    )
                continue

            if not sym:
                continue

            # A citation is only CHECKABLE when the named identifier is defined
            # in the cited file. Without this the scan flagged `src`, `cli`,
            # `tests`, `pcap`, `to_vec` and `requires` -- words that appear
            # beside a citation without being its subject, in files that never
            # define them. Those are not drifted citations, they are the gate
            # reading prose, and a gate that cries about `to_vec` gets skimmed
            # exactly like the one that cries about `--limit`.
            where = definition_lines(lines, sym)
            if not where:
                continue
            checked += 1
            lo, hi = max(0, line - 1 - TOLERANCE), min(len(lines), line + TOLERANCE)
            if re.search(rf"\b{re.escape(sym)}\b", "\n".join(lines[lo:hi])):
                continue

            if apply and len(where) == 1:
                out = out.replace(m.group(0), _repoint(m.group(0), where[0]))
                moved = True
                fixed += 1
            else:
                problems.append(
                    f"{rel}: cites {path}:{line} for `{sym}`, which is not "
                    f"within {TOLERANCE} lines of there"
                    + (f" (defined at {where})" if where else " (no unique definition found)")
                )

        if moved:
            md.write_text(out)

    if apply:
        print(f"re-pointed {fixed} citation(s); {len(problems)} need a human")
    print(f"checked {checked} citation(s) that name a symbol")
    for p in problems:
        print(f"  {p}")
    return 1 if problems else 0


def _repoint(cite: str, line: int) -> str:
    """Rewrite both the label's `:NNN` and the link's `#LNNN` together."""
    cite = re.sub(r"(\.rs):\d+`\]", rf"\1:{line}`]", cite)
    cite = re.sub(r"#L\d+(-L\d+)?", f"#L{line}", cite)
    return cite


if __name__ == "__main__":
    sys.exit(check(apply="--apply" in sys.argv))
