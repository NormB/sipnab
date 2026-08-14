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

# [`src/foo.rs:123`](url#L123) -- the link is captured because the label alone
# does not say which file is meant. See `source_for`.
CITE = re.compile(r"\[`([A-Za-z0-9_./-]+\.rs):(\d+)`\]\(([^)]*)\)")
# https://github.com/OWNER/REPO/blob/REF/the/path.rs
BLOB = re.compile(r"https?://[^/]*github\.com/[^/]+/[^/]+/blob/[^/]+/(.+)$")
# A markdown link whose label is backticked: [`whatever`](target). See
# `symbol_near` for why these are masked on the trailing side of a citation.
LINKED = re.compile(r"\[`[^`\n]+`\]\([^)\n]*\)")
# A backticked identifier, optionally path-qualified: `merge`, `Store::merge`.
# The qualifier is captured because the prose is usually citing the MEMBER --
# `resolve_symbol` decides which segment the sentence is actually about.
IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)")
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
    # BEFORE wins. The subject precedes its citation in every form these pages
    # use — "`foo` ([`x.rs:12`](url))" and "[`foo`](path) at [`x.rs:12`](url)" —
    # so an identifier AFTER a citation is the subject of the NEXT one.
    #
    # Nearest-wins-either-side was tried and is wrong, and the case it was
    # added for is one "before" already settles: it had picked
    # `process_parsed_packet` 75 characters after a citation whose subject,
    # `processor.process`, sat two characters before it. Ranking by raw distance
    # then mis-attributed silently wherever the next subject sat closer than the
    # current one. Measured, when resolving citations through their links made
    # these visible for the first time: it re-pointed `list_captures` and
    # `shutdown_server` at `resolve_in_root`'s definition — both one line
    # further on — and rewrote a CORRECT `dialog_store.rs:43` for
    # `CorrelationReason` to `find_correlated_scored`'s line 1187. A fixer that
    # damages correct citations is worse than the drift it repairs.
    #
    # "After" survives only as a fallback for a citation with nothing usable
    # before it, and even then the next "[`...`](...)" is masked out: that
    # label belongs to its own reference. Masked rather than truncated so
    # distances stay measured against the original text.
    before = text[max(0, start - CONTEXT_CHARS) : start]
    after = LINKED.sub(lambda m: " " * len(m.group(0)), text[end : end + CONTEXT_CHARS])

    def usable(name: str) -> bool:
        return name not in NOT_SYMBOLS and len(name) > 2

    best, best_dist = None, CONTEXT_CHARS + 1
    for m in IDENT.finditer(before):
        dist = len(before) - m.end()
        if usable(m.group(1)) and dist < best_dist:
            best, best_dist = m.group(1), dist
    if best is not None:
        return best
    for m in IDENT.finditer(after):
        if usable(m.group(1)) and m.start() < best_dist:
            best, best_dist = m.group(1), m.start()
    return best


def resolve_symbol(lines: list[str], qualified: str):
    """Which segment of `Type::member` the prose is citing, or `None`.

    The MEMBER is tried first. A sentence that says `HepSender::send` is about
    `send`, and pointing it at `struct HepSender` is a different line with a
    different meaning. Measured on this tree: `HepSender::send` was cited at
    hep.rs:1741 and lives at 2035, but the type is at 1860 — so resolving to
    the type would have swapped one wrong line for another wrong line while
    reporting the citation repaired. The same held for `DialogStore::merge`
    (986, type at 190), `StreamStore::reassociate_all` (1326, type at 294) and
    four others.

    The type is the fallback, for `DialogStore` used on its own and for a
    member this file does not define (an inherent method on a foreign type).
    """
    for cand in dict.fromkeys(reversed(qualified.split("::"))):
        if cand in NOT_SYMBOLS or len(cand) <= 2:
            continue
        if definition_lines(lines, cand):
            return cand
    return None


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


def source_for(page: pathlib.Path, path: str, target: str):
    """The file a citation is actually about, or `None` if it cannot be told.

    The label is not a repo path and was never required to be one. Most of them
    are a bare basename (`dialog_store.rs:595`) or a path relative to `src/`
    (`tui/mod.rs:145`), and resolving the LABEL from the repo root makes both
    of those miss. Measured before this existed: of 296 citations only 158
    resolved, so 138 -- near half the corpus -- were dropped by the `is_file`
    test below and never checked for drift at all. They were not covered
    elsewhere either: `linked_code_targets_exist` skips any `http` target, and
    these are absolute `blob/` URLs.

    The LINK says which file is meant, so it is the fallback. `_repoint`
    already treats the two as one citation -- it rewrites the label's `:NNN`
    and the link's `#LNNN` together -- so reading the file out of the link is
    the same rule this script already applies in the other direction.
    """
    direct = REPO / path
    if direct.is_file():
        return direct

    href = target.split("#", 1)[0].strip()
    if not href:
        return None

    blob = BLOB.match(href)
    if blob:
        cand = REPO / blob.group(1)
        return cand if cand.is_file() else None

    if href.startswith(("http://", "https://")):
        return None  # some other host; nothing to resolve against

    # A relative link, resolved from the page that carries it. Confined to the
    # repo: `../../../etc/passwd` is not a source file, and a gate that reads
    # outside the tree is a gate reading someone else's code.
    cand = (page.parent / href).resolve()
    try:
        cand.relative_to(REPO)
    except ValueError:
        return None
    return cand if cand.is_file() else None


def check(apply: bool) -> int:
    problems, fixed, checked = [], 0, 0

    for md in sorted(REPO.glob("docs/**/*.md")):
        if "superpowers" in str(md):
            continue
        text = md.read_text()
        rel = md.relative_to(REPO)
        # Collected as (start, end, replacement) against the ORIGINAL text and
        # applied right-to-left below, never with `str.replace`.
        #
        # `str.replace` rewrites EVERY occurrence of the matched text, and the
        # matches come from `text` while the edits accumulated in a separate
        # string. So repointing symbol A to line N, then repointing symbol B
        # whose original citation was line N, rewrote A's just-corrected
        # citation as well. On 2026-08-13 that left `security_findings` in
        # docs/design/backlog.md pointing at `capture_status`, and the fixer
        # reported both as repaired.
        edits: list[tuple[int, int, str]] = []

        for m in CITE.finditer(text):
            path, line, target = m.group(1), int(m.group(2)), m.group(3)
            src = source_for(md, path, target)
            if src is None:
                continue  # linked_code_targets_exist owns missing files
            # Name the file that was actually read. When the label is a
            # basename it does not identify the file, and a report that echoes
            # the label sends the reader looking for `file.rs` in the root.
            shown = src.relative_to(REPO).as_posix()
            lines = src.read_text().splitlines()
            qual = symbol_near(text, m.start(), m.end())
            sym = resolve_symbol(lines, qual) if qual else None

            # Out of range is wrong whether or not a symbol is named.
            if line > len(lines):
                where = definition_lines(lines, sym) if sym else []
                if apply and len(where) == 1:
                    edits.append((m.start(), m.end(), _repoint(m.group(0), where[0])))
                    fixed += 1
                else:
                    problems.append(
                        f"{rel}: cites {shown}:{line} but that file has "
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
                edits.append((m.start(), m.end(), _repoint(m.group(0), where[0])))
                fixed += 1
            else:
                problems.append(
                    f"{rel}: cites {shown}:{line} for `{sym}`, which is not "
                    f"within {TOLERANCE} lines of there"
                    + (f" (defined at {where})" if where else " (no unique definition found)")
                )

        if edits:
            # Right-to-left, so an earlier edit cannot shift a later span.
            out = text
            for start, end, replacement in sorted(edits, reverse=True):
                out = out[:start] + replacement + out[end:]
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
