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

# The second rule: a citation says its line TWICE

A citation carries the line number in the visible LABEL and again in the URL's
`#L` fragment, and `_repoint` has always rewritten the two together -- because
they are one citation. Nothing read them back. So when source moved 28 lines
and the LABELS were updated by hand, the ANCHORS stayed where they were: the
drift rule above resolved every label to the right code and reported the tree
clean, while every click landed 28 lines away. It was found by eye.

`check_anchors` is that missing read-back, and it lives here rather than in a
Rust gate for the reason this file already exists: it is the FIXER as well, and
a gate and its fixer must derive from one rule. It is deliberately wider than
the drift rule in three ways, because the drift rule's narrowness is bought
with a symbol lookup that agreement does not need:

  * every label shape, not only `.rs` -- `docs/architecture.md:149-150` and
    the bare `[`:1928`](...)` form used inside tables are 349 of the 781
    citations here, and `CITE` matches none of them;
  * ranges, at BOTH ends -- 228 of them, and comparing only the start
    certifies `:35-40` -> `#L35-L99`;
  * every published page, not only `docs/` -- `website/content/` carries
    citations that no Rust gate opens for this.

The LABEL is authoritative and `--apply` moves the fragment onto it. That is
not a coin toss: the label is what a human wrote, and it is the half the drift
rule above validates against the source, so the two rules cannot pull a
citation in opposite directions.
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from lib_markdown import fence_mask  # noqa: E402

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

# Any line-bearing citation, in every shape these pages use: `.rs` and `.md`
# labels, a bare `[`:1928`](...)`, a single line and a range. Wider than `CITE`
# on purpose -- agreement needs neither the cited file's language nor its
# contents, so the restrictions `CITE` pays for a symbol lookup with are not
# owed here.
ANCHORED = re.compile(r"\[`([^`\n]*?):(\d+)(?:-(\d+))?`\]\(([^)\n]+)\)")
# The `#L` fragment at the END of an href. `-L20` is GitHub's form; `-20` is
# accepted so a half-written one is REPORTED rather than silently read as
# having no range at all.
FRAGMENT = re.compile(r"#L(\d+)(?:-L?(\d+))?$")

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


def choose_definition(where: list[int], cited: int) -> int | None:
    """Which definition a drifted citation meant, or `None` when it cannot tell.

    One candidate is the easy case. Several arise from the cfg-gated pairs this
    codebase uses for optional features -- `#[cfg(feature = "x")] fn f` beside
    `#[cfg(not(feature = "x"))] fn f` -- and the fixer used to refuse them all,
    printing "needs a human" and leaving somebody to guess which half was meant.

    A citation drifts by however far the code around it moved. It does not
    migrate from one definition to another, so the NEAREST candidate is the one
    the author was pointing at.

    Ambiguity is a question of MARGIN, not of distance. Two definitions eighty
    lines apart with the citation beside one of them is not ambiguous however
    stale the number is, while two definitions eight lines apart is, because
    the citation could have been pointing at either and drifted the other way.
    """
    if not where:
        return None
    if len(where) == 1:
        return where[0]
    ranked = sorted(where, key=lambda n: (abs(n - cited), n))
    nearest, runner_up = ranked[0], ranked[1]
    margin = abs(runner_up - cited) - abs(nearest - cited)
    # Twice the tolerance: inside that the citation could have drifted from
    # either candidate, and a confident wrong answer silently re-points a
    # reader at the wrong half of a pair.
    if margin <= TOLERANCE * 2:
        return None
    return nearest


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


def check(apply: bool, pages: list[pathlib.Path] | None = None) -> int:
    """Check `pages`, or every page under `docs/` when none are named.

    Naming pages is what makes the FIXER testable. The gate half is proven by
    the tree itself -- it runs on every commit -- but nothing proved `--apply`
    emits what the gate accepts, and a fixer whose output the gate rejects is
    the unfixable-by-design shape this repo has hit before. A test can now hand
    it one page in a temporary directory, and the source files still resolve
    against this repository, so the fixture cites real code.
    """
    problems, fixed, checked = [], 0, 0

    for md in sorted(REPO.glob("docs/**/*.md")) if pages is None else pages:
        if "superpowers" in str(md):
            continue
        text = md.read_text()
        # A page outside the repository -- a test fixture -- has no path
        # relative to it, and reporting an absolute path is better than
        # refusing to report at all.
        try:
            rel = md.relative_to(REPO)
        except ValueError:
            rel = md
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

            chosen = choose_definition(where, line)
            if apply and chosen is not None:
                edits.append((m.start(), m.end(), _repoint(m.group(0), chosen)))
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


def anchor_pages() -> list[pathlib.Path]:
    """Every page a reader can reach a citation from.

    Wider than `check`'s `docs/**` glob. `docs/` is mirrored into
    `website/content/docs/` and both are published, so a citation that
    desynchronizes on the site is as wrong as one that desynchronizes in the
    repository -- and no Rust gate opens the site copy for this: measured
    2026-08-31, two line citations live under `website/content/` alone.
    README.md is here for the same reason and currently carries none, which is
    the point: a page set chosen by where citations happen to be today is one
    that misses the first one written tomorrow.
    """
    pages = [p for p in sorted(REPO.glob("docs/**/*.md")) if "superpowers" not in str(p)]
    pages += sorted(REPO.glob("website/content/**/*.md"))
    readme = REPO / "README.md"
    if readme.is_file():
        pages.append(readme)
    return pages


def check_anchors(apply: bool, pages: list[pathlib.Path] | None = None) -> int:
    """The label and the `#L` fragment of one citation must name one line."""
    page_list = anchor_pages() if pages is None else pages
    problems: list[str] = []
    fixed = examined = both = fenced = 0

    for md in page_list:
        text = md.read_text()
        try:
            rel = md.relative_to(REPO).as_posix()
        except ValueError:
            rel = str(md)  # a fixture outside the repository

        # `fence_mask`, not a per-line toggle, and not "no masking at all".
        # Documentation about citations has to be able to SHOW a broken one,
        # and a gate that fails on its own worked example gets an exemption
        # comment instead of a fix. Measured 2026-08-31: zero citations in this
        # tree sit inside a fence, so the mask costs no coverage today. The
        # count is reported below, because a mask that swallowed the whole
        # document would otherwise look exactly like a clean document.
        mask = fence_mask(text)
        lines = text.split("\n")
        changed = False

        for i, line in enumerate(lines):
            if i < len(mask) and mask[i]:
                fenced += len(ANCHORED.findall(line))
                continue
            edits: list[tuple[int, int, str]] = []
            for m in ANCHORED.finditer(line):
                examined += 1
                start, end, href = m.group(2), m.group(3), m.group(4)
                frag = FRAGMENT.search(href)
                if frag is None:
                    # A label with no fragment at all is a different failure
                    # with a different fix, and `cited_line_numbers_link_to_
                    # the_line` in tests/doc_link_hygiene_test.rs owns it --
                    # including the `docs/internals/**` exemption it has to
                    # carry, which this rule must not contradict.
                    continue
                both += 1
                label = f":{start}" + (f"-{end}" if end else "")
                want = f"#L{start}" + (f"-L{end}" if end else "")
                have = frag.group(0)
                if have == want:
                    continue
                if apply:
                    at = m.start(4)
                    edits.append((at + frag.start(), at + frag.end(), want))
                    fixed += 1
                else:
                    problems.append(
                        f"{rel}:{i + 1}: the label promises `{label}` and the "
                        f"link lands at `{have}` -- expected `{want}`"
                    )
            if edits:
                # Right-to-left, so an earlier edit cannot shift a later span.
                for lo, hi, replacement in sorted(edits, reverse=True):
                    line = line[:lo] + replacement + line[hi:]
                lines[i] = line
                changed = True

        if changed:
            md.write_text("\n".join(lines))

    if apply:
        print(f"re-anchored {fixed} citation(s)")
    # One machine-readable line, because every number here is load-bearing:
    # `examined=0` is how this scanner goes blind, and `disagreeing=0` reads
    # identically whether it examined 781 citations or none.
    print(
        f"two-part references: pages={len(page_list)} examined={examined} "
        f"both_halves={both} fenced={fenced} disagreeing={len(problems)}"
    )
    for p in problems:
        print(f"  {p}")
    return 1 if problems else 0


def _repoint(cite: str, line: int) -> str:
    """Rewrite both the label's `:NNN` and the link's `#LNNN` together."""
    cite = re.sub(r"(\.rs):\d+`\]", rf"\1:{line}`]", cite)
    cite = re.sub(r"#L\d+(-L\d+)?", f"#L{line}", cite)
    return cite


if __name__ == "__main__":
    named = [pathlib.Path(a) for a in sys.argv[1:] if not a.startswith("-")]
    apply_ = "--apply" in sys.argv
    pages = named or None
    # Both rules always run, and both always report. Short-circuiting on the
    # first failure would hide the second one behind it, and these two fail for
    # unrelated reasons -- a moved symbol against a half-applied edit.
    rc = check(apply=apply_, pages=pages)
    rc |= check_anchors(apply=apply_, pages=pages)
    sys.exit(rc)
