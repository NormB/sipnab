#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

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

# The third rule: the cited line exists

Agreement never opened the file both halves name, so `[`mcp.md:1268`](...
#L1268)` passed on a 486-line page: label and fragment agreed on a line that
does not exist. On 2026-11-04 five citations in docs/design/ pointed past the
end of their target, and the drift rule could not see them because `CITE`
reads `.rs` labels only. `check_anchors` now resolves the file the LINK opens
(`link_target`) and refuses any cited line past its end, through
`beyond_eof`, the predicate the drift rule uses too. `--apply` leaves these
alone: the label is the authority, and here the label is what is wrong.

# The fourth rule: the cited line holds what the citation says

A line that exists can still be the wrong line. `process-isolation-and-hot-
path-cost.md` cited `rest-api.md:1117` for a sentence that page no longer had
there, and the three rules above passed it. Measured 2026-11-08: of the 649
line citations under docs/, 573 no longer landed on the lines they held when
they were written. The drift rule could see 172 of them, and its tolerance
let it pass a citation anywhere within 15 lines of the symbol, including a
blank line above `DialogStore::generation`.

So a citation says what its first cited line holds: a PHRASE, in an HTML
comment directly after the link, `[`docs/x.md:12`](...#L12)<!-- "text that
begins on line 12" -->`. `check_anchors` requires the phrase to begin on that
line (`phrase_starts`, whitespace-normalized, so it may wrap), and `--apply`
moves label and fragment together to the one line it begins on when there is
exactly one. A citation of a file this checker can read, on `main`, without a
phrase is counted as `unanchored`, and the tree-wide test holds that count at
zero. A link pinned to a commit is not read: it shows that commit's file,
which does not move.

# The fifth rule: a line link that no rule reads names a commit

Every rule above reads a CITATION: a link whose label is `file:line`, to this
repository on `main`. A line link in any other shape, `[the parser](...
/blob/main/src/sip/parser.rs#L10)`, a bare URL, a link to a branch of another
project, was read by nothing and could drift with every commit there.
`unpinned_line_links` finds them: a GitHub link with an `#L` fragment must be
a citation of `main` here, or name a commit by its full hash, or, for another
project, a version tag. `--apply` does not rewrite one: it cannot know which
commit the author read.
"""

import bisect
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from lib_markdown import fence_mask  # noqa: E402
from lib_tracked import ls_files  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent


def tracked(pattern: str) -> list[pathlib.Path]:
    """Markdown git TRACKS under REPO matching `pattern`, sorted.

    Never a filesystem glob. docs/design/backlog.local.md is gitignored and
    exists on one machine only; globbing picked up its 40 line citations, so
    this checker reported 212 where CI -- which has no such file -- reported
    172, and a pre-commit run passed over a verdict CI then refused. A gate
    reads what is committed.

    Each page once: git lists an unmerged path once per stage, and a page read
    three times reported each stale citation three times.
    """
    return sorted(REPO / rel for rel in ls_files(REPO, "--", f":(glob){pattern}"))

# [`src/foo.rs:123`](url#L123) -- the link is captured because the label alone
# does not say which file is meant. See `source_for`.
CITE = re.compile(r"\[`([A-Za-z0-9_./-]+\.rs):(\d+)`\]\(([^)]*)\)")
# https://github.com/NormB/sipnab/blob/main/the/path.rs -- THIS repository on
# `main`, the only ref the working tree stands for. It used to accept any
# owner and any ref, so a kamailio link to `src/modules/x.c` would have been
# read from sipnab's own `src/modules/x.c` had one existed, and a link pinned
# to a commit would be measured against today's file instead of that commit's.
# GitHub matches owner and repository names without regard to case.
BLOB = re.compile(
    r"https?://(?:www\.)?github\.com/NormB/sipnab/blob/main/(.+)$", re.IGNORECASE
)
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
# What a citation says its first cited line holds: an HTML comment directly
# after the link, `[`docs/rest-api.md:1117`](...#L1117)<!-- "it is not a
# separate OS process" -->`. A comment and not a link title, because a title
# sits inside the link's parentheses, which every link parser in this
# repository reads as the target. It renders as nothing.
PHRASE = re.compile(r'<!-- "(.*?)" -->')
# A link pinned to one commit of this repository by its full hash. Counted,
# not resolved: it shows that commit's file, which does not move.
PINNED = re.compile(
    r"https?://(?:www\.)?github\.com/NormB/sipnab/blob/[0-9a-f]{40}/", re.IGNORECASE
)
# Any link to a line of a file on GitHub: owner, repository and ref captured.
LINE_LINK = re.compile(
    r"https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s]+)/blob/([^/\s]+)/"
    r"[^\s()<>\[\]\"']*?#L\d+(?:-L?\d+)?",
    re.IGNORECASE,
)
FULL_HASH = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
VERSION_TAG = re.compile(r"v?\d+(?:\.\d+)+")


def unpinned_line_links(line: str) -> list[str]:
    """The line links on `line` that no rule reads and that can move.

    A link to a line is fixed when it names a commit by its full hash, or, in
    another project, a version tag. A link to this repository on `main` is
    read by the citation rules when it is a citation (`ANCHORED`). Every other
    one is returned: a link with a prose label or a bare link to `main`, a branch, a
    short hash, a tag of this repository.
    """
    cited = [m.span() for m in ANCHORED.finditer(line)]
    found = []
    for m in LINE_LINK.finditer(line):
        owner, repo, ref = m.group(1).lower(), m.group(2).lower(), m.group(3)
        ours = (owner, repo) == ("normb", "sipnab")
        if FULL_HASH.fullmatch(ref):
            continue
        if not ours and VERSION_TAG.fullmatch(ref):
            continue
        in_citation = any(a <= m.start() and m.end() <= b for a, b in cited)
        if ours and ref == "main" and in_citation:
            continue
        found.append(m.group(0))
    return found

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
    #
    # A citation's phrase comment is REMOVED on both sides before the window
    # is measured. It quotes code, and code is full of backticked names: read
    # as prose, the `parse_body` quoted for one citation became the subject of
    # the next. Blanking it to spaces instead kept its length in the window,
    # so adding phrases pushed subjects out of range and `checked` fell from
    # 172 to 171. The slack keeps the removal off the whole page.
    slack = CONTEXT_CHARS + 4096
    before = PHRASE.sub("", text[max(0, start - slack) : start])[-CONTEXT_CHARS:]
    after = PHRASE.sub("", text[end : end + slack])[:CONTEXT_CHARS]
    after = LINKED.sub(lambda m: " " * len(m.group(0)), after)

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
    #
    # A member too common to look up (`new`, `default`) is not a reason to
    # cite the type instead: `BatchRunner::new` resolved to `struct
    # BatchRunner`, 876 lines from the constructor the sentence is about.
    # Such a citation is left to its phrase.
    parts = qualified.split("::")
    if parts[-1] in NOT_SYMBOLS:
        return None
    for cand in dict.fromkeys(reversed(parts)):
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
    # An absolute link that is not this repository's `main` -- a commit pin,
    # another ref, another project -- shows a file this tree does not hold,
    # so the label must not be read against today's file either.
    target_file = link_target(page, target)
    if target_file is None and target.strip().startswith(("http://", "https://")):
        return None
    direct = REPO / path
    if direct.is_file():
        return direct
    return target_file


def link_target(page: pathlib.Path, target: str):
    """The repository file a link's href lands on, or `None`.

    The CLICK's file, from the href alone. `source_for` falls back to it when
    the label names no file; `check_anchors` asks it directly, because the line
    a reader lands on is in the file the link opens, whatever the label says.
    """
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


def beyond_eof(length: int, *cited: int | None) -> int | None:
    """The first cited line a `length`-line file does not have, or `None`.

    The one past-the-end rule, shared by both scans. `check` applied it to
    `.rs` citations only, through `CITE`; `check_anchors` compared a label
    with its own fragment and never opened the file, so
    [`mcp.md:1268`](...#L1268) passed on a 486-line page because both halves
    agreed on a line that does not exist. `None` entries are the absent end
    of a single-line citation.
    """
    for n in cited:
        if n is not None and n > length:
            return n
    return None


def drift_subject(page: pathlib.Path, text: str, m: re.Match):
    """What the drift rule checks a `CITE` match against, or `None`.

    `(file, its lines, symbol)`, where the symbol is `None` when the prose
    names none the file can resolve.
    """
    src = source_for(page, m.group(1), m.group(3))
    if src is None:
        return None
    lines = src.read_text().splitlines()
    qual = symbol_near(text, m.start(), m.end())
    return src, lines, (resolve_symbol(lines, qual) if qual else None)


def normalize(text: str) -> str:
    """`text` with every run of whitespace made one space, and stripped."""
    return " ".join(text.split())


def phrase_starts(lines: list[str], phrase: str) -> list[int]:
    """The 1-based lines on which an occurrence of `phrase` begins.

    Read over the file's text with whitespace normalized and its non-blank
    lines joined by one space, so a phrase may wrap onto the next line and
    indentation does not matter. The one predicate behind the content rule:
    the gate asks whether the first cited line is among these, and the fixer
    re-points a citation when there is exactly one.
    """
    want = normalize(phrase)
    if not want:
        return []
    starts: list[int] = []  # offset in `joined` where each kept line begins
    numbers: list[int] = []
    parts: list[str] = []
    at = 0
    for n, raw in enumerate(lines, 1):
        flat = normalize(raw)
        if not flat:
            continue
        starts.append(at)
        numbers.append(n)
        parts.append(flat)
        at += len(flat) + 1
    joined = " ".join(parts)
    found: list[int] = []
    i = joined.find(want)
    while i != -1:
        n = numbers[bisect.bisect_right(starts, i) - 1]
        if not found or found[-1] != n:
            found.append(n)
        i = joined.find(want, i + 1)
    return found


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

    for md in tracked("docs/**/*.md") if pages is None else pages:
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
            line = int(m.group(2))
            subject = drift_subject(md, text, m)
            if subject is None:
                continue  # linked_code_targets_exist owns missing files
            src, lines, sym = subject
            # Name the file that was actually read. When the label is a
            # basename it does not identify the file, and a report that echoes
            # the label sends the reader looking for `file.rs` in the root.
            shown = src.relative_to(REPO).as_posix()

            # Out of range is wrong whether or not a symbol is named.
            if beyond_eof(len(lines), line) is not None:
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
    pages = tracked("docs/**/*.md")
    pages += tracked("website/content/**/*.md")
    readme = REPO / "README.md"
    if readme.is_file():
        pages.append(readme)
    return pages


def check_anchors(apply: bool, pages: list[pathlib.Path] | None = None) -> int:
    """The label and the `#L` fragment of one citation must name one line.

    And the line must exist, and, when the citation carries a phrase, hold it.
    """
    page_list = anchor_pages() if pages is None else pages
    problems: list[str] = []
    unanchored: list[str] = []
    fixed = examined = both = fenced = resolved = past_eof = disagreeing = 0
    phrased = wrong_content = pinned = unpinned = 0
    files: dict[pathlib.Path, list[str]] = {}

    def lines_of(path: pathlib.Path) -> list[str]:
        if path not in files:
            files[path] = path.read_text().splitlines()
        return files[path]

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
            for url in unpinned_line_links(line):
                unpinned += 1
                problems.append(
                    f"{rel}:{i + 1}: {url} links to a line and no rule reads it: it "
                    "follows a branch, a tag or a short hash. Write it as a citation "
                    "of main ([`path:line`](...#Lline) with its phrase), or name a "
                    "commit by its full hash"
                )
            edits: list[tuple[int, int, str]] = []
            for m in ANCHORED.finditer(line):
                examined += 1
                start, end, href = m.group(2), m.group(3), m.group(4)
                # The cited line must EXIST, in the file the click opens.
                # Agreement alone passed `mcp.md:1268` -> `#L1268` on a
                # 486-line page. Checked before the fragment: a label with no
                # fragment still promises a line.
                target = link_target(md, href)
                said = PHRASE.match(line, m.end())
                if target is None and PINNED.match(href):
                    pinned += 1
                if target is not None:
                    resolved += 1
                    shown = target.relative_to(REPO).as_posix()
                    body = lines_of(target)
                    first, last = int(start), int(end) if end else None
                    # The content rule. The phrase names what the first cited
                    # line holds, so it is the one half of a citation that
                    # survives the code moving: the fixer re-points the label
                    # and the fragment to the one line it begins on.
                    if said is not None:
                        phrased += 1
                        phrase = normalize(said.group(1))
                        if not phrase:
                            wrong_content += 1
                            problems.append(
                                f"{rel}:{i + 1}: the phrase after {shown}:{start} is "
                                "empty, and an empty phrase occurs on every line"
                            )
                            continue
                        if "|" in phrase:
                            wrong_content += 1
                            problems.append(
                                f"{rel}:{i + 1}: the phrase after {shown}:{start} "
                                "holds `|`, which splits a table row before the "
                                "comment is read; quote another part of the line"
                            )
                            continue
                        at = phrase_starts(body, phrase)
                        if first not in at:
                            if apply and len(at) == 1:
                                moved = at[0] - first
                                edits.append((m.start(), m.end(), _repoint_range(
                                    m.group(0), at[0],
                                    last + moved if last is not None else None,
                                )))
                                fixed += 1
                                continue
                            wrong_content += 1
                            problems.append(
                                f'{rel}:{i + 1}: cites {shown}:{start} for "{phrase}", '
                                "which does not begin on that line"
                                + (f" (it begins on line {at})" if at else
                                   " (it is nowhere in the file)")
                            )
                    else:
                        # Coverage, not a verdict: nothing says what this
                        # citation is about, so no rule here can tell when it
                        # lands on the wrong content. Counted and named, and
                        # the tree-wide test holds the count at zero. A Rust
                        # symbol in the prose is not enough: the drift rule
                        # accepts any line within TOLERANCE of it, and passed
                        # `DialogStore::generation` cited at a blank line 15
                        # lines above its definition.
                        unanchored.append(
                            f"{rel}:{i + 1}: {shown}:{start} carries no phrase; "
                            + (f'line {first} reads "{normalize(body[first - 1])[:80]}"'
                               if first <= len(body) else "that line does not exist")
                        )
                    # Never fixed by `--apply` without a phrase: the label is
                    # the authority below, and here it is the label that is
                    # wrong, so only a human knows what was meant.
                    over = beyond_eof(len(body), first, last)
                    if over is not None:
                        past_eof += 1
                        problems.append(
                            f"{rel}:{i + 1}: cites {shown}:{over} but that "
                            f"file has {len(body)} lines"
                        )
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
                    disagreeing += 1
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
            files.pop(md, None)  # another page may cite this one

    if apply:
        print(f"re-anchored {fixed} citation(s)")
    # One machine-readable line, because every number here is load-bearing:
    # `examined=0` is how this scanner goes blind, and `disagreeing=0` reads
    # identically whether it examined 781 citations or none. `resolved` is the
    # same guard for `past_eof`: a resolver that stopped resolving would
    # report `past_eof=0` exactly like a clean tree; `pinned` counts the links
    # it does not resolve on purpose, so `resolved + pinned` must account for
    # every examined citation. `phrased` is that guard
    # for `wrong_content`, and `unanchored` is how many citations no rule can
    # check for content at all. `unpinned` is the line links no rule reads
    # because they are not citations of `main` and name no commit.
    print(
        f"two-part references: pages={len(page_list)} examined={examined} "
        f"both_halves={both} fenced={fenced} "
        f"disagreeing={disagreeing} resolved={resolved} "
        f"past_eof={past_eof} pinned={pinned} phrased={phrased} "
        f"wrong_content={wrong_content} unanchored={len(unanchored)} "
        f"unpinned={unpinned}"
    )
    for p in problems:
        print(f"  {p}")
    if unanchored:
        print("unanchored citations (add <!-- \"...\" --> quoting the first cited line):")
        for u in unanchored:
            print(f"  {u}")
    return 1 if problems else 0


def _repoint_range(cite: str, start: int, end: int | None) -> str:
    """Move a citation of any label shape to `start` (through `end`).

    The label's trailing `:N` or `:N-M` and the `#L` fragment are rewritten
    together, because they are one citation. A citation with no fragment keeps
    having none: adding one is `cited_line_numbers_link_to_the_line`'s call.
    """
    span = f"{start}" + (f"-{end}" if end is not None else "")
    frag = f"#L{start}" + (f"-L{end}" if end is not None else "")
    cite = re.sub(r":\d+(?:-\d+)?`\]", f":{span}`]", cite, count=1)
    return re.sub(r"#L\d+(?:-L?\d+)?(?=\)$)", frag, cite, count=1)


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
