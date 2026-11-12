# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The citation fixer, and the case that defeated it three times in one day.

A symbol with two cfg-gated definitions -- the `#[cfg(feature = "x")]` /
`#[cfg(not(feature = "x"))]` pair this codebase uses for optional features --
produced two definition lines, and the fixer only ever re-pointed when there
was exactly one. It printed "N need a human" and the human then guessed which
definition the citation meant, three times, getting it wrong twice.
"""

import pytest
from conftest import load

drift = load("check-line-drift")


# ── which lines count as a definition ────────────────────────────────

def test_a_struct_outranks_its_impl_blocks():
    """A type has one definition and any number of impl blocks. Citing an impl
    is also unstable: adding a second one changes which line "the definition"
    means."""
    src = [
        "pub struct Widget {",
        "}",
        "impl Widget {",
        "}",
        "impl Default for Widget {",
    ]
    assert drift.definition_lines(src, "Widget") == [1]


def test_a_cfg_gated_pair_yields_both_definitions():
    """The shape this codebase uses for an optional feature. Both are real
    definitions and the fixer has to cope with two."""
    src = [
        '#[cfg(feature = "vcon")]',
        "fn export_vcon(",
        ") -> bool {",
        "}",
        '#[cfg(not(feature = "vcon"))]',
        "fn export_vcon(",
    ]
    assert drift.definition_lines(src, "export_vcon") == [2, 6]


def test_a_mention_is_not_a_definition():
    """Prose beside a citation is not its subject. A gate that flags `to_vec`
    gets skimmed exactly like one that flags every flag name."""
    src = ["    let x = widget.to_vec();", "    // Widget is nice"]
    assert drift.definition_lines(src, "Widget") == []


# ── choosing between several definitions ─────────────────────────────

def test_one_definition_is_chosen_without_argument():
    assert drift.choose_definition([42], cited=40) == 42


def test_no_definition_chooses_nothing():
    assert drift.choose_definition([], cited=40) is None


def test_the_nearest_definition_wins_when_they_are_far_apart():
    """A citation drifts by a few lines as code moves around it. It does not
    migrate from one definition to another, so the nearer one is the one the
    author meant -- which is what a human picked by hand, three times."""
    assert drift.choose_definition([5042, 5132], cited=5001) == 5042
    assert drift.choose_definition([5042, 5132], cited=5120) == 5132


def test_two_definitions_at_the_same_distance_are_left_to_a_human():
    """Equidistant is genuinely undecidable, and guessing would silently
    re-point a citation at the wrong half of a cfg pair."""
    assert drift.choose_definition([100, 200], cited=150) is None


def test_definitions_too_close_together_are_left_to_a_human():
    """When the margin is inside the tolerance the fixer cannot tell which one
    the citation was already pointing at, and a confident wrong answer is worse
    than an honest refusal."""
    assert drift.choose_definition([100, 108], cited=103) is None


def test_a_far_cited_line_still_resolves_when_one_is_clearly_nearer():
    """Drift can be large after a big refactor. Distance alone does not make
    the choice ambiguous -- the MARGIN between candidates does."""
    assert drift.choose_definition([200, 4000], cited=900) == 200


# ── the citation text itself ─────────────────────────────────────────

def test_repointing_updates_both_the_label_and_the_link():
    """A citation carries the line twice: in the visible label and in the URL
    fragment. Updating one leaves a link that disagrees with its own text."""
    cite = ("[`src/app/batch.rs:5001`]"
            "(https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L5001)")
    out = drift._repoint(cite, 5042)
    assert "batch.rs:5042" in out
    assert "#L5042" in out
    assert "5001" not in out


# ── the two halves of one citation must name one line ────────────────

BLOB = "https://github.com/NormB/sipnab/blob/main"


def page(tmp_path, body):
    p = tmp_path / "page.md"
    p.write_text(body)
    return p


def run_anchors(pages, apply=False):
    """`check_anchors` over named pages, returning (rc, printed lines)."""
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = drift.check_anchors(apply, pages=list(pages))
    return rc, buf.getvalue()


def test_the_fragment_regex_reads_both_range_spellings():
    """`#L10-L20` is GitHub's form. `#L10-20` is a half-written one, and it has
    to be READ as a range so it can be reported -- treating it as "no range"
    would let it pass beside a `:10-20` label."""
    assert drift.FRAGMENT.search("...#L10").groups() == ("10", None)
    assert drift.FRAGMENT.search("...#L10-L20").groups() == ("10", "20")
    assert drift.FRAGMENT.search("...#L10-20").groups() == ("10", "20")


def test_the_citation_regex_reads_the_shapes_the_drift_rule_cannot():
    """`CITE` needs a `.rs` label and a single line because it resolves a Rust
    symbol. Agreement needs neither, and 349 of this tree's 781 citations are
    one of the shapes below."""
    for text, groups in [
        ("[`src/cli.rs:12`](x#L12)", ("src/cli.rs", "12", None)),
        ("[`docs/architecture.md:149-150`](x#L149-L150)",
         ("docs/architecture.md", "149", "150")),
        ("[`:1928`](x#L1928)", ("", "1928", None)),
    ]:
        m = drift.ANCHORED.search(text)
        assert m.group(1, 2, 3) == groups


def test_a_stale_fragment_beside_a_fresh_label_is_reported(tmp_path):
    """The defect: source moved 28 lines, the labels were updated by hand and
    the fragments were not. The drift rule resolved every label to the right
    code and passed."""
    p = page(tmp_path, f"See [`src/mcp/server.rs:5278`]({BLOB}/src/mcp/server.rs#L5250).\n")
    rc, out = run_anchors([p])
    assert rc == 1
    assert "5278" in out and "5250" in out
    assert "disagreeing=1" in out


def test_a_range_is_compared_at_both_ends(tmp_path):
    """Comparing only the first number certifies `:38-40` -> `#L38-L99`."""
    ok = page(tmp_path, f"[`src/capture/device.rs:38-40`]({BLOB}/src/capture/device.rs#L38-L40)\n")
    assert run_anchors([ok])[0] == 0

    bad = tmp_path / "bad.md"
    bad.write_text(f"[`src/capture/device.rs:38-40`]({BLOB}/src/capture/device.rs#L38-L99)\n")
    rc, out = run_anchors([bad])
    assert rc == 1
    assert "#L38-L40" in out          # names the fragment the label asks for


def test_applying_moves_the_fragment_and_leaves_the_label_alone(tmp_path):
    """The label is the half a human wrote and the half the drift rule
    validates against the source. Rewriting it instead would silently change
    what the page claims."""
    p = page(tmp_path, f"[`src/mcp/server.rs:5278`]({BLOB}/src/mcp/server.rs#L5250)\n")
    rc, out = run_anchors([p], apply=True)
    assert "re-anchored 1 citation(s)" in out
    assert p.read_text().strip().endswith("#L5278)")
    assert "server.rs:5278`" in p.read_text()
    assert run_anchors([p])[0] == 0   # what the fixer wrote, the gate accepts


def test_a_fenced_example_is_skipped_and_counted(tmp_path):
    """Documentation about citations has to be able to SHOW a broken one. The
    skip is COUNTED, because a mask that swallowed the document would otherwise
    read as a clean document."""
    cite = f"[`src/mcp/server.rs:5278`]({BLOB}/src/mcp/server.rs#L5250)"
    p = page(tmp_path, f"Never write this:\n\n```markdown\n{cite}\n```\n")
    rc, out = run_anchors([p])
    assert rc == 0
    assert "fenced=1" in out and "examined=0" in out


def test_the_same_citation_in_prose_is_still_caught(tmp_path):
    """The paired half: the fence mask must not be a way through the gate."""
    cite = f"[`src/mcp/server.rs:5278`]({BLOB}/src/mcp/server.rs#L5250)"
    p = page(tmp_path, f"Written for real: {cite}\n")
    assert run_anchors([p])[0] == 1


def test_the_page_set_reaches_past_the_docs_tree(tmp_path):
    """`docs/` is mirrored into `website/content/docs/` and both are published,
    so a citation that desynchronizes on the site is as wrong as one that
    desynchronizes in the repository."""
    pages = [p.as_posix() for p in drift.anchor_pages()]
    assert any(p.startswith(str(drift.REPO / "docs")) for p in pages)
    assert any("/website/content/" in p for p in pages)
    assert any(p.endswith("/README.md") for p in pages)


# ── the two the recurring cost demanded ──────────────────────────────
#
# Two tests owed for a citation that broke and needed hand-fixing three times
# in one session. The ambiguity itself is covered above; what was not is how an
# operator LEARNS the fixer will not resolve it, and whether re-running is
# worth anything.


def test_apply_reports_how_many_it_could_not_fix():
    """The line an operator reads to know re-running is futile.

    `--apply` prints `re-pointed N citation(s); M need a human`. When M is
    non-zero the fixer has done everything it can and the rest is a manual
    edit; without that number the only signal is the gate failing again, which
    reads identically to "the fixer did not run".

    Driven directly, because nothing else in this file reads the string and a
    report nobody drives is a report that rots into silence.
    """
    src = "check-line-drift"
    body = (drift.__file__ and open(drift.__file__, encoding="utf-8").read()) or ""
    assert "need a human" in body, (
        f"{src} no longer prints how many citations it declined; an operator's "
        "only remaining signal is the gate failing again"
    )
    assert "re-pointed" in body, f"{src} no longer reports what it DID fix"


def test_applying_twice_changes_nothing_the_second_time(tmp_path):
    """A fixer that keeps editing fights its gate forever.

    Its sibling `link-repo-paths.py` has had this test since it was written;
    this one did not, and it is the fixer that gets re-run most — every time
    a source file shifts, which is every release.
    """
    page_path = page(
        tmp_path,
        f"See [`src/capture/device.rs:38-40`]({BLOB}/src/capture/device.rs#L38-L99).\n",
    )
    before_gate = run_anchors([page_path])[0]
    assert before_gate == 1, "the fixture must start out of agreement"

    run_anchors([page_path], apply=True)
    once = page_path.read_text(encoding="utf-8")

    run_anchors([page_path], apply=True)
    twice = page_path.read_text(encoding="utf-8")

    assert once == twice, "a second run of the fixer changed the page again"
    assert run_anchors([page_path])[0] == 0, (
        "what the fixer leaves behind must satisfy the gate that demands it, "
        "or the instruction to run it is a loop with no exit"
    )


# ── which pages it reads ────────────────────────────────

def _repo_with(tmp_path, tracked: dict, untracked: dict):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for rel, body in {**tracked, **untracked}.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    subprocess.run(["git", "-C", str(tmp_path), "add", *tracked], check=True)
    return tmp_path


def test_an_untracked_page_under_docs_is_not_read(tmp_path, monkeypatch):
    """The gate must read what is COMMITTED, not whatever happens to be on disk.

    It globbed docs/**/*.md, so the gitignored local backlog -- 40 line
    citations that exist on one machine only -- counted locally and not in CI.
    The pre-commit hook said 212 and passed; CI said 172 and turned main red on
    2026-09-17, over a verdict the local run could not have reproduced.
    """
    root = _repo_with(
        tmp_path,
        tracked={"docs/public.md": "see `src/main.rs:1`\n"},
        untracked={"docs/design/backlog.local.md": "see `src/main.rs:2`\n"},
    )
    monkeypatch.setattr(drift, "REPO", root)
    names = sorted(p.relative_to(root).as_posix() for p in drift.anchor_pages())
    assert names == ["docs/public.md"]


# ── a cited line must exist ────────────────────────────────
#
# The agreement rule compares a citation's label with its own `#L` fragment and
# never opens the file both of them name. So `[`mcp.md:1268`](...#L1268)`
# passed on a 486-line page: both halves said 1268, and line 1268 does not
# exist. Five citations in docs/design/ pointed past the end of their target on
# 2026-11-04, and every gate here reported the tree clean.


def _eof_repo(tmp_path, monkeypatch, lines=3):
    """A repository root holding `docs/target.md` of exactly `lines` lines."""
    (tmp_path / "docs").mkdir()
    target = tmp_path / "docs" / "target.md"
    target.write_text("".join(f"line {n}\n" for n in range(1, lines + 1)))
    monkeypatch.setattr(drift, "REPO", tmp_path)
    return tmp_path


def _eof_page(root, body):
    p = root / "docs" / "page.md"
    p.write_text(body)
    return p


def test_a_citation_past_the_end_of_its_file_is_reported(tmp_path, monkeypatch):
    """Both halves agree on line 4 of a 3-line file: the defect as found."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(root, f"See [`docs/target.md:4`]({BLOB}/docs/target.md#L4).\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "past_eof=1" in out, out
    assert "docs/target.md:4" in out and "3 lines" in out, out


def test_the_last_line_of_a_file_is_not_past_its_end(tmp_path, monkeypatch):
    """The boundary, from the other side: line 3 of 3 exists."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(root, f"See [`docs/target.md:3`]({BLOB}/docs/target.md#L3).\n")
    rc, out = run_anchors([p])
    assert rc == 0, out
    assert "past_eof=0" in out and "resolved=1" in out, out


def test_a_range_whose_end_is_past_the_file_is_reported(tmp_path, monkeypatch):
    """A range that starts inside the file and ends outside it is as wrong as
    one that starts outside, and comparing only the start would pass it."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(root, f"See [`docs/target.md:2-4`]({BLOB}/docs/target.md#L2-L4).\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "past_eof=1" in out, out


def test_a_bare_label_with_a_relative_link_is_resolved_through_the_link(tmp_path, monkeypatch):
    """`[`:9`](target.md#L9)` names no file in its label. The link does, relative
    to the page carrying it."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(root, "See [`:9`](target.md#L9).\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "past_eof=1" in out and "resolved=1" in out, out


def test_a_citation_without_a_fragment_is_still_checked_against_its_file(tmp_path, monkeypatch):
    """The missing fragment belongs to `cited_line_numbers_link_to_the_line`;
    the label still promises a line, and that line must exist."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(root, f"See [`docs/target.md:9`]({BLOB}/docs/target.md).\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "past_eof=1" in out, out


def test_a_target_that_cannot_be_resolved_is_neither_counted_nor_reported(tmp_path, monkeypatch):
    """A missing file is `linked_code_targets_exist`'s failure, and another host
    is nothing this repository can measure. Neither is counted as resolved, so
    `resolved` cannot be inflated by citations nobody opened."""
    root = _eof_repo(tmp_path, monkeypatch)
    p = _eof_page(
        root,
        f"[`docs/gone.md:9`]({BLOB}/docs/gone.md#L9) and "
        "[`x.md:9`](https://example.com/x.md#L9)\n",
    )
    rc, out = run_anchors([p])
    assert rc == 0, out
    assert "resolved=0" in out and "past_eof=0" in out, out


def test_applying_leaves_a_citation_past_the_end_for_a_human(tmp_path, monkeypatch):
    """No number the fixer could write is right: the label is the authority for
    the agreement rule, and here the label itself is wrong. It must not be
    rewritten, and the gate must still fail after `--apply`."""
    root = _eof_repo(tmp_path, monkeypatch)
    body = f"See [`docs/target.md:4`]({BLOB}/docs/target.md#L4).\n"
    p = _eof_page(root, body)
    rc, out = run_anchors([p], apply=True)
    assert p.read_text() == body
    assert rc == 1 and "past_eof=1" in out, out


def test_the_predicate_reads_every_cited_line_against_the_length():
    """The one rule both scans share, driven directly at its boundary."""
    assert drift.beyond_eof(3, 3) is None
    assert drift.beyond_eof(3, 4) == 4
    assert drift.beyond_eof(3, 2, 4) == 4
    assert drift.beyond_eof(3, 2, None) is None
    assert drift.beyond_eof(0, 1) == 1


# ── a quoted phrase says what the cited line holds ───────────────────
#
# Agreement and past-the-end both pass a citation that lands on the wrong
# content inside its file: `process-isolation-and-hot-path-cost.md` cited
# `rest-api.md:1117` for a sentence that page no longer has at that line, and
# every rule here reported it clean. Measured 2026-11-08: of the 649 line
# citations under docs/, 573 no longer landed on the lines they held when the
# citation was written, and the drift rule could check 172 of them, the ones
# whose prose names a Rust symbol defined in the cited file. A phrase in an
# HTML comment directly after the link, `<!-- "..." -->`, is the subject for
# the rest: the gate requires it to begin on the first cited line.


def _phrase_repo(tmp_path, monkeypatch, body):
    """A repository root holding `docs/target.md` with the lines in `body`."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "target.md").write_text(body)
    monkeypatch.setattr(drift, "REPO", tmp_path)
    return tmp_path


TARGET = (
    "# Title\n"                                   # 1
    "\n"                                          # 2
    "The API runs in the same process.\n"         # 3
    "Treat the bind address\n"                    # 4
    "    and the key   accordingly.\n"            # 5
    "Unrelated closing line.\n"                   # 6
)


def _cite(spec, phrase=None, frag=None):
    """`[`docs/target.md:SPEC`](BLOB/docs/target.md#L...)` plus an optional phrase."""
    start, _, end = spec.partition("-")
    frag = frag or (f"#L{start}" + (f"-L{end}" if end else ""))
    out = f"[`docs/target.md:{spec}`]({BLOB}/docs/target.md{frag})"
    return out + (f'<!-- "{phrase}" -->' if phrase is not None else "")


def _summary(out):
    line = next(l for l in out.splitlines() if l.startswith("two-part references:"))
    return dict(tok.split("=") for tok in line.split()[2:])


def test_a_phrase_on_its_cited_line_passes(tmp_path, monkeypatch):
    """SUCCESS: the phrase is the first thing on the cited line."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('3', 'The API runs in the same process.')}\n")
    rc, out = run_anchors([p])
    assert rc == 0, out
    s = _summary(out)
    assert (s["phrased"], s["wrong_content"], s["unanchored"]) == ("1", "0", "0"), out


def test_a_phrase_that_moved_to_another_line_is_reported(tmp_path, monkeypatch):
    """FAILURE: the defect as found. The line exists, both halves agree, and
    the content the sentence quotes is two lines further on."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('1', 'The API runs in the same process.')}\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert _summary(out)["wrong_content"] == "1", out
    assert "docs/target.md:1" in out and "line [3]" in out, out


def test_a_phrase_the_file_no_longer_holds_is_reported(tmp_path, monkeypatch):
    """FAILURE: the quoted content was rewritten away, so no line holds it."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('3', 'it is not a separate OS process')}\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "nowhere in the file" in out, out


def test_a_phrase_may_wrap_onto_the_next_line(tmp_path, monkeypatch):
    """EDGE: a sentence wraps. The phrase begins on line 4 and ends on line 5,
    across an indent and a run of spaces that normalize to one."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('4', 'bind address and the key accordingly')}\n")
    rc, out = run_anchors([p])
    assert rc == 0, out
    assert _summary(out)["phrased"] == "1", out


def test_a_phrase_must_begin_on_the_first_cited_line(tmp_path, monkeypatch):
    """EDGE: `:5` with a phrase that starts on line 4. Accepting an occurrence
    that merely OVERLAPS the cited line would let a citation one line early
    pass, and the fixer could not tell which line was meant."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('5', 'bind address and the key')}\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert "line [4]" in out, out


def test_a_phrase_inside_a_range_but_not_at_its_start_is_reported(tmp_path, monkeypatch):
    """EDGE: the phrase anchors the FIRST cited line, so the fixer can move a
    range without guessing where inside it the phrase used to sit."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    ok = _eof_page(root, f"See {_cite('3-5', 'The API runs')}\n")
    assert run_anchors([ok])[0] == 0
    bad = _eof_page(root, f"See {_cite('3-5', 'Treat the bind address')}\n")
    assert run_anchors([bad])[0] == 1


def test_applying_re_points_a_moved_phrase_at_both_halves(tmp_path, monkeypatch):
    """SUCCESS for the fixer: one occurrence, so the label and the fragment
    move to it together, and the gate accepts what it wrote."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('1', 'Unrelated closing line.')}\n")
    rc, out = run_anchors([p], apply=True)
    assert p.read_text() == f"See {_cite('6', 'Unrelated closing line.')}\n", out
    assert run_anchors([p])[0] == 0
    once = p.read_text()
    run_anchors([p], apply=True)
    assert p.read_text() == once, "a second --apply changed the page again"


def test_applying_moves_a_range_and_keeps_its_length(tmp_path, monkeypatch):
    """A range moves as a block: `:1-3` whose phrase is now on line 3 becomes
    `:3-5`, both in the label and in the fragment."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('1-3', 'The API runs')}\n")
    run_anchors([p], apply=True)
    assert p.read_text() == f"See {_cite('3-5', 'The API runs')}\n"


def test_applying_leaves_an_ambiguous_phrase_for_a_human(tmp_path, monkeypatch):
    """FAILURE for the fixer: two lines hold the phrase, and choosing one
    would be a guess presented as a repair."""
    root = _phrase_repo(tmp_path, monkeypatch, "same text\nother\nsame text\n")
    body = f"See {_cite('2', 'same text')}\n"
    p = _eof_page(root, body)
    rc, out = run_anchors([p], apply=True)
    assert p.read_text() == body
    assert rc == 1 and "line [1, 3]" in out, out


def test_applying_re_points_a_citation_past_the_end_when_its_phrase_is_found(tmp_path, monkeypatch):
    """EDGE: without a phrase a past-the-end citation is left alone, because
    only the label says what was meant and the label is what is wrong. A
    phrase says what was meant, so the fixer can act on it."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('60', 'Treat the bind')}\n")
    rc, out = run_anchors([p], apply=True)
    assert p.read_text() == f"See {_cite('4', 'Treat the bind')}\n", out
    rc, out = run_anchors([p])
    assert rc == 0 and _summary(out)["past_eof"] == "0", out


def test_a_phrase_with_a_table_separator_is_refused(tmp_path, monkeypatch):
    """FAILURE: GitHub splits a table row on `|` before it parses the comment,
    so a phrase holding one breaks the table it sits in."""
    root = _phrase_repo(tmp_path, monkeypatch, "a | b\n")
    p = _eof_page(root, f"See {_cite('1', 'a | b')}\n")
    rc, out = run_anchors([p])
    assert rc == 1 and "`|`" in out, out


def test_an_empty_phrase_is_refused(tmp_path, monkeypatch):
    """EDGE: whitespace normalizes to nothing, and an empty string occurs on
    every line, so it would pass any citation."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('3', '   ')}\n")
    rc, out = run_anchors([p])
    assert rc == 1 and "empty" in out, out


def test_a_citation_with_neither_phrase_nor_symbol_is_counted_unanchored(tmp_path, monkeypatch):
    """FAILURE for coverage: nothing says what this citation is about, so no
    rule can tell when it lands on the wrong content. It is counted and named;
    the tree-wide test holds the count at zero."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"See {_cite('3')}\n")
    rc, out = run_anchors([p])
    assert _summary(out)["unanchored"] == "1", out
    assert "unanchored" in out and "docs/page.md:1" in out and "The API runs" in out, out


def test_a_rust_citation_that_names_its_symbol_still_needs_a_phrase(tmp_path, monkeypatch):
    """FAILURE for coverage: the drift rule accepts a cited line anywhere within
    15 lines of the symbol, so it passed `DialogStore::generation` cited at a
    blank line 15 lines above its definition. A named symbol is not a phrase."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "api.rs").write_text("// x\npub fn serve() {}\n")
    monkeypatch.setattr(drift, "REPO", tmp_path)
    p = tmp_path / "page.md"
    p.write_text(f"`serve` ([`src/api.rs:1`]({BLOB}/src/api.rs#L1)).\n\n"
                 f'`serve` ([`src/api.rs:2`]({BLOB}/src/api.rs#L2)<!-- "pub fn serve" -->).\n')
    rc, out = run_anchors([p])
    assert _summary(out)["unanchored"] == "1", out
    assert "api.rs:1 carries no phrase" in out, out


def test_a_citation_of_another_host_is_not_unanchored(tmp_path, monkeypatch):
    """EDGE: nothing here can open another project's file, so a phrase could
    not be checked and is not asked for."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, "[`x.c:9`](https://github.com/OpenSIPS/opensips/blob/"
                        "5fa4e627187f23544e702db0a47dbe877a407117/docs/target.md#L9)\n")
    rc, out = run_anchors([p])
    assert rc == 0 and _summary(out)["unanchored"] == "0", out


def test_a_fenced_phrase_citation_is_not_checked(tmp_path, monkeypatch):
    """EDGE: an example of a broken phrase inside a fence is documentation."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"```markdown\n{_cite('1', 'nowhere at all')}\n```\n")
    rc, out = run_anchors([p])
    assert rc == 0 and _summary(out)["phrased"] == "0", out


def test_phrase_starts_reads_normalized_text_across_lines():
    """The predicate both the gate and the fixer use, driven directly."""
    lines = ["  alpha  beta", "", "gamma", "alpha beta"]
    assert drift.phrase_starts(lines, "alpha beta") == [1, 4]
    assert drift.phrase_starts(lines, "beta gamma") == [1]   # across a blank line
    assert drift.phrase_starts(lines, "gamma alpha") == [3]
    assert drift.phrase_starts(lines, "delta") == []


def test_repointing_a_range_rewrites_every_label_shape():
    """The shapes `_repoint` never handled: a bare label, a non-Rust range and
    a citation without a fragment."""
    assert drift._repoint_range("[`:12`](x#L12)", 40, None) == "[`:40`](x#L40)"
    assert (drift._repoint_range("[`docs/a.md:1-3`](x#L1-L3)", 7, 9)
            == "[`docs/a.md:7-9`](x#L7-L9)")
    assert drift._repoint_range("[`docs/a.md:1`](x)", 5, None) == "[`docs/a.md:5`](x)"


def test_an_identifier_inside_a_phrase_is_not_the_next_citations_subject():
    """A phrase quotes code, and code is full of backticked names. Read as
    prose, the `parse_body` quoted for the first citation would become the
    subject of the second, and the drift rule would check the wrong symbol."""
    first = '[`:1`](a.rs#L1)<!-- "fn `parse_body`(x)" -->'
    text = f"`serve` at {first} and [`:9`](a.rs#L9)"
    start = text.index("[`:9`")
    end = text.index(")", start) + 1
    assert drift.symbol_near(text, start, end) == "serve"


# ── which repository a link opens ────────────────────────────────────


def test_a_link_to_another_project_is_not_read_from_this_tree(tmp_path, monkeypatch):
    """FAILURE before the fix: `BLOB` accepted any owner, so a kamailio link
    to `src/modules/x.c` was checked against sipnab's `src/modules/x.c`
    whenever this tree happened to hold one."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    page_ = root / "docs" / "page.md"
    href = "https://github.com/kamailio/kamailio/blob/24cbec17f/docs/target.md#L3"
    assert drift.link_target(page_, href) is None
    # The same project on ITS `main`, so only the owner tells the two apart.
    href = "https://github.com/kamailio/kamailio/blob/main/docs/target.md#L3"
    assert drift.link_target(page_, href) is None


def test_a_link_to_this_project_on_main_is_read_from_this_tree(tmp_path, monkeypatch):
    """SUCCESS: the neighbor, which must keep resolving, whatever the case of
    the owner (GitHub matches owner and repository names without case)."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    page_ = root / "docs" / "page.md"
    want = root / "docs" / "target.md"
    assert drift.link_target(page_, f"{BLOB}/docs/target.md#L3") == want
    assert drift.link_target(page_, "https://github.com/normb/Sipnab/blob/main/docs/target.md") == want


def test_a_link_pinned_to_a_commit_is_not_read_from_the_working_tree(tmp_path, monkeypatch):
    """EDGE: a pinned link shows the file as of that commit, so the working
    tree's line count and content say nothing about where it lands."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    page_ = root / "docs" / "page.md"
    href = "https://github.com/NormB/sipnab/blob/1bb055303a519bb7/docs/target.md#L3"
    assert drift.link_target(page_, href) is None


# ── an unmerged page is one page ─────────────────────────────────────


def _git(root, *args):
    import subprocess
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c",
                    "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True)


def _conflicted(tmp_path, base: bool):
    """A repository mid-merge with `docs/x.md` unmerged and `docs/y.md` clean.

    With `base`, both sides edited a file both had (index stages 1, 2 and 3);
    without, both sides added it (stages 2 and 3 only).
    """
    import subprocess
    subprocess.run(["git", "init", "-q", "-b", "trunk", str(tmp_path)], check=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "y.md").write_text("y\n")
    if base:
        (tmp_path / "docs" / "x.md").write_text("base\n")
    _git(tmp_path, "add", "docs")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "checkout", "-qb", "side")
    (tmp_path / "docs" / "x.md").write_text("side\n")
    _git(tmp_path, "add", "docs")
    _git(tmp_path, "commit", "-qm", "side")
    _git(tmp_path, "checkout", "-q", "trunk")
    (tmp_path / "docs" / "x.md").write_text("trunk\n")
    _git(tmp_path, "add", "docs")
    _git(tmp_path, "commit", "-qm", "trunk")
    r = subprocess.run(["git", "-C", str(tmp_path), "-c", "commit.gpgsign=false",
                        "merge", "side"], capture_output=True)
    assert r.returncode != 0, "the fixture must leave a conflict"
    return tmp_path


def test_an_unmerged_page_is_read_once(tmp_path, monkeypatch):
    """FAILURE before the fix: `git ls-files` prints an unmerged path once per
    index stage, so during a rebase conflict the gate read one page three
    times and reported `checked 180` against the tree's 172."""
    root = _conflicted(tmp_path, base=True)
    monkeypatch.setattr(drift, "REPO", root)
    names = [p.relative_to(root).as_posix() for p in drift.tracked("docs/**/*.md")]
    assert names == ["docs/x.md", "docs/y.md"]


def test_a_page_added_on_both_sides_is_read_once(tmp_path, monkeypatch):
    """EDGE: an add/add conflict has two stages, not three."""
    root = _conflicted(tmp_path, base=False)
    monkeypatch.setattr(drift, "REPO", root)
    names = [p.relative_to(root).as_posix() for p in drift.tracked("docs/**/*.md")]
    assert names == ["docs/x.md", "docs/y.md"]


def test_clean_pages_are_each_read_once(tmp_path, monkeypatch):
    """SUCCESS: the neighbor without a conflict, which deduplication must not
    change: every tracked page, once, in order."""
    root = _repo_with(tmp_path, tracked={"docs/b.md": "b\n", "docs/a.md": "a\n"}, untracked={})
    monkeypatch.setattr(drift, "REPO", root)
    names = [p.relative_to(root).as_posix() for p in drift.tracked("docs/**/*.md")]
    assert names == ["docs/a.md", "docs/b.md"]


def test_a_phrase_does_not_use_up_the_context_window():
    """EDGE: the subject sits 60 characters before its citation, inside the
    90-character window, with a long phrase comment between them. Blanked to
    spaces, the comment still counted toward the window and pushed `serve`
    out of it, so adding phrases to a page dropped a citation from `checked`
    (172 to 171 on 2026-11-08). A phrase is not prose and takes no room."""
    long_phrase = '<!-- "' + "x" * 80 + '" -->'
    text = f"`serve` is the entry point, see [`:1`](a.rs#L1){long_phrase} and [`:9`](a.rs#L9)"
    start = text.index("[`:9`")
    end = text.index(")", start) + 1
    assert drift.symbol_near(text, start, end) == "serve"


def _run_check(pages):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = drift.check(False, pages=list(pages))
    return rc, buf.getvalue()


def test_the_drift_rule_does_not_read_a_pinned_citation_from_the_working_tree(tmp_path, monkeypatch):
    """FAILURE before the fix: `source_for` tried the LABEL before the link, so
    a citation pinned to a commit, `src/api.rs:99` on a 2-line file today, was
    measured against today's file and reported past its end. Line 99 is the
    line at that commit."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "api.rs").write_text("// x\npub fn serve() {}\n")
    monkeypatch.setattr(drift, "REPO", tmp_path)
    p = tmp_path / "page.md"
    p.write_text("`serve` ([`src/api.rs:99`](https://github.com/NormB/sipnab/blob/"
                 "1bb055303a519bb7b012f0c7ba4608f38644fb54/src/api.rs#L99))\n")
    rc, out = _run_check([p])
    assert rc == 0, out
    assert "checked 0 citation(s)" in out, out


def test_the_drift_rule_still_reads_a_main_citation_by_its_label(tmp_path, monkeypatch):
    """SUCCESS: the neighbor. The same citation on `main` is read from today's
    file, and line 99 of a 2-line file is reported."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "api.rs").write_text("// x\npub fn serve() {}\n")
    monkeypatch.setattr(drift, "REPO", tmp_path)
    p = tmp_path / "page.md"
    p.write_text(f"`serve` ([`src/api.rs:99`]({BLOB}/src/api.rs#L99))\n")
    rc, out = _run_check([p])
    assert rc == 1 and "2 lines" in out, out


def test_a_constructor_is_not_resolved_to_its_type():
    """FAILURE before the fix: `new` is too common to look up, so
    `BatchRunner::new` fell back to `struct BatchRunner` and the drift rule
    demanded a citation of the constructor sit within 15 lines of the struct,
    876 lines away in batch.rs. A sentence about `Type::new` is not about the
    type, which is the substitution `resolve_symbol` exists to refuse."""
    lines = ["pub struct BatchRunner {", "}", "impl BatchRunner {", "    pub fn new() -> Self {"]
    assert drift.resolve_symbol(lines, "BatchRunner::new") is None


def test_a_type_named_alone_still_resolves():
    """SUCCESS: the neighbor. `BatchRunner` on its own is the type."""
    lines = ["pub struct BatchRunner {", "}"]
    assert drift.resolve_symbol(lines, "BatchRunner") == "BatchRunner"


def test_a_member_this_file_does_not_define_falls_back_to_its_type():
    """EDGE: an inherent method on a foreign type is not defined here, and the
    type is still the right fallback; only an unreadable member is refused."""
    lines = ["pub struct Store {", "}"]
    assert drift.resolve_symbol(lines, "Store::merge") == "Store"


def test_a_pinned_citation_is_counted_as_pinned_not_lost(tmp_path, monkeypatch):
    """A pinned link is deliberately not resolved, so `resolved` falls with
    every pin. `pinned` counts them, so `resolved + pinned` still accounts for
    every examined citation and a resolver that stopped resolving shows up as
    a gap rather than as more pins. A short or foreign hash is neither."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    sha = "1bb055303a519bb7b012f0c7ba4608f38644fb54"
    p = _eof_page(root,
                  f"[`docs/target.md:3`](https://github.com/NormB/sipnab/blob/{sha}/docs/target.md#L3) "
                  "[`docs/target.md:3`](https://github.com/NormB/sipnab/blob/1bb0553/docs/target.md#L3) "
                  f"[`x.c:3`](https://github.com/kamailio/kamailio/blob/{sha}/x.c#L3)\n")
    rc, out = run_anchors([p])
    s = _summary(out)
    assert (s["examined"], s["resolved"], s["pinned"]) == ("3", "0", "1"), out


# ── a line link that nothing checks must not move (DOC-LINE-LINKS) ────
#
# The rules above read a citation: a link whose label is `file:line`, on
# `main`. A line link in any other shape was read by nothing, so it could point
# at a branch and drift with every commit. Such a link has to name a commit.

SHA = "0123456789abcdef0123456789abcdef01234567"


def test_unpinned_finds_a_main_link_with_a_prose_label():
    """FAILURE before the rule: no label line, so no rule read it."""
    line = f"See [the parser]({BLOB}/src/sip/parser.rs#L10) for the loop."
    assert drift.unpinned_line_links(line) == [f"{BLOB}/src/sip/parser.rs#L10"]


def test_unpinned_finds_a_bare_url_and_a_range():
    line = f"<{BLOB}/src/a.rs#L10-L12> and {BLOB}/src/b.rs#L7."
    assert drift.unpinned_line_links(line) == [
        f"{BLOB}/src/a.rs#L10-L12",
        f"{BLOB}/src/b.rs#L7",
    ]


def test_unpinned_finds_a_backticked_label_that_names_no_line():
    line = f"[`parser.rs`]({BLOB}/src/sip/parser.rs#L10)"
    assert drift.unpinned_line_links(line) == [f"{BLOB}/src/sip/parser.rs#L10"]


def test_unpinned_finds_another_branch_of_this_repository():
    url = "https://github.com/NormB/sipnab/blob/develop/src/a.rs#L3"
    assert drift.unpinned_line_links(f"[here]({url})") == [url]


def test_unpinned_finds_a_short_hash():
    """A short hash can become ambiguous; only the full one is a pin."""
    url = "https://github.com/NormB/sipnab/blob/1bb0553/src/a.rs#L3"
    assert drift.unpinned_line_links(f"[here]({url})") == [url]


def test_unpinned_finds_another_project_on_a_branch():
    url = "https://github.com/kamailio/kamailio/blob/master/src/x.c#L480-L495"
    assert drift.unpinned_line_links(f"[`x.c`]({url})") == [url]


def test_unpinned_finds_a_citation_of_another_branch_of_this_repository():
    """Citation-shaped, but the rules read `main` only."""
    url = "https://github.com/NormB/sipnab/blob/develop/src/a.rs#L3"
    assert drift.unpinned_line_links(f"[`src/a.rs:3`]({url})") == [url]


def test_unpinned_finds_a_citation_of_another_projects_main():
    """Citation-shaped and on `main`, but of a tree this checker cannot read."""
    url = "https://github.com/kamailio/kamailio/blob/main/src/x.c#L480"
    assert drift.unpinned_line_links(f"[`x.c:480`]({url})") == [url]


def test_unpinned_finds_a_tag_of_this_repository():
    """This repository's own lines are cited on `main` or by commit: a tag here
    would be a third form with no rule reading it."""
    url = "https://github.com/NormB/sipnab/blob/v0.5.246/src/a.rs#L3"
    assert drift.unpinned_line_links(f"[here]({url})") == [url]


def test_a_citation_on_main_is_not_unpinned():
    """SUCCESS: the citation rules read it, so it may follow `main`."""
    line = f"[`src/a.rs:10`]({BLOB}/src/a.rs#L10) and [`:12-14`]({BLOB}/src/a.rs#L12-L14)"
    assert drift.unpinned_line_links(line) == []


def test_a_link_pinned_to_a_full_hash_is_not_unpinned():
    line = (
        f"[the parser](https://github.com/NormB/sipnab/blob/{SHA}/src/a.rs#L10) "
        f"[`x.c`](https://github.com/kamailio/kamailio/blob/{SHA}/src/x.c#L480-L495)"
    )
    assert drift.unpinned_line_links(line) == []


def test_another_project_at_a_version_tag_is_not_unpinned():
    line = "[`sofia.c`](https://github.com/signalwire/freeswitch/blob/v1.11.3/src/sofia.c#L5395)"
    assert drift.unpinned_line_links(line) == []


def test_a_link_without_a_line_is_not_unpinned():
    line = f"[`src/a.rs`]({BLOB}/src/a.rs) and [docs]({BLOB}/docs/x.md#heading)"
    assert drift.unpinned_line_links(line) == []


def test_a_citation_and_an_unpinned_link_on_one_line_are_told_apart():
    line = f"[`src/a.rs:10`]({BLOB}/src/a.rs#L10), then [more]({BLOB}/src/a.rs#L10)"
    assert drift.unpinned_line_links(line) == [f"{BLOB}/src/a.rs#L10"]


def test_the_gate_reports_an_unpinned_link_with_its_page_and_line(tmp_path, monkeypatch):
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"intro\n\nSee [the page]({BLOB}/docs/target.md#L3).\n")
    rc, out = run_anchors([p])
    assert rc == 1, out
    assert _summary(out)["unpinned"] == "1", out
    assert "docs/page.md:3" in out and "docs/target.md#L3" in out, out
    assert "name a commit" in out, out


def test_the_gate_passes_a_page_whose_line_links_are_all_read_or_pinned(tmp_path, monkeypatch):
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(
        root,
        f"See {_cite('3', 'The API runs in the same process.')} and "
        f"[then](https://github.com/NormB/sipnab/blob/{SHA}/docs/target.md#L3).\n",
    )
    rc, out = run_anchors([p])
    assert rc == 0, out
    assert _summary(out)["unpinned"] == "0", out


def test_the_gate_does_not_read_an_unpinned_link_inside_a_fence(tmp_path, monkeypatch):
    """Documentation about line links has to be able to show a wrong one."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    p = _eof_page(root, f"```\n[bad]({BLOB}/docs/target.md#L3)\n```\n")
    rc, out = run_anchors([p])
    assert rc == 0, out
    assert _summary(out)["unpinned"] == "0", out


def test_applying_does_not_rewrite_an_unpinned_link(tmp_path, monkeypatch):
    """The fixer cannot know which commit the author read; it reports."""
    root = _phrase_repo(tmp_path, monkeypatch, TARGET)
    body = f"See [the page]({BLOB}/docs/target.md#L3).\n"
    p = _eof_page(root, body)
    rc, out = run_anchors([p], apply=True)
    assert rc == 1, out
    assert p.read_text() == body
