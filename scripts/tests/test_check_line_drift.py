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
