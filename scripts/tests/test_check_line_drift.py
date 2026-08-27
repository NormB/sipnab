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
