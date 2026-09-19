"""The generated backlog status table."""

import pytest
from conftest import load

bs = load("backlog-status")


@pytest.mark.parametrize("line, state", [
    ("- [x] ✅ Diagnosis shows no media (❌)", "done"),
    ("- [ ] Document the 🟡 indicator", "open"),
    ("- [ ] 🟡 I Implement the indicator", "doing"),
    ("- [x] ❌ REJECTED — no operator need", "rejected"),
])
def test_only_the_leading_status_marker_changes_the_state(line, state):
    """Quoted UI icons in the item body do not change its work status."""
    assert bs.classify(line) == state

# The four states docs/design/backlog.md documents: open, in progress (amber
# circle), complete, and rejected (red cross, box ticked so it leaves the open
# list). The emoji are the marker -- a renderer draws no third checkbox.
DOC = """# Backlog

intro text

## P0 — panics

- [x] **A** done
- [x] \u274c **B** REJECTED — the cause was upstream

## PV — interop

- [ ] **C** open
- [ ] \U0001f7e1 I **D** in progress
- [x] **E** done
"""


def test_sections_are_tallied_in_document_order():
    # (section, open, doing, done, rejected)
    assert bs.tally(DOC) == [
        ("P0 — panics", 0, 0, 1, 1),
        ("PV — interop", 1, 1, 1, 0),
    ]


def test_each_state_is_counted_as_itself():
    """A rejected item is not a completed one, and an in-progress item is not
    an open one. Collapsing either hides the two facts the colors carry."""
    rows = bs.tally(DOC)
    assert [r[4] for r in rows] == [1, 0], "the red cross must count as rejected"
    assert [r[2] for r in rows] == [0, 1], "the amber circle must count as doing"


def test_the_generator_does_not_count_its_own_output():
    """The block carries a `## Status` heading. Counting it made the summary
    disagree with itself on the second run: one wrote N sections, the next
    counted N+1 and called the file permanently stale."""
    once = bs.render(bs.tally(DOC))
    doubled = DOC.replace("\n## P0", "\n" + once + "\n## P0", 1)
    assert bs.tally(doubled) == bs.tally(DOC)


def test_rendering_is_stable_so_the_gate_does_not_flap():
    """A gate that compares generated output to itself must get the same bytes
    every run, or it reports drift nobody caused."""
    rows = bs.tally(DOC)
    assert bs.render(rows) == bs.render(rows)


def test_the_totals_match_the_items():
    out = bs.render(bs.tally(DOC))
    assert "**1 open, 1 in progress, 2 done, 1 rejected**" in out


def test_a_section_with_no_items_is_omitted():
    """A heading with nothing under it is structure, not work. A row of zeroes
    invites the reader to wonder what is hiding there."""
    doc = DOC + "\n## Appendix\n\nprose only, no items\n"
    assert "Appendix" not in bs.render(bs.tally(doc))


def test_progress_reads_full_only_when_nothing_is_open():
    # A rejected item is settled, so it fills the bar the way a done one does:
    # the bar answers "how much is still to decide", not "how much shipped".
    rows = [("Done", 0, 0, 4, 0), ("Half", 2, 0, 2, 0), ("None", 4, 0, 0, 0)]
    out = bs.render(rows)
    assert "`##########`" in out and "`..........`" in out


def test_a_rejected_item_fills_the_bar_like_a_done_one():
    rows = [("Settled", 0, 0, 0, 3)]
    assert "`##########`" in bs.render(rows)
