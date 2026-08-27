"""The generated backlog status table."""

import pytest
from conftest import load

bs = load("backlog-status")

DOC = """# Backlog

intro text

## P0 — panics

- [x] **A** done
- [x] **B** done

## PV — interop

- [ ] **C** open
- [ ] **D** open
- [x] **E** done
"""


def test_sections_are_tallied_in_document_order():
    assert bs.tally(DOC) == [("P0 — panics", 0, 2), ("PV — interop", 2, 1)]


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
    assert "**2 open, 3 done**" in out


def test_a_section_with_no_items_is_omitted():
    """A heading with nothing under it is structure, not work. A row of zeroes
    invites the reader to wonder what is hiding there."""
    doc = DOC + "\n## Appendix\n\nprose only, no items\n"
    assert "Appendix" not in bs.render(bs.tally(doc))


def test_progress_reads_full_only_when_nothing_is_open():
    rows = [("Done", 0, 4), ("Half", 2, 2), ("None", 4, 0)]
    out = bs.render(rows)
    assert "`##########`" in out and "`..........`" in out
