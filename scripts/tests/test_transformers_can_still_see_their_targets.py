"""A doc transformer that matches nothing reports the same success as one with
nothing to do.

`rfc-links.py`, `link-repo-paths.py` and `fix-line-anchors.py` each scan the
documentation for a pattern and rewrite what they find. Run on a clean tree
they print `WOULD LINK 0 paths across 0 files` and exit 0 -- which is exactly
what they print when their regex has stopped matching anything at all.

The two states are indistinguishable from the outside, and only one of them is
healthy. A `SPAN` regex that no longer recognizes a repository path does not
fail; it quietly stops linking, every new path in every new page ships as bare
text, and the gate that would have caught it (`repo_paths_in_docs_are_clickable`)
is checking output nobody produces.

So these do not assert that the transformers have work to do. They assert that
each one can still SEE the thing it exists to act on, by applying its own
compiled pattern to the real documentation corpus and requiring a floor of
matches. The floors are deliberately far below today's counts: this is a gate
against a pattern that broke, not a ratchet on how much prose exists.
"""

import pathlib
import re

import pytest

from conftest import load

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def docs_corpus() -> str:
    """Every published markdown page, concatenated."""
    parts = []
    for sub in ("docs",):
        for p in sorted((ROOT / sub).rglob("*.md")):
            parts.append(p.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


CORPUS = docs_corpus()


def test_the_corpus_this_gate_reads_is_not_empty():
    """Anti-vacuity for the anti-vacuity gates below.

    Every test in this file counts matches in `CORPUS`. An empty corpus makes
    all of them pass by finding nothing to disagree with, which is the failure
    mode the file is about.
    """
    assert len(CORPUS) > 200_000, (
        f"the documentation corpus read {len(CORPUS)} characters, which is far "
        f"too small -- the walk broke, and every floor below is being checked "
        f"against nothing"
    )


def test_the_rfc_citation_patterns_still_match_the_documentation():
    """`rfc-links.py` links RFC citations; a rotted pattern links none."""
    mod = load("rfc-links")
    section = len(mod.SECTION.findall(CORPUS))
    bare = len(mod.BARE.findall(CORPUS))
    assert section + bare >= 50, (
        f"rfc-links matched {section} section citations and {bare} bare ones "
        f"across the docs. This tree cites RFCs hundreds of times, so a total "
        f"this low means SECTION or BARE stopped matching -- and the script "
        f"would report `WOULD LINK 0` exactly as it does on a clean tree"
    )


def test_the_repo_path_pattern_still_matches_the_documentation():
    """`link-repo-paths.py` reports `0 paths across 0 files` either way."""
    mod = load("link-repo-paths")
    hits = len(mod.SPAN.findall(CORPUS))
    assert hits >= 20, (
        f"link-repo-paths' SPAN regex matched {hits} backtick-wrapped repo "
        f"paths. The docs are full of them, so this means the pattern broke: "
        f"the script then links nothing, and every path in a new page ships as "
        f"text a reader has to retype"
    )


def test_the_line_citation_pattern_still_matches_the_documentation():
    """`fix-line-anchors.py` repairs `[`path:123`](url)` citations."""
    mod = load("fix-line-anchors")
    hits = len(mod.LINK.findall(CORPUS))
    assert hits >= 20, (
        f"fix-line-anchors' LINK regex matched {hits} line citations. The "
        f"design docs carry many, so a count this low means the pattern "
        f"stopped recognizing them and drifted anchors go unrepaired"
    )


@pytest.mark.parametrize(
    "stem,needle,floor",
    [
        ("rfc-links", "citation", 1),
        ("link-repo-paths", "path", 1),
        ("fix-line-anchors", "line citation", 1),
    ],
)
def test_each_transformer_still_reports_what_it_scanned(stem, needle, floor):
    """A transformer must say what it looked at, not only what it changed.

    `WOULD FIX 0 line citations across 0 of 95 files scanned` is readable: the
    trailing count proves the walk happened. `WOULD LINK 0 paths across 0
    files` is not -- it cannot be told from a walk that found no files at all.
    This requires the reporting line to exist at minimum, so a future rewrite
    cannot drop the only evidence that the scan ran.
    """
    src = (ROOT / "scripts" / f"{stem}.py").read_text(encoding="utf-8")
    assert needle in src, (
        f"{stem}.py no longer mentions {needle!r} in its output, so its "
        f"summary line changed shape and this gate is reading the wrong thing"
    )
    assert re.search(r"print\(", src), f"{stem}.py reports nothing at all"
