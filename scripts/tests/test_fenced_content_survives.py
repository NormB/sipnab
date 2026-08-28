"""Every markdown transformer must leave fenced content byte-identical.

Three scripts rewrite prose in place -- `rfc-links.py` links RFC citations,
`link-repo-paths.py` links repository paths, `fix-line-anchors.py` repairs line
anchors -- and all three skip fenced blocks, because a markdown link pasted
into a terminal is a syntax error.

Each hand-rolls the same fence tracker: toggle on a line starting with ``` or
~~~. That tracker cannot see fence RUN LENGTH, and `lib_markdown` exists
precisely because of it -- a fence is three or MORE backticks, and only a run
at least as long as the opener closes it. So a four-backtick block that shows a
three-backtick block inside it (the ordinary way to document fenced markdown)
reads as closed at the inner line, and the remainder of the code block is
rewritten as prose.
"""

import pytest

from conftest import load

TRANSFORMERS = ["rfc-links", "link-repo-paths", "fix-line-anchors"]


def convert(stem: str, text: str) -> str:
    """Run one transformer over `text` and return the rewritten document."""
    mod = load(stem)
    if stem == "fix-line-anchors":
        import pathlib

        return mod.convert(pathlib.Path("docs/probe.md"), text)[0]
    return mod.convert(text)[0]


# Bait each transformer actually matches. A shared document would leave two of
# the three untouched, and a fence guard over a document a transformer ignores
# passes without testing anything -- which is what the second test below
# catches.
BAIT = {
    # A SECTION citation, not a bare one: bare citations link once per
    # document, so a fenced copy below an unfenced one is skipped by the rule
    # rather than by the fence, and the guard would pass without testing it.
    "rfc-links": "see RFC 7989 \u00a75 for Session-ID",
    "link-repo-paths": "see `src/output/vcon.rs` for the exporter",
    "fix-line-anchors": (
        "[`src/output/vcon.rs:1290`]"
        "(https://github.com/NormB/sipnab/blob/main/src/output/vcon.rs#L1)"
    ),
}


def nested_document(stem: str) -> str:
    """A four-backtick block showing a three-backtick block, holding bait."""
    return (
        "````markdown\n"
        "How to write a fenced block:\n"
        "```\n"
        f"{BAIT[stem]}\n"
        "```\n"
        f"still inside the outer block: {BAIT[stem]}\n"
        "````\n\nProse below.\n"
    )


@pytest.mark.parametrize("stem", TRANSFORMERS)
def test_a_longer_fence_is_not_closed_by_a_shorter_run_inside_it(stem):
    """Nothing between the ```` markers may change."""
    doc = nested_document(stem)
    out = convert(stem, doc)
    body = doc.split("````")[1]
    assert body in out, (
        f"{stem} rewrote content inside a four-backtick fence -- the inner "
        f"three-backtick line was read as closing it. Fenced text must survive "
        f"byte-for-byte; use lib_markdown.fence_mask rather than a per-line "
        f"toggle.\n\n{out}"
    )


@pytest.mark.parametrize("stem", TRANSFORMERS)
def test_prose_outside_every_fence_is_still_rewritten(stem):
    """The guard above must not be satisfiable by rewriting nothing at all.

    Skipping fences correctly and skipping the whole document look identical
    from the test above, and the bait only works if each transformer actually
    matches it. This is the half that fails if a fix over-corrects, and the
    half that fails if the bait goes stale.
    """
    prose = BAIT[stem] + "\n"
    out = convert(stem, prose)
    assert out != prose, (
        f"{stem} changed nothing outside any fence, so the fence guard proves "
        f"nothing -- it would pass with all rewriting disabled"
    )


# The counter and the loop index are different numbers, and `convert` returns
# the counter. Rewriting these loops to walk a fence mask introduced a loop
# index named `n` into two scripts whose counter was also `n`, so both returned
# a line number as their rewrite count -- a number the callers print and the
# `--apply` paths act on.
COUNTED = {
    "rfc-links": lambda out: out[1] + out[2],  # (text, n_section, n_bare)
    "link-repo-paths": lambda out: out[1],
    "fix-line-anchors": lambda out: out[1],
}


def convert_full(stem: str, text: str):
    """Run a transformer and return its whole result tuple."""
    mod = load(stem)
    if stem == "fix-line-anchors":
        import pathlib

        return mod.convert(pathlib.Path("docs/probe.md"), text)
    return mod.convert(text)


@pytest.mark.parametrize("stem", TRANSFORMERS)
def test_the_reported_count_is_rewrites_made_not_a_line_number(stem):
    """Three baits, padded far apart, must report three."""
    padding = "\n".join(f"Filler line {i} with nothing to rewrite." for i in range(20))
    doc = "\n".join([BAIT[stem], padding, BAIT[stem], padding, BAIT[stem], ""])
    result = convert_full(stem, doc)
    assert COUNTED[stem](result) == 3, (
        f"{stem} rewrote three baits spread across 40+ lines but reported "
        f"{COUNTED[stem](result)} -- a loop index shadowing the counter reports "
        f"the last line touched instead of the work done"
    )


@pytest.mark.parametrize("stem", TRANSFORMERS)
def test_a_citation_only_inside_a_fence_counts_as_no_rewrite(stem):
    """Skipping a fence must also mean not COUNTING it.

    A transformer that leaves fenced text alone but still tallies it reports
    work it did not do, and `--apply` then claims changes to a file it did not
    change.
    """
    doc = f"Prose with nothing to rewrite.\n\n```\n{BAIT[stem]}\n```\n\nMore prose.\n"
    text, *_ = (r := convert_full(stem, doc))[0], None
    assert COUNTED[stem](r) == 0, (
        f"{stem} counted a rewrite for a citation that only appears inside a "
        f"fence"
    )
    assert r[0] == doc, f"{stem} altered a document whose only bait was fenced"


def test_no_script_hand_rolls_fence_detection():
    """`lib_markdown` exists so this logic is written once.

    Four scripts had their own copy; three of them shared one defect and the
    fourth silently truncated what it checked. A fifth copy would reintroduce
    it, so the shape itself is guarded -- a `startswith` against a fence
    marker.

    Matched against the parsed AST, not the file text: the first version of
    this test searched with a regex and fired on a docstring that mentions
    `startswith("```")` while explaining why the code below it does not do
    that. A gate that reads prose is a gate that reports on prose.
    """
    import ast
    import pathlib

    scripts = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in sorted(scripts.glob("*.py")):
        if path.name == "lib_markdown.py":
            continue  # the one place that MAY know what a fence looks like
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "startswith"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value[:3] in ("```", "~~~")
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        "these scripts detect fences by hand instead of using "
        "lib_markdown.fence_mask / fences(), which is how one run-length "
        f"defect came to have four copies: {offenders}"
    )


def test_fence_mask_keeps_a_tilde_block_containing_backticks_whole():
    """A ``` line inside a ~~~ block is content, not a closing marker."""
    import sys, pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from lib_markdown import fence_mask

    doc = "before\n~~~\n```\nstill code\n~~~\nafter\n"
    mask = fence_mask(doc)
    assert mask[1:5] == [True, True, True, True], f"fence body not masked: {mask}"
    assert mask[0] is False and mask[5] is False, f"prose masked as code: {mask}"


def test_fence_mask_runs_an_unclosed_fence_to_the_end_of_the_document():
    """An unclosed fence swallows the rest -- the safe direction to fail."""
    import sys, pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from lib_markdown import fence_mask

    doc = "before\n```\nopened and never closed\nstill inside\n"
    mask = fence_mask(doc)
    assert mask[0] is False, f"prose above the fence masked as code: {mask}"
    assert all(mask[1:]), (
        f"an unclosed fence stopped masking before end of document, so the "
        f"tail would be rewritten as prose: {mask}"
    )


def test_this_files_parametrisation_is_not_empty():
    """Every test above is parametrised over `TRANSFORMERS` and `BAIT`.

    An empty list is not a failure in pytest — it collects zero cases, prints
    nothing, and the run stays green. So the file that guards three
    transformers against silently rewriting nothing could itself silently check
    nothing, which would be a poor joke.

    Named per transformer rather than counted, because a list that still has
    three entries but has lost `link-repo-paths` is the same hole with a
    passing count.
    """
    assert TRANSFORMERS, "TRANSFORMERS is empty — every test in this file collected zero cases"
    for stem in ("rfc-links", "link-repo-paths", "fix-line-anchors"):
        assert stem in TRANSFORMERS, (
            f"{stem} is no longer covered. It rewrites documentation in place, "
            f"and the fence guard is the only thing standing between it and "
            f"code rewritten as prose."
        )
        assert stem in BAIT, (
            f"{stem} has no bait, so its fence guard would pass over a "
            f"document it never touches — the vacuity this file exists to "
            f"refuse"
        )
