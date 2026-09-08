"""The RFC linker: a citation a reader has to retype into a search box.

Written as four tests owed for a gate that turned red during 0.5.159. Its
sibling `link-repo-paths.py` has had an agreement test and an idempotence test
since it was written; this fixer had neither, so nothing in the tree said its
output satisfies the gate that demands it -- which is the shape of a gate that
can never be made green.
"""

import subprocess
import pathlib

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent


def run(*args, cwd=REPO):
    return subprocess.run(
        ["python3", str(SCRIPTS / "rfc-links.py"), *args],
        capture_output=True, text=True, timeout=180, cwd=cwd,
    )


def test_the_tree_is_currently_clean():
    """The gate and the fixer must agree.

    `rfc_section_citations_are_linked` tells a reader to run this script. If
    what the script leaves behind does not satisfy that test, the instruction
    is a loop with no exit, and the person following it has no way to know.
    """
    assert run().returncode == 0, run().stdout[-400:]


def test_the_fixer_is_idempotent():
    """A second run must change nothing.

    A fixer that keeps editing fights its gate forever, and the symptom is a
    commit that will not go through however many times the fix is applied.
    Measured as the tree state around a second run rather than by reading the
    fixer's own report, which is the thing under test.
    """
    def tree():
        return subprocess.run(["git", "status", "--porcelain"],
                              capture_output=True, text=True, cwd=REPO).stdout

    assert run("--apply").returncode == 0
    before = tree()
    assert run("--apply").returncode == 0
    assert tree() == before, "a second run of the fixer changed the tree"


def test_it_reports_what_it_did():
    """Silence from a fixer cannot be told apart from a fixer that never ran.

    This one prints its counts even when both are zero, which is what makes
    "I ran it and nothing happened" a distinguishable outcome.
    """
    out = run("--apply").stdout
    assert out.strip(), "the fixer printed nothing at all"
    assert "section citations" in out, out


def convert():
    """The fixer's pure rewrite, imported rather than driven through the CLI.

    The script derives its root from its own location, deliberately -- it once
    carried an absolute path that existed on one machine, matched nothing
    everywhere else, and reported success. That makes it unpointable at a
    fixture tree, so the rule is driven where it lives instead.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "rfc_links", SCRIPTS / "rfc-links.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.convert


def test_a_section_citation_is_linked_and_a_repeated_bare_rfc_is_not():
    """The rule has two halves and only one of them is unconditional.

    A SECTION citation -- written with the section sign, which is the form
    this tree uses -- is what a reader chases, so every one is linked. A bare
    `RFC N` is linked on first mention only, because one page in this tree
    cites RFC 3261 248 times and linking every instance would bury the page in
    identical links. Driving both halves from one document is what keeps this
    from passing on a fixer that links everything, or nothing.
    """
    out, sections, bare = convert()(
        "# Sample\n\n"
        "The transport rules are in RFC 3261, and RFC 3261 says so again.\n\n"
        "Header names are case-insensitive per RFC 3261 \u00a77.3.1.\n"
    )

    assert sections == 1, out
    assert "https://www.rfc-editor.org/rfc/rfc3261#section-7.3.1" in out, out

    assert bare == 1, (
        "a bare RFC is linked on first mention only; a page citing one RFC "
        "248 times must not gain 248 identical links:\n" + out
    )
    assert out.count("(https://www.rfc-editor.org/rfc/rfc3261)") == 1, out
    # The repeat stays as plain text, which is the half that makes the rule a
    # rule rather than "link everything".
    assert "and RFC 3261 says so again" in out, out


def test_an_already_linked_citation_is_left_alone():
    """The fixer must not link a link.

    This is the property idempotence rests on: a second run sees the output of
    the first, and a rewriter that cannot recognize its own work produces
    `[[RFC 3261](...)](...)` and fights its gate forever.
    """
    linked = (
        "See [RFC 3261 \u00a77.3.1](https://www.rfc-editor.org/rfc/rfc3261"
        "#section-7.3.1) for the rule.\n"
    )
    out, sections, bare = convert()(linked)
    assert (out, sections, bare) == (linked, 0, 0), out
