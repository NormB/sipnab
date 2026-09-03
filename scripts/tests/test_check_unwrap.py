"""The production-panic ban, and the exception marker it accepts.

`check-unwrap.py` banned `.unwrap()` and `.expect()` on production paths and
nothing else. A clippy restriction-lint measurement found zero of either under
`src/`, and six `panic!`/`unreachable!` sites the gate had never looked at.
Those macros end the process exactly as an unwrap does, and a scanner that
covers one spelling of "abort here" and not the others is a gate with a hole
the width of a keyword.

A site that genuinely cannot be reached stays, but only with a comment naming
the macro and saying WHY -- `// gate: <macro> because <reason>` -- on the same
line or in the comment block directly above it. The reason is load-bearing: a
marker that gives none is a waiver nobody explained, and the scanner reports
it rather than honoring it. Every rule below is driven through the script as a
subprocess, in a throwaway workspace, because the script runs at import.
"""

import pathlib
import subprocess
import sys

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "check-unwrap.py"

# The reason in every accepted marker below. Three words is the floor the
# scanner enforces; this one clears it so the tests are about the SITE and
# not about the reason's length.
REASON = "the early return above handles that arm"


def scan(tmp_path, body, audio="pub fn audio() -> u8 { 1 }"):
    """Run the scanner over a two-member workspace whose `src/lib.rs` is `body`.

    Returns `(exit status, stdout, stderr)`. The second member exists because
    the scanner refuses to run against fewer than two source roots -- its own
    guard against a walk that covers less than the workspace.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "crates" / "sipnab-audio" / "src").mkdir(parents=True)
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = [".", "crates/sipnab-audio"]\n'
    )
    (tmp_path / "src" / "lib.rs").write_text(body + "\n")
    (tmp_path / "crates" / "sipnab-audio" / "src" / "lib.rs").write_text(audio + "\n")
    done = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, done.stdout.strip(), done.stderr


def violations(stderr):
    """The `  src/lib.rs:N:` report lines, as line numbers."""
    out = []
    for line in stderr.splitlines():
        if line.startswith("  src/lib.rs:"):
            out.append(int(line.split(":")[1]))
    return out


# ── the four macros are violations on a production path ──────────────


@pytest.mark.parametrize("macro", ["panic", "unreachable", "todo", "unimplemented"])
def test_a_bare_abort_macro_in_production_is_reported(tmp_path, macro):
    rc, _, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        "        0 => 1,\n"
        f"        _ => {macro}!(),\n"
        "    }\n"
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [4], err


def test_a_qualified_panic_is_still_a_panic(tmp_path):
    """`core::panic!` and `std::panic!` are the same macro with a path on it."""
    rc, _, err = scan(tmp_path, 'pub fn prod() { core::panic!("no") }')
    assert rc == 1, err
    assert violations(err) == [1], err


def test_a_macro_that_merely_ends_in_the_name_is_not_one(tmp_path):
    """`my_panic!` is somebody's macro, not the standard one, and matching it
    would push an author toward renaming rather than toward the rule."""
    rc, out, err = scan(
        tmp_path,
        "macro_rules! my_panic { ($e:expr) => { $e }; }\n"
        "pub fn prod() -> u8 { my_panic!(1) }",
    )
    assert (rc, out) == (0, "0"), err


def test_the_unwrap_rule_survives_the_widening(tmp_path):
    """The control: the older half of the rule still fires."""
    rc, _, err = scan(tmp_path, 'pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }')
    assert rc == 1, err
    assert violations(err) == [1], err


# ── the exception marker, and what it refuses ────────────────────────


def test_a_reasoned_marker_above_the_site_exempts_it(tmp_path):
    rc, out, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        "        0 => 1,\n"
        f"        // gate: unreachable because {REASON}\n"
        "        _ => unreachable!(),\n"
        "    }\n"
        "}",
    )
    assert (rc, out) == (0, "0"), err


def test_a_trailing_marker_on_the_same_line_exempts_it(tmp_path):
    rc, out, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        "        0 => 1,\n"
        f"        _ => unreachable!(), // gate: unreachable because {REASON}\n"
        "    }\n"
        "}",
    )
    assert (rc, out) == (0, "0"), err


def test_a_marker_reaches_past_an_attribute_line(tmp_path):
    """Comments go above attributes in Rust, so a marker written the natural
    way has a `#[cfg(...)]` between it and the macro it covers."""
    rc, out, err = scan(
        tmp_path,
        "pub fn prod() {\n"
        f"    // gate: unreachable because {REASON}\n"
        '    #[cfg(not(feature = "api"))]\n'
        "    unreachable!()\n"
        "}",
    )
    assert (rc, out) == (0, "0"), err


def test_a_marker_may_run_on_to_a_second_comment_line(tmp_path):
    """A real reason is often longer than one line; the marker line carries
    the words that make it a reason and the block continues."""
    rc, out, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        "        0 => 1,\n"
        "        // The index is drawn from a fixed range and every arm exists.\n"
        f"        // gate: unreachable because {REASON}\n"
        "        // and the snapshot suite renders every arm.\n"
        "        _ => unreachable!(),\n"
        "    }\n"
        "}",
    )
    assert (rc, out) == (0, "0"), err


def test_a_marker_with_no_reason_does_not_exempt(tmp_path):
    """The rule this file exists for. A bare `because` is a waiver nobody
    explained, and honoring it would make the marker a magic word."""
    rc, _, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        "        0 => 1,\n"
        "        // gate: unreachable because\n"
        "        _ => unreachable!(),\n"
        "    }\n"
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [5], err
    assert "no reason" in err, err


def test_a_marker_with_a_token_reason_does_not_exempt(tmp_path):
    """`because yes` is the same waiver with a word on it."""
    rc, _, err = scan(
        tmp_path,
        "pub fn prod() {\n"
        "    // gate: panic because yes\n"
        '    panic!("no")\n'
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [3], err


def test_a_marker_naming_a_different_macro_does_not_exempt(tmp_path):
    """The marker names what it waives, so it cannot be copied from a
    `panic!` onto an `unreachable!` without saying so."""
    rc, _, err = scan(
        tmp_path,
        "pub fn prod() {\n"
        f"    // gate: panic because {REASON}\n"
        "    unreachable!()\n"
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [3], err


def test_a_marker_separated_from_the_site_by_code_does_not_reach_it(tmp_path):
    """The marker is local to one site. A line of code between them ends the
    comment block, and the site below is a bare one."""
    rc, _, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        f"    // gate: unreachable because {REASON}\n"
        "    let y = x + 1;\n"
        "    if y == 0 { unreachable!() }\n"
        "    y\n"
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [4], err


def test_a_marker_covers_one_site_and_not_the_next(tmp_path):
    rc, _, err = scan(
        tmp_path,
        "pub fn prod(x: u8) -> u8 {\n"
        "    match x {\n"
        f"        // gate: unreachable because {REASON}\n"
        "        0 => unreachable!(),\n"
        "        1 => unreachable!(),\n"
        "        _ => 2,\n"
        "    }\n"
        "}",
    )
    assert rc == 1, err
    assert violations(err) == [5], err


# ── what is not a violation ──────────────────────────────────────────


def test_a_panic_in_a_test_module_is_exempt(tmp_path):
    rc, out, err = scan(
        tmp_path,
        "pub fn prod() -> u8 { 1 }\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        '    fn t() { if super::prod() != 1 { panic!("no") } }\n'
        "}",
    )
    assert (rc, out) == (0, "0"), err


def test_a_mention_in_a_string_or_comment_is_not_a_violation(tmp_path):
    rc, out, err = scan(
        tmp_path,
        "/// Never `panic!(` on a request path; `unreachable!(` is the same.\n"
        "pub fn prod() -> &'static str {\n"
        '    "this parser does not panic!( on any input"\n'
        "}",
    )
    assert (rc, out) == (0, "0"), err
