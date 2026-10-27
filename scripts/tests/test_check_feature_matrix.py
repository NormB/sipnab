# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/check-feature-matrix.py: what it prints from a failing combination.

CI sets CARGO_TERM_COLOR=always, so cargo's diagnostics arrive wrapped in ANSI
color codes. The report keeps the lines that name the problem; these drive that
selection on the shapes cargo writes, colored and plain.
"""

from conftest import load

matrix = load("check-feature-matrix")

ESC = "\x1b"
COLORED = (
    f"{ESC}[0m{ESC}[1m{ESC}[32m    Checking{ESC}[0m demo v0.1.0\n"
    f"{ESC}[0m{ESC}[1m{ESC}[91merror{ESC}[0m{ESC}[0m{ESC}[1m: unneeded `return` statement{ESC}[0m\n"
    f"{ESC}[0m {ESC}[0m{ESC}[0m{ESC}[1m{ESC}[94m--> {ESC}[0m{ESC}[0msrc/main.rs:9:9{ESC}[0m\n"
    f"{ESC}[0m  {ESC}[0m{ESC}[0m{ESC}[1m{ESC}[94m|{ESC}[0m\n"
    f"{ESC}[0m{ESC}[1m{ESC}[91merror{ESC}[0m{ESC}[1m:{ESC}[0m could not compile `demo` (bin \"demo\") due to 1 previous error\n"
)
PLAIN = (
    "    Checking demo v0.1.0\n"
    "warning: unused variable: `x`\n"
    "error[E0425]: cannot find value `y` in this scope\n"
    " --> src/lib.rs:3:5\n"
    "  |\n"
)


def test_a_colored_diagnostic_keeps_its_message():
    lines = matrix.report_lines(COLORED)
    assert "error: unneeded `return` statement" in lines
    assert any("--> src/main.rs:9:9" in line for line in lines)


def test_reported_lines_carry_no_color_codes():
    assert all(ESC not in line for line in matrix.report_lines(COLORED))


def test_progress_and_gutter_lines_are_left_out():
    lines = matrix.report_lines(COLORED)
    assert not any("Checking" in line for line in lines)
    assert not any(line.strip() == "|" for line in lines)


def test_plain_output_keeps_errors_warnings_and_locations():
    assert matrix.report_lines(PLAIN) == [
        "warning: unused variable: `x`",
        "error[E0425]: cannot find value `y` in this scope",
        " --> src/lib.rs:3:5",
    ]
