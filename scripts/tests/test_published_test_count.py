"""The homepage's automated-test count is derived from a run, by one rule.

`scripts/published-test-count.py` is that rule. ci.yml runs it on the suite's
output, and pages.yml runs it on the same output at deploy time, writing the
data file the homepage template reads. These pin what it counts and what it
refuses, so the published number cannot come from a partial or failed run.
"""

import pathlib
import subprocess
import sys
import tomllib

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/published-test-count.py"

ptc = load("published-test-count")

# Three binaries, the shape `cargo test` prints: a library, an integration
# test binary and the doctests, each ending in one `test result:` line.
SAMPLE = """\
running 264 tests
test a ... ok
test result: ok. 264 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 7.82s

     Running tests/x.rs (target/debug/deps/x-0123)
test result: ok. 1600 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
   Doc-tests sipnab
test result: ok. 974 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
"""


def run(*args, stdin=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        input=stdin,
    )


def test_sums_the_passed_column_of_every_result_line():
    assert ptc.count(SAMPLE) == 2838


def test_a_result_line_that_does_not_start_the_line_is_not_counted():
    # CI's rule anchors at the start of the line. A test that prints a
    # result-shaped string mid-line must not inflate the published number.
    text = SAMPLE + 'println: "test result: ok. 5 passed; 0 failed"\n'
    assert ptc.count(text) == 2838


def test_output_with_no_result_line_is_refused():
    try:
        ptc.count("running 0 tests\n")
    except ptc.CountError as e:
        assert "no `test result:` line" in str(e)
    else:
        raise AssertionError("an output with no result line produced a count")


def test_a_total_of_zero_is_refused():
    text = "test result: ok. 0 passed; 0 failed; 0 ignored\n"
    try:
        ptc.count(text)
    except ptc.CountError as e:
        assert "0 tests" in str(e)
    else:
        raise AssertionError("a zero total was published")


def test_a_failed_binary_is_refused():
    text = SAMPLE + "test result: FAILED. 10 passed; 1 failed; 0 ignored\n"
    try:
        ptc.count(text)
    except ptc.CountError as e:
        assert "FAILED" in str(e)
    else:
        raise AssertionError("a run with a failed binary produced a count")


def test_cli_prints_the_count_and_writes_the_data_file(tmp_path):
    out = tmp_path / "suite.txt"
    out.write_text(SAMPLE)
    data = tmp_path / "data" / "test-count.toml"
    res = run(str(out), "--write", str(data))
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "2838"
    assert tomllib.loads(data.read_text()) == {"automated_tests": 2838}


def test_cli_exits_non_zero_and_writes_nothing_on_a_bad_run(tmp_path):
    out = tmp_path / "suite.txt"
    out.write_text("error[E0425]: cannot find value\n")
    data = tmp_path / "test-count.toml"
    res = run(str(out), "--write", str(data))
    assert res.returncode != 0
    assert "no `test result:` line" in res.stderr
    assert not data.exists()


def test_cli_reads_standard_input_when_given_a_dash():
    res = run("-", stdin=SAMPLE)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "2838"
