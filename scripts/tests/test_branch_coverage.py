"""The branch-coverage verdict the weekly Quality job reads.

`cargo llvm-cov report` enforces floors for lines, regions and functions and
has no `--fail-under-branches`, so the branch number is read out of its
`--json --summary-only` export instead. These fixtures pin the two ways that
reading can lie:

- A report with NO branch data. A stable toolchain, or a collection run
  without `--branch`, exports `branches.count == 0`. Zero of zero is not 100%
  and not a pass; it means the thing being gated was never measured.
- A floor compared against the wrong number. The verdict is taken from
  `covered / count`, the counts the export carries, so a rounded `percent`
  field cannot carry 79.996% over an 80% floor.
"""

import json
import pathlib
import subprocess
import sys

import pytest
from conftest import load

bc = load("branch-coverage")
SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "branch-coverage.py"


def export(count, covered, percent=None):
    """A minimal `cargo llvm-cov report --json --summary-only` document."""
    if percent is None:
        percent = 100.0 * covered / count if count else 0.0
    return {
        "type": "llvm.coverage.json.export",
        "version": "2.0.1",
        "data": [
            {
                "files": [],
                "totals": {
                    "branches": {
                        "count": count,
                        "covered": covered,
                        "notcovered": count - covered,
                        "percent": percent,
                    },
                    "lines": {"count": 10, "covered": 10, "percent": 100.0},
                },
            }
        ],
    }


def test_a_report_above_the_floor_passes():
    ok, msg = bc.evaluate(export(1000, 850), floor=80)
    assert ok, msg
    assert "850/1000" in msg and "85.00%" in msg


def test_a_report_below_the_floor_fails_and_names_both_numbers():
    ok, msg = bc.evaluate(export(1000, 799), floor=80)
    assert not ok
    assert "79.90%" in msg and "80" in msg


def test_the_verdict_uses_the_counts_not_the_rounded_percent():
    # 7999/10000 is 79.99%; a producer that rounded `percent` to 80.0 must not
    # carry it over the floor.
    ok, _ = bc.evaluate(export(10000, 7999, percent=80.0), floor=80)
    assert not ok


def test_exactly_the_floor_passes():
    ok, msg = bc.evaluate(export(1000, 800), floor=80)
    assert ok, msg


def test_no_branch_data_fails_even_without_a_floor():
    ok, msg = bc.evaluate(export(0, 0), floor=None)
    assert not ok
    assert "--branch" in msg


def test_no_floor_reports_without_judging_the_number():
    ok, msg = bc.evaluate(export(1000, 100), floor=None)
    assert ok, msg
    assert "10.00%" in msg


def test_a_floor_outside_zero_to_one_hundred_is_refused():
    with pytest.raises(ValueError):
        bc.evaluate(export(1000, 900), floor=800)


def test_a_document_without_totals_is_refused():
    with pytest.raises(ValueError):
        bc.evaluate({"data": []}, floor=80)


def _run(tmp_path, doc, *args):
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(doc))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_command_line_exit_code_follows_the_verdict(tmp_path):
    assert _run(tmp_path, export(1000, 850), "--floor", "80").returncode == 0
    below = _run(tmp_path, export(1000, 700), "--floor", "80")
    assert below.returncode == 1
    assert "70.00%" in below.stdout + below.stderr
    assert _run(tmp_path, export(0, 0)).returncode == 1
