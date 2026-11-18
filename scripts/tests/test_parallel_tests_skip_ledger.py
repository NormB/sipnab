# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A suite run counts the tests it skipped on a missing prerequisite.

src/test_prereq.rs appends one line per skip to the file
SIPNAB_PREREQ_SKIP_LEDGER names: binary, test, prerequisite and reason,
separated by tabs. nextest's `suite` profile prints nothing of a passing
test, so the notice each skip writes to stderr is not seen in a suite run;
scripts/parallel-tests.py points the variable at a fresh file and prints the
total and the count per prerequisite when the run ends.
"""

import os

from conftest import load

pt = load("parallel-tests")

LINE = "{b}\t{t}\t{p}\twhy\n"


def ledger(*rows):
    return "".join(LINE.format(b=b, t=t, p=p) for b, t, p in rows)


def test_success_no_ledger_lines_say_nothing_was_skipped():
    assert pt.skip_summary("") == "parallel-tests: 0 tests skipped on a missing prerequisite"


def test_success_the_summary_counts_every_skip():
    text = ledger(("a", "t1", "sudo"), ("a", "t2", "sudo"), ("b", "t3", "landlock"))
    assert pt.skip_summary(text).startswith("parallel-tests: 3 tests skipped"), pt.skip_summary(text)


def test_success_the_summary_counts_by_prerequisite_most_first():
    text = ledger(("a", "t1", "landlock"), ("a", "t2", "sudo"), ("b", "t3", "sudo"))
    assert pt.skip_summary(text).endswith("(sudo 2, landlock 1)"), pt.skip_summary(text)


def test_edge_one_skip_is_one_test():
    text = ledger(("a", "t1", "sudo"))
    assert pt.skip_summary(text) == "parallel-tests: 1 test skipped on a missing prerequisite (sudo 1)"


def test_edge_a_tie_is_ordered_by_name():
    text = ledger(("a", "t1", "tshark"), ("a", "t2", "editcap"))
    assert pt.skip_summary(text).endswith("(editcap 1, tshark 1)"), pt.skip_summary(text)


def test_failure_a_malformed_line_is_counted_as_unreadable():
    text = ledger(("a", "t1", "sudo")) + "not a ledger line\n"
    summary = pt.skip_summary(text)
    assert summary.startswith("parallel-tests: 2 tests skipped"), summary
    assert "unreadable 1" in summary, summary


def test_failure_a_line_with_three_or_five_fields_is_unreadable():
    summary = pt.skip_summary("a\tt\tsudo\n" + "a\tt\tsudo\twhy\textra\n")
    assert summary.endswith("(unreadable 2)"), summary


def test_edge_an_empty_prerequisite_field_is_unreadable():
    summary = pt.skip_summary("a\tt\t\twhy\n")
    assert summary.endswith("(unreadable 1)"), summary


def test_edge_blank_lines_are_not_skips():
    text = "\n" + ledger(("a", "t1", "sudo")) + "\n\n"
    assert pt.skip_summary(text).startswith("parallel-tests: 1 test skipped"), pt.skip_summary(text)


def test_success_a_suite_run_leaves_no_ledger_in_the_tree(monkeypatch, capsys):
    seen = []
    real = pt.skip_ledger_env

    def recording(env, directory):
        out = real(env, directory)
        seen.append(out[1])
        return out

    monkeypatch.setattr(pt, "skip_ledger_env", recording)
    monkeypatch.delenv(pt.SKIP_LEDGER_VAR, raising=False)
    assert pt.run_commands([]) == 0
    assert len(seen) == 1, seen
    ledger = seen[0]
    assert pt.REPO not in ledger.parents, f"{ledger} is inside the tree the hook stamps"
    assert not ledger.exists(), f"{ledger} outlived the run"
    assert "0 tests skipped on a missing prerequisite" in capsys.readouterr().err


def test_success_the_ledger_is_a_fresh_file_in_the_given_directory(tmp_path):
    env, path = pt.skip_ledger_env({}, tmp_path)
    assert path == tmp_path / "prereq-skips.tsv"
    assert env[pt.SKIP_LEDGER_VAR] == str(path)
    assert path.read_text() == "", "the run starts with an empty ledger"


def test_success_an_old_ledger_is_emptied(tmp_path):
    (tmp_path / "prereq-skips.tsv").write_text(ledger(("old", "t", "sudo")))
    _, path = pt.skip_ledger_env({}, tmp_path)
    assert path.read_text() == "", "an earlier run's skips are not this run's"


def test_edge_a_ledger_the_caller_named_is_kept(tmp_path):
    named = tmp_path / "mine.tsv"
    named.write_text(ledger(("kept", "t", "sudo")))
    env, path = pt.skip_ledger_env({pt.SKIP_LEDGER_VAR: str(named)}, tmp_path / "target")
    assert path == named, "the caller's ledger is used"
    assert env[pt.SKIP_LEDGER_VAR] == str(named)
    assert "kept" in named.read_text(), "and not emptied: the caller owns it"


def test_edge_the_environment_passed_in_is_not_changed(tmp_path):
    given = {"PATH": "/bin"}
    env, _ = pt.skip_ledger_env(given, tmp_path)
    assert pt.SKIP_LEDGER_VAR not in given, "the caller's mapping is left alone"
    assert env["PATH"] == "/bin", "and the rest of it is passed on"


def test_failure_a_ledger_directory_that_cannot_exist_is_an_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    try:
        pt.skip_ledger_env({}, blocker / "target")
    except OSError:
        return
    raise AssertionError("a target directory under a file cannot hold the ledger")


def test_success_the_summary_of_a_missing_ledger_file_is_zero(tmp_path):
    assert pt.read_skip_ledger(tmp_path / "absent.tsv") == ""


def test_success_the_ledger_file_is_read(tmp_path):
    path = tmp_path / "skips.tsv"
    path.write_text(ledger(("a", "t", "sudo")))
    assert pt.read_skip_ledger(path) == ledger(("a", "t", "sudo"))


def test_edge_the_variable_name_is_the_helpers():
    helper = (pt.REPO / "src" / "test_prereq.rs").read_text(encoding="utf-8")
    assert f'pub const LEDGER_VAR: &str = "{pt.SKIP_LEDGER_VAR}";' in helper, (
        "parallel-tests.py and src/test_prereq.rs must name the same variable"
    )


def test_edge_os_environ_is_not_needed_to_build_the_env(tmp_path):
    env, _ = pt.skip_ledger_env(dict(os.environ), tmp_path)
    assert env[pt.SKIP_LEDGER_VAR].endswith("prereq-skips.tsv")
