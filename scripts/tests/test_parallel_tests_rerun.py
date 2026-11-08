# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The tests that failed last run run first, and the first failure stops them.

Any failure used to restart the whole pre-commit hook, every test included, so
learning whether a fix worked cost a full suite. scripts/parallel-tests.py now
records the tests a suite run names as failed (`record-failures`), and the
hook's next run replays them first (`--rerun`) with nextest's `--fail-fast`.
A failure there stops the hook; a pass goes on to the full suite, so a pass
still means the full suite passed on that tree.

The filterset syntax, `--fail-fast` and `--no-tests pass` were checked against
cargo-nextest 0.9.148, the version .config/nextest.toml pins: `binary_id(=X)`
takes `::`, `/` and `-` unquoted, `--no-tests pass` exits 0 when a recorded
test no longer exists, and a doctest is selected by a libtest substring filter
(rustdoc's names do not match `--exact`).
"""

import json

from conftest import load

pt = load("parallel-tests")

RENDERED = """\
     Running sipnab

test app::tests::ok_one ... ok
test app::tests::bad_one ... FAILED

failures:

---- app::tests::bad_one stdout ----
panicked at src/app.rs:1:1

failures:
    app::tests::bad_one

test result: FAILED. 1 passed; 1 failed; ignored tests are not reported by cargo-nextest; finished in 0.01s

     Running sipnab::bin/sipnab

test cli_parses ... FAILED

test result: FAILED. 0 passed; 1 failed; ignored tests are not reported by cargo-nextest; finished in 0.01s

     Running sipnab::docs_drift_test

test docs_match ... ok

test result: ok. 1 passed; 0 failed; ignored tests are not reported by cargo-nextest; finished in 0.01s

   Doc-tests sipnab

running 2 tests
test src/lib.rs - Thing (line 12) ... FAILED
test src/lib.rs - other (line 40) ... ok
"""


def test_failures_are_read_with_the_binary_that_ran_them():
    assert pt.failed_tests(RENDERED) == [
        ("sipnab", "app::tests::bad_one"),
        ("sipnab::bin/sipnab", "cli_parses"),
        ("doc:sipnab", "src/lib.rs - Thing (line 12)"),
    ]


def test_a_run_with_no_failure_records_none():
    assert pt.failed_tests("     Running sipnab\n\ntest a ... ok\n") == []


def test_a_failure_before_any_binary_header_is_not_recorded():
    assert pt.failed_tests("test orphan ... FAILED\n") == []


def test_the_filterset_selects_each_failed_test_in_its_own_binary():
    expr = pt.filterset([("sipnab", "app::tests::bad_one"), ("sipnab::bin/sipnab", "cli_parses")])
    assert expr == (
        "(binary_id(=sipnab) & test(=app::tests::bad_one)) | (binary_id(=sipnab::bin/sipnab) & test(=cli_parses))"
    )


def test_a_name_the_filterset_cannot_spell_is_left_to_the_full_suite():
    assert pt.filterset([("sipnab", "weird name (x)"), ("sipnab", "fine::one")]) == (
        "(binary_id(=sipnab) & test(=fine::one))"
    )
    assert pt.filterset([("sip|nab", "x")]) is None


def test_the_rerun_is_nextest_with_the_filter_and_fail_fast_then_the_doctests():
    failures = [("sipnab", "a::b"), ("doc:sipnab", "src/lib.rs - Thing (line 12)")]
    commands = pt.rerun_commands(failures, ["--features", "full", "--color", "never"], None)
    assert commands == [
        [
            "nextest", "run", "--profile", "suite", "--features", "full", "--color", "never",
            "-E", "(binary_id(=sipnab) & test(=a::b))", "--fail-fast", "--no-tests", "pass",
        ],
        ["test", "--features", "full", "--color", "never", "--doc", "--", "src/lib.rs - Thing (line 12)"],
    ]


def test_a_rerun_of_doctests_only_starts_no_nextest_run():
    commands = pt.rerun_commands([("doc:sipnab", "src/lib.rs - x (line 1)")], ["--features", "full"], 2)
    assert commands == [["test", "--features", "full", "--doc", "--", "src/lib.rs - x (line 1)"]]


def test_a_doctest_of_another_crate_is_not_replayed():
    assert pt.rerun_commands([("doc:sipnab_bpf_types", "src/lib.rs - y (line 3)")], [], None) == []


def test_the_rerun_keeps_the_jobs_setting():
    commands = pt.rerun_commands([("sipnab", "a")], [], 3)
    assert commands[0][:6] == ["nextest", "run", "--profile", "suite", "--test-threads", "3"]


def test_a_record_reads_back_what_was_written(tmp_path):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab", "a::b"), ("doc:sipnab", "src/lib.rs - x (line 1)")])
    assert pt.read_failure_record(record) == [("sipnab", "a::b"), ("doc:sipnab", "src/lib.rs - x (line 1)")]


def test_a_run_without_failures_removes_the_record(tmp_path):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab", "a")])
    pt.write_failure_record(record, [])
    assert not record.exists()


def test_a_corrupt_or_foreign_record_replays_nothing(tmp_path):
    record = tmp_path / "failed.json"
    for body in ("{not json", json.dumps({"schema": 99, "failures": [["sipnab", "a"]]}), json.dumps([1, 2])):
        record.write_text(body, encoding="utf-8")
        assert pt.read_failure_record(record) is None, body
    assert pt.read_failure_record(tmp_path / "missing.json") is None


def test_the_rerun_stops_at_the_first_failing_command(monkeypatch):
    ran = []

    def fake(cmd):
        ran.append(cmd[0])
        return 1

    monkeypatch.setattr(pt, "run_nextest", fake)
    monkeypatch.setattr(pt.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran on")))
    assert pt.run_rerun([["nextest", "run"], ["test", "--doc"]]) == 1
    assert ran == ["nextest"]
