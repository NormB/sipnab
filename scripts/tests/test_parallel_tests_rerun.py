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
test no longer exists (but writes a report with no test in it, which is why
the replay now lists first; see the end of this file), and a doctest is selected by a libtest substring filter
(rustdoc's names do not match `--exact`).
"""

import json

from conftest import SCRIPTS, load

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


# ── a recorded test nextest no longer lists ─────────────────────────────────
#
# HOOK-REPLAY-OF-REMOVED-TEST, 2026-11-22: a fix renamed the test its last run
# had failed, and the hook's replay ended "without naming a test (exit 1)".
# Measured on cargo-nextest 0.9.148 (2026-11-23): a filterset that selects no
# test exits 0 under `--no-tests pass` but writes a report with no test in it,
# which run_nextest refuses; a filterset naming a binary that is gone does not
# parse at all ("no binary IDs matched this", exit 94). The replay now asks
# nextest which recorded tests it still lists and replays only those.

BINARIES_JSON = json.dumps(
    {
        "rust-build-meta": {},
        "rust-binaries": {
            "sipnab": {"binary-id": "sipnab", "kind": "lib"},
            "sipnab::docs_drift_test": {"binary-id": "sipnab::docs_drift_test", "kind": "test"},
            "sipnab::bin/sipnab": {"binary-id": "sipnab::bin/sipnab", "kind": "bin"},
        },
    }
)


def _suites(cases: dict[str, dict[str, str]]) -> str:
    return json.dumps(
        {
            "rust-suites": {
                binary: {
                    "binary-id": binary,
                    "testcases": {name: {"filter-match": {"status": status}} for name, status in tests.items()},
                }
                for binary, tests in cases.items()
            }
        }
    )


def _main(monkeypatch, record) -> int:
    monkeypatch.setattr(pt.sys, "argv", ["parallel-tests.py", "--rerun", str(record), "--", "--features", "full"])
    return pt.main()


def _never(what):
    def refuse(*args, **kwargs):
        raise AssertionError(f"{what} ran: {args!r}")

    return refuse


# success


def test_the_listed_binaries_are_read():
    assert pt.listed_binaries(BINARIES_JSON) == {"sipnab", "sipnab::docs_drift_test", "sipnab::bin/sipnab"}


def test_the_listed_tests_are_the_ones_the_filter_matches():
    text = _suites({"sipnab::docs_drift_test": {"docs_match": "matches", "other": "mismatch"}})
    assert pt.listed_tests(text) == {("sipnab::docs_drift_test", "docs_match")}


def test_a_recorded_test_still_listed_is_kept():
    failures = [("sipnab::docs_drift_test", "docs_match")]
    assert pt.still_listed(failures, {("sipnab::docs_drift_test", "docs_match")}) == (failures, [])


def test_the_list_filter_names_only_binaries_that_exist():
    failures = [("sipnab::gone_test", "a"), ("sipnab", "app::tests::bad_one")]
    assert pt.list_filterset(failures, {"sipnab"}) == "(binary_id(=sipnab) & test(=app::tests::bad_one))"


def test_the_list_command_is_nextests_with_the_suites_profile():
    cmd = pt.list_command(["--features", "full", "--color", "never", "--", "--nocapture"], ["--list-type", "binaries-only"])
    assert cmd[:4] == ["nextest", "list", "--profile", pt.PROFILE]
    at = cmd.index("--message-format")
    assert cmd[at : at + 2] == ["--message-format", "json"]
    assert "--features" in cmd and "--list-type" in cmd
    assert "--nocapture" not in cmd, "the harness arguments go to a run, not to a list"


def test_a_replay_of_listed_tests_runs_them(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab::docs_drift_test", "docs_match")])
    lists = iter([BINARIES_JSON, _suites({"sipnab::docs_drift_test": {"docs_match": "matches"}})])
    monkeypatch.setattr(pt, "nextest_list", lambda cmd: (0, next(lists)))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    ran = []
    monkeypatch.setattr(pt, "run_rerun", lambda commands: ran.append(commands) or 0)
    assert _main(monkeypatch, record) == 0
    assert "docs_match" in " ".join(ran[0][0])
    assert "dropped" not in capsys.readouterr().err


# failure: the record names what nextest no longer lists


def test_a_test_removed_from_its_binary_is_dropped():
    failures = [("sipnab::docs_drift_test", "renamed_away"), ("sipnab", "app::tests::bad_one")]
    kept, dropped = pt.still_listed(failures, {("sipnab", "app::tests::bad_one")})
    assert kept == [("sipnab", "app::tests::bad_one")]
    assert dropped == [("sipnab::docs_drift_test", "renamed_away")]


def test_a_removed_binary_drops_its_tests():
    kept, dropped = pt.still_listed([("sipnab::gone_test", "a")], set())
    assert (kept, dropped) == ([], [("sipnab::gone_test", "a")])


def test_an_ignored_test_is_dropped_as_nextest_would_not_run_it():
    text = _suites({"sipnab": {"slow_one": "mismatch"}})
    assert pt.still_listed([("sipnab", "slow_one")], pt.listed_tests(text)) == ([], [("sipnab", "slow_one")])


def test_a_record_of_only_removed_tests_replays_nothing_and_passes(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab::docs_drift_test", "renamed_away")])
    lists = iter([BINARIES_JSON, _suites({"sipnab::docs_drift_test": {"docs_match": "matches"}})])
    monkeypatch.setattr(pt, "nextest_list", lambda cmd: (0, next(lists)))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    monkeypatch.setattr(pt, "run_rerun", _never("the replay"))
    assert _main(monkeypatch, record) == 0
    err = capsys.readouterr().err
    assert "dropped from the replay" in err and "sipnab::docs_drift_test renamed_away" in err, err


def test_a_record_naming_a_removed_binary_lists_no_filter_for_it(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab::gone_test", "a"), ("sipnab::docs_drift_test", "docs_match")])
    seen = []

    def fake_list(cmd):
        seen.append(cmd)
        if "--list-type" in cmd:
            return 0, BINARIES_JSON
        return 0, _suites({"sipnab::docs_drift_test": {"docs_match": "matches"}})

    monkeypatch.setattr(pt, "nextest_list", fake_list)
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    ran = []
    monkeypatch.setattr(pt, "run_rerun", lambda commands: ran.append(commands) or 0)
    assert _main(monkeypatch, record) == 0
    assert len(seen) == 2 and "gone_test" not in " ".join(seen[1])
    assert "gone_test" not in " ".join(ran[0][0])
    assert "sipnab::gone_test a" in capsys.readouterr().err


def test_a_list_that_fails_stops_the_replay_with_its_status(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab", "app::tests::bad_one")])
    monkeypatch.setattr(pt, "nextest_list", lambda cmd: (101, ""))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    monkeypatch.setattr(pt, "run_rerun", _never("the replay"))
    assert _main(monkeypatch, record) == 101
    assert "nextest list" in capsys.readouterr().err


def test_a_list_that_is_not_json_stops_the_replay(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab", "app::tests::bad_one")])
    monkeypatch.setattr(pt, "nextest_list", lambda cmd: (0, "not json"))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    monkeypatch.setattr(pt, "run_rerun", _never("the replay"))
    assert _main(monkeypatch, record) == 1
    assert "nextest list" in capsys.readouterr().err


def test_the_hook_shows_what_the_replay_dropped():
    hook = (SCRIPTS.parent / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    replay = hook[hook.index("0c. The tests that failed last run") : hook.index("1. Clippy must pass")]
    code = "\n".join(line for line in replay.splitlines() if not line.lstrip().startswith("#"))
    printed = (SCRIPTS / "parallel-tests.py").read_text(encoding="utf-8")
    prefix = "parallel-tests: dropped from the replay"
    assert f'print(f"{prefix}' in printed, "the script's dropped line changed; match it here"
    assert f"grep '^{prefix}'" in code, "a passing replay must still print the names it dropped"


# edge


def test_a_doctest_is_kept_without_a_listing():
    doc = (pt.DOC_PREFIX + "sipnab", "src/lib.rs - Thing (line 12)")
    assert pt.still_listed([doc], set()) == ([doc], [])


def test_a_record_of_doctests_only_lists_nothing(monkeypatch, tmp_path):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [(pt.DOC_PREFIX + "sipnab", "src/lib.rs - Thing (line 12)")])
    monkeypatch.setattr(pt, "nextest_list", _never("nextest list"))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    ran = []
    monkeypatch.setattr(pt, "run_rerun", lambda commands: ran.append(commands) or 0)
    assert _main(monkeypatch, record) == 0
    assert ran and ran[0][0][0] == "test"


def test_a_name_the_filterset_cannot_spell_is_neither_listed_nor_dropped():
    odd = ("sipnab", "has space")
    assert pt.list_filterset([odd], {"sipnab"}) is None
    assert pt.still_listed([odd], set()) == ([odd], [])


def test_the_kept_tests_keep_the_record_order():
    failures = [("sipnab", "b"), ("sipnab", "a"), ("sipnab", "c")]
    kept, _ = pt.still_listed(failures, {("sipnab", "a"), ("sipnab", "b"), ("sipnab", "c")})
    assert kept == failures


def test_listings_with_no_suites_or_binaries_list_nothing():
    assert pt.listed_tests(json.dumps({})) == set()
    assert pt.listed_binaries(json.dumps({})) == set()


def test_a_record_with_no_binary_left_runs_only_the_binaries_list(monkeypatch, tmp_path, capsys):
    record = tmp_path / "failed.json"
    pt.write_failure_record(record, [("sipnab::gone_test", "a")])
    seen = []
    monkeypatch.setattr(pt, "nextest_list", lambda cmd: seen.append(cmd) or (0, BINARIES_JSON))
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    monkeypatch.setattr(pt, "run_rerun", _never("the replay"))
    assert _main(monkeypatch, record) == 0
    assert len(seen) == 1, "with no recorded binary left there is no filterset to list"
    assert "sipnab::gone_test a" in capsys.readouterr().err
