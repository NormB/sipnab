# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The suite runs under cargo-nextest, with a deadline on every test.

`cargo test` bounds no single test, and neither did the pool that ran its
binaries side by side: one hung test held the pre-commit hook until its
30-minute wall-clock watchdog fired (TEST-DEADLINE-NEXTEST-SIPNAB).
scripts/parallel-tests.py now runs the suite with `cargo nextest run
--profile suite`, whose slow-timeout stops a test that runs past 60 s three
times over, and the doctests, which nextest does not run, with `cargo test
--doc`.

Everything that reads the suite's output reads libtest's text: the hook's
failure report (`test NAME ... FAILED`, `---- NAME stdout ----`), and
scripts/published-test-count.py (`test result:` lines). So parallel-tests.py
renders nextest's JUnit report in that shape, one block per test binary, and
these tests hold the rendering, the profile, the pin and the run.
"""

import pathlib
import re
import subprocess
import tomllib

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

pt = load("parallel-tests")
count = load("published-test-count")

PASSING = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="0" errors="0">
    <testsuite name="sipnab::b_test" tests="2" failures="0" errors="0">
        <testcase name="two" classname="sipnab::b_test" time="0.010"/>
        <testcase name="one" classname="sipnab::b_test" time="0.020"/>
    </testsuite>
    <testsuite name="sipnab" tests="1" failures="0" errors="0">
        <testcase name="tests::unit" classname="sipnab" time="0.001"/>
    </testsuite>
</testsuites>
"""

FAILING = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="2" errors="0">
    <testsuite name="sipnab::t" tests="3" failures="2" errors="0">
        <testcase name="fails" classname="sipnab::t" time="0.004">
            <failure message="thread &apos;fails&apos; panicked at tests/t.rs:2:73" type="test failure with exit code 101">thread &apos;fails&apos; (3515464) panicked at tests/t.rs:2:73:
assertion `left == right` failed: boom
  left: 1
 right: 2</failure>
            <system-out>
running 1 test
some stdout
test fails ... FAILED

failures:

failures:
    fails

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s

</system-out>
            <system-err>some stderr
</system-err>
        </testcase>
        <testcase name="passes" classname="sipnab::t" time="0.005"/>
        <testcase name="hangs" classname="sipnab::t" time="180.003">
            <failure type="test timeout"/>
            <system-out>
running 1 test
before the hang
</system-out>
            <system-err></system-err>
        </testcase>
    </testsuite>
</testsuites>
"""


def test_a_passing_report_renders_as_libtest_one_block_per_binary():
    text, passed, failed = pt.render_junit(PASSING)
    assert (passed, failed) == (3, 0)
    lines = text.splitlines()
    # Binaries in name order, tests in name order inside each.
    assert lines.index("     Running sipnab") < lines.index("     Running sipnab::b_test")
    assert "test one ... ok" in lines and "test two ... ok" in lines
    assert lines.index("test one ... ok") < lines.index("test two ... ok")
    results = [line for line in lines if line.startswith("test result:")]
    assert len(results) == 2
    assert all(r.startswith("test result: ok. ") for r in results)


def test_the_published_count_reads_the_rendering_as_it_reads_cargo_test():
    text, passed, _ = pt.render_junit(PASSING)
    assert count.count(text) == passed == 3


def test_a_failing_report_names_each_failure_the_way_the_hook_reads_it():
    text, passed, failed = pt.render_junit(FAILING)
    assert (passed, failed) == (1, 2)
    named = re.findall(r"(?m)^test (.*) \.\.\. FAILED$", text)
    assert sorted(named) == ["fails", "hangs"]
    assert re.search(r"(?m)^test result: FAILED\. 1 passed; 2 failed;", text)
    with pytest.raises(count.CountError):
        count.count(text)


def test_a_failure_block_carries_the_panic_and_the_tests_own_output():
    text, _, _ = pt.render_junit(FAILING)
    block = text.split("---- fails stdout ----\n", 1)[1].split("\n---- ", 1)[0]
    assert "panicked at tests/t.rs:2:73" in block
    assert "assertion `left == right` failed: boom" in block
    assert "some stdout" in block and "some stderr" in block


def test_a_failure_block_holds_no_harness_line_of_the_per_test_process():
    # Each test runs in its own process, whose libtest prints its own
    # `test result:` line. Carried into the block, the published count would
    # read it as a binary's result.
    text, _, _ = pt.render_junit(FAILING)
    # One binary, so exactly one result line, and each test named once.
    assert len(re.findall(r"(?m)^test result:", text)) == 1, text
    assert len(re.findall(r"(?m)^test fails \.\.\. ", text)) == 1, text
    assert "running 1 test" not in text, text


def test_a_test_stopped_at_the_deadline_says_so():
    text, _, _ = pt.render_junit(FAILING)
    block = text.split("---- hangs stdout ----\n", 1)[1]
    assert "slow-timeout" in block and "before the hang" in block


def test_a_report_with_no_test_in_it_is_refused():
    with pytest.raises(ValueError):
        pt.render_junit('<?xml version="1.0"?><testsuites name="nextest-run" tests="0"></testsuites>')


def test_an_unreadable_report_is_refused():
    with pytest.raises(ValueError):
        pt.render_junit("<testsuites><testsuite")


def suite_profile():
    return tomllib.loads((REPO / ".config/nextest.toml").read_text())


def test_the_suite_profile_stops_a_test_at_three_sixty_second_periods():
    config = suite_profile()
    profile = config["profile"][pt.PROFILE]
    assert profile["slow-timeout"] == {"period": "60s", "terminate-after": 3}
    assert profile["retries"] == 0, "a retry hides the first failure of a flaky test"
    assert profile["fail-fast"] is False, "every test must run after one fails"
    assert profile["junit"]["path"] == pt.JUNIT


def test_only_the_test_measured_past_the_deadline_gets_a_longer_one():
    # every_documented_command_runs_or_says_why_not runs every command the
    # docs show. On CI's macos-latest runner its binary finished in 191.85 s
    # under cargo test (run 42188622852, on 86a902663), and nextest stopped it
    # at 180 s on this branch's first macOS run. One override, for that test
    # alone, doubles its deadline; every other test keeps three periods.
    overrides = suite_profile()["profile"][pt.PROFILE].get("overrides", [])
    assert overrides == [
        {
            "filter": "test(=every_documented_command_runs_or_says_why_not)",
            "slow-timeout": {"period": "60s", "terminate-after": 6},
        }
    ]


def test_the_report_is_read_from_the_store_the_config_names():
    config = suite_profile()
    assert config["store"]["dir"] == pt.STORE_DEFAULT
    assert pt.report_path({"workspace_root": "/w", "target_directory": "/t"}, REPO) == pathlib.Path(
        "/w", pt.STORE_DEFAULT, pt.PROFILE, pt.JUNIT
    )


def test_the_nextest_version_is_pinned_exactly_in_one_place():
    config = suite_profile()
    assert config["nextest-version"] == {"required": pt.nextest_version(REPO)}
    assert re.fullmatch(r"\d+\.\d+\.\d+", pt.nextest_version(REPO))


@pytest.mark.parametrize(
    "reported,problem",
    [
        ("cargo-nextest 0.9.148 (cd1d6d546 2026-10-07)\n", None),
        ("cargo-nextest 0.9.147 (abc 2026-09-01)\n", "0.9.147"),
        (None, "not installed"),
    ],
)
def test_the_installed_nextest_must_be_the_pinned_one(reported, problem):
    found = pt.nextest_problem("0.9.148", reported)
    if problem is None:
        assert found is None
    else:
        assert problem in found and "cargo install cargo-nextest --locked --version 0.9.148" in found


def test_an_unsharded_run_is_nextest_then_the_doctests():
    assert pt.suite_commands(["--features", "full"]) == [
        ["nextest", "run", "--profile", "suite", "--features", "full"],
        ["test", "--features", "full", "--doc"],
    ]


def test_jobs_become_nextest_test_threads():
    assert pt.suite_commands(["--features", "full"], jobs=1)[0] == [
        "nextest", "run", "--profile", "suite", "--test-threads", "1", "--features", "full",
    ]


def fake_cargo(tmp_path, junit=PASSING, nextest_status=0, doc_status=0):
    """A cargo that logs each call and, for `nextest run`, writes `junit`.

    The report goes where nextest writes it: under its store directory, which
    is relative to the workspace root and does not follow CARGO_TARGET_DIR.
    The build directory the fake's `cargo metadata` reports is elsewhere, as
    it is on CI's self-hosted runners, so a reader that looked there finds no
    report.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "cargo.log"
    report = tmp_path / "target" / "nextest" / pt.PROFILE / pt.JUNIT
    (tmp_path / "report.xml").write_text(junit or "")
    (tmp_path / "meta.json").write_text(
        f'{{"target_directory": "{tmp_path / "elsewhere"}", "workspace_root": "{tmp_path}", "packages": []}}'
    )
    cargo = bindir / "cargo"
    cargo.write_text(
        "#!/bin/sh\n"
        f'case "$1" in metadata) cat "{tmp_path}/meta.json"; exit 0 ;; esac\n'
        f'echo "$*" >> "{log}"\n'
        'if [ "$1" = nextest ] && [ "$2" = --version ]; then echo "cargo-nextest 0.9.148 (x 2026-10-07)"; exit 0; fi\n'
        'if [ "$1" = nextest ]; then\n'
        + (f'  mkdir -p "{report.parent}" && cp "{tmp_path}/report.xml" "{report}"\n' if junit else "")
        + f"  exit {nextest_status}\n"
        "fi\n"
        'echo "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"\n'
        f"exit {doc_status}\n"
    )
    cargo.chmod(0o755)
    return bindir, log, report


def run(tmp_path, bindir, *args):
    import os

    return subprocess.run(
        ["python3", str(REPO / "scripts/parallel-tests.py"), *args, "--", "--features", "full"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"},
    )


def test_a_green_run_prints_the_rendered_report_and_the_doctests(tmp_path):
    bindir, log, _ = fake_cargo(tmp_path)
    proc = run(tmp_path, bindir)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert count.count(proc.stdout) == 3 + 2
    calls = log.read_text().splitlines()
    assert calls[-2:] == ["nextest run --profile suite --features full", "test --features full --doc"]


def test_a_failing_nextest_run_fails_and_the_doctests_still_run(tmp_path):
    bindir, log, _ = fake_cargo(tmp_path, junit=FAILING, nextest_status=100)
    proc = run(tmp_path, bindir)
    assert proc.returncode != 0
    assert "test fails ... FAILED" in proc.stdout
    assert log.read_text().splitlines()[-1] == "test --features full --doc"


def test_a_failing_doctest_run_fails_the_run(tmp_path):
    bindir, _, _ = fake_cargo(tmp_path, doc_status=101)
    assert run(tmp_path, bindir).returncode != 0


def test_a_report_left_by_an_earlier_run_is_never_read(tmp_path):
    # nextest exits non-zero without writing a report when the build fails;
    # the previous run's green report must not stand in for this one.
    bindir, _, report = fake_cargo(tmp_path, junit=None, nextest_status=101)
    report.parent.mkdir(parents=True)
    report.write_text(PASSING)
    proc = run(tmp_path, bindir)
    assert proc.returncode != 0
    assert "test one ... ok" not in proc.stdout, "the stale report was rendered as this run's"


def test_a_run_whose_nextest_wrote_no_report_fails_even_if_it_exited_zero(tmp_path):
    bindir, _, _ = fake_cargo(tmp_path, junit=None, nextest_status=0)
    proc = run(tmp_path, bindir)
    assert proc.returncode != 0
    assert "no report" in proc.stderr


def test_a_run_with_the_wrong_nextest_installed_stops_before_building(tmp_path):
    bindir, log, _ = fake_cargo(tmp_path)
    cargo = bindir / "cargo"
    cargo.write_text(cargo.read_text().replace("cargo-nextest 0.9.148", "cargo-nextest 0.9.100"))
    proc = run(tmp_path, bindir)
    assert proc.returncode != 0
    assert "0.9.100" in proc.stderr and "0.9.148" in proc.stderr
    assert "nextest run" not in log.read_text()
