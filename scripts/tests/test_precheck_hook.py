# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The pre-check is the REAL pre-commit hook with SIPNAB_GATE_PRECHECK=1.

In the week to 2026-11-21 hook runs failed on clippy and on gates that read
only the source tree, after scripts/pin-gates.py, the quick check run before
the hook, had passed: it ran none of them. The pre-check runs the hook's own
steps, so the two cannot drift, with two left out: the full suite, replaced by
`scripts/pin-gates.py --source-gates`, and the script tests. These tests run
the hook in scripts/lib-hook-sandbox.sh's sandbox (a stubbed cargo that logs
every call) and observe what it did.
"""

import os
import pathlib
import subprocess

import pytest
from test_gate_cache_hooks import clean_env, git, junit, pre_commit_sandbox

REPO = pathlib.Path(__file__).resolve().parents[2]
PRECHECK = {"SIPNAB_GATE_PRECHECK": "1"}
SOURCE_GATE = 'fn t() { let _ = std::fs::read_to_string("SECURITY.md"); }\n'


def add_source_gate(sb):
    """A test binary that reads the tree only, and the lists pin-gates.py reads."""
    (sb.tree / "tests").mkdir(exist_ok=True)
    (sb.tree / "tests/a_test.rs").write_text(SOURCE_GATE)
    (sb.tree / "tests/b_test.rs").write_text('fn t() { let _ = env!("CARGO_BIN_EXE_sipnab"); }\n')
    (sb.tree / ".config/pin-gates.txt").write_text("# none\n")
    (sb.tree / ".config/precheck-skip.txt").write_text("# none\n")
    # `pin-gates.py --hook` runs the tree's own .githooks/pre-commit; the
    # sandbox runs the repository's hook by its path, so the tree's one hands over to it.
    (sb.tree / ".githooks").mkdir(exist_ok=True)
    (sb.tree / ".githooks/pre-commit").write_text(f'exec bash "{sb.hook}" "$@"\n')
    git(sb.tree, "add", "tests", ".config", ".githooks")
    git(sb.tree, "commit", "-qm", "gates")


@pytest.fixture
def pre(tmp_path):
    with pre_commit_sandbox(tmp_path / "harness") as sb:
        add_source_gate(sb)
        yield sb


def nextest_calls(sb):
    return [line for line in sb.cargo() if line.startswith("nextest")]


def step_log(sb, name):
    path = sb.tree / ".git" / name
    return path.read_text() if path.exists() else ""


# ── success ─────────────────────────────────────────────────────────────────


def test_a_passing_precheck_exits_zero_and_says_it_is_not_the_hook(pre):
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "Pre-check passed" in out and "All pre-commit checks passed" not in out, out


def test_the_precheck_runs_the_source_gates_and_not_the_suite(pre):
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    calls = nextest_calls(pre)
    assert len(calls) == 1, calls
    assert "--test a_test" in calls[0] and "--test b_test" not in calls[0], calls
    assert not any(line.startswith("test --doc") for line in pre.cargo()), "the doctests are the suite's"


def test_the_precheck_runs_clippy_as_the_hook_does(pre):
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert any(line.startswith("clippy --workspace --all-features --all-targets") for line in pre.cargo()), pre.cargo()


def test_the_precheck_writes_the_clippy_stamp_and_never_the_suite_or_hook_stamp(pre):
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    stamps = pre.stamps()
    assert "clippy" in stamps and "bpf-types" in stamps, stamps
    assert "tests" not in stamps and "hook" not in stamps, stamps


def test_the_hook_after_a_precheck_reuses_clippy_and_runs_the_suite(pre):
    assert pre.run(**PRECHECK)[0] == 0
    rc, out = pre.run()
    assert rc == 0, out
    assert not any(line.startswith("clippy") for line in pre.cargo()), "clippy passed on these inputs already"
    assert any("--test" not in line for line in nextest_calls(pre)), "the hook runs the whole suite"
    assert "hook" in pre.stamps() and "tests" in pre.stamps(), pre.stamps()


def test_the_precheck_logs_its_steps_apart_from_the_hooks(pre):
    before = step_log(pre, "sipnab-pre-commit-steps.log")
    assert pre.run(**PRECHECK)[0] == 0
    assert step_log(pre, "sipnab-pre-commit-steps.log") == before, "hook-steps.py reads hook runs only"
    lines = step_log(pre, "sipnab-precheck-steps.log").splitlines()
    assert any("\tClippy (CI's exact scope)\t" in line for line in lines), lines
    assert lines[-1].split("\t")[1:4:2] == ["total", "0"], lines[-1]


def test_the_precheck_says_which_steps_it_leaves_to_the_hook(pre):
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "the full suite runs in the hook" in out, out
    assert "Homepage test count generated... OK (not counted: the pre-check runs the source gates" in out, out


def test_the_precheck_leaves_out_the_script_tests(pre):
    (pre.tree / "scripts/tests").mkdir()
    (pre.tree / "scripts/tests/test_fails.py").write_text("def test_x():\n    assert False\n")
    git(pre.tree, "add", "scripts/tests")
    git(pre.tree, "commit", "-qm", "a failing script test")
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "Script tests... NOT RUN (pre-check" in out, out


def test_a_hook_that_passed_on_this_tree_passes_the_precheck_at_once(pre):
    assert pre.run()[0] == 0
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert pre.cargo() == [], "a full pass on these inputs covers the pre-check"


def test_precheck_zero_is_the_full_hook(pre):
    rc, out = pre.run(SIPNAB_GATE_PRECHECK="0")
    assert rc == 0, out
    assert "All pre-commit checks passed" in out and "hook" in pre.stamps(), out


def test_pin_gates_hook_runs_the_precheck(pre):
    out = subprocess.run(
        ["python3", "scripts/pin-gates.py", "--hook"], cwd=pre.tree, capture_output=True, text=True,
        env=pre.env(SIPNAB_HOOK_ANY_TREE="1"),
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Pre-check passed" in out.stdout, out.stdout
    assert "--test a_test" in nextest_calls(pre)[0]


def test_a_rerun_precheck_on_an_unchanged_tree_reuses_the_stamps(pre):
    assert pre.run(**PRECHECK)[0] == 0
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert not any(line.startswith(("clippy", "test -p sipnab-bpf-types")) for line in pre.cargo()), pre.cargo()


# ── failure ─────────────────────────────────────────────────────────────────


def test_a_failing_source_gate_fails_the_precheck_by_name(pre):
    (pre.harness / "canned-junit.xml").write_text(junit(("sipnab::a_test", "the_rule_holds", False)))
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "Tests... FAIL" in out and "the_rule_holds" in out, out


def test_a_failing_source_gate_is_replayed_first_by_the_next_run(pre):
    (pre.harness / "canned-junit.xml").write_text(junit(("sipnab::a_test", "the_rule_holds", False)))
    assert pre.run(**PRECHECK)[0] == 1
    assert (pre.tree / ".git/sipnab-pre-commit-failed-tests.json").exists()
    rc, out = pre.run(**PRECHECK)
    assert "Tests that failed last run, first" in out, out


def test_a_clippy_failure_fails_the_precheck(pre):
    pre.switch("fail-clippy")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "Clippy (CI's exact scope)... FAIL" in out, out
    assert nextest_calls(pre) == [], "it stops where the hook stops"


def test_the_precheck_writes_no_stamp_when_a_step_fails(pre):
    pre.switch("fail-clippy")
    assert pre.run(**PRECHECK)[0] == 1
    assert pre.stamps() == [], pre.stamps()


def test_the_precheck_refuses_under_git_commit(pre):
    rc, out = pre.run(GIT_INDEX_FILE=str(pre.tree / ".git/index"), **PRECHECK)
    assert rc == 1, out
    assert "SIPNAB_GATE_PRECHECK" in out and "git commit" in out, out
    assert pre.cargo() == [], "no step runs"


def test_git_commit_with_the_variable_set_is_refused(pre):
    (pre.tree / "docs/internals/x.md").write_text("x\n")
    git(pre.tree, "add", "docs/internals/x.md")
    head = git(pre.tree, "rev-parse", "HEAD")
    out = subprocess.run(
        ["git", "-c", f"core.hooksPath={pre.hook.parent}", "commit", "-qm", "x"], cwd=pre.tree,
        capture_output=True, text=True, env=pre.env(SIPNAB_HOOK_ANY_TREE="1", **PRECHECK),
    )
    assert out.returncode != 0, out.stdout + out.stderr
    assert git(pre.tree, "rev-parse", "HEAD") == head, "no commit was made on the pre-check alone"


def test_an_untracked_file_fails_the_precheck_by_name(pre):
    (pre.tree / "docs/internals/new.md").write_text("x\n")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "docs/internals/new.md" in out and "git add" in out, out


def test_a_skip_list_that_names_no_source_gate_fails_the_precheck(pre):
    (pre.tree / ".config/precheck-skip.txt").write_text("!b_test runs the binary, so it is no source gate\n")
    git(pre.tree, "add", ".config/precheck-skip.txt")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "no source gate" in out, out


def test_a_failed_precheck_logs_a_failed_total(pre):
    pre.switch("fail-clippy")
    assert pre.run(**PRECHECK)[0] == 1
    last = step_log(pre, "sipnab-precheck-steps.log").splitlines()[-1].split("\t")
    assert last[1] == "total" and last[3] == "1", last


def test_pin_gates_hook_returns_a_failed_precheck(pre):
    pre.switch("fail-clippy")
    out = subprocess.run(
        ["python3", "scripts/pin-gates.py", "--hook"], cwd=pre.tree, capture_output=True, text=True,
        env=pre.env(SIPNAB_HOOK_ANY_TREE="1"),
    )
    assert out.returncode == 1, out.stdout + out.stderr


# ── edge ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["", "yes", "true", "2"])
def test_only_one_turns_the_precheck_on(pre, value):
    rc, out = pre.run(SIPNAB_GATE_PRECHECK=value)
    assert rc == 0, out
    assert "All pre-commit checks passed" in out, f"{value!r} is no pre-check: {out}"


def test_the_precheck_variable_does_not_enter_the_stamp_key(pre):
    """The clippy stamp the pre-check writes is the hook's: same key with and without the mode."""
    assert pre.run(**PRECHECK)[0] == 0
    first = pre.stamps()
    pre.run()
    assert set(first) <= set(pre.stamps())
    assert not any(line.startswith("clippy") for line in pre.cargo())


def test_no_cache_reruns_every_precheck_step_and_still_writes_no_hook_stamp(pre):
    assert pre.run(**PRECHECK)[0] == 0
    rc, out = pre.run(SIPNAB_GATE_NO_CACHE="1", **PRECHECK)
    assert rc == 0, out
    assert any(line.startswith("clippy") for line in pre.cargo()), "SIPNAB_GATE_NO_CACHE=1 runs every step"
    assert "hook" not in pre.stamps() and "tests" not in pre.stamps(), pre.stamps()


def test_a_precheck_with_no_binary_to_run_fails_loudly(pre):
    """A tree whose only source gate is skipped, and no pin gate, has nothing to run: that is no pass."""
    (pre.tree / ".config/precheck-skip.txt").write_text("!a_test the only one, left to the hook here\n")
    git(pre.tree, "add", ".config/precheck-skip.txt")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "no test binary to run" in out, out


def test_clean_env_holds_no_precheck_variable():
    """The fixtures start from no SIPNAB_GATE_* variable, so a test sets the mode itself."""
    os.environ["SIPNAB_GATE_PRECHECK"] = "1"
    try:
        assert "SIPNAB_GATE_PRECHECK" not in clean_env()
    finally:
        del os.environ["SIPNAB_GATE_PRECHECK"]


def test_the_hook_names_pin_gates_so_the_sandbox_carries_it():
    hook = (REPO / ".githooks/pre-commit").read_text()
    assert "python3 scripts/pin-gates.py --source-gates" in hook
