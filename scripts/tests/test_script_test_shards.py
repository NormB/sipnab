# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The script tests in shards: `pin-gates.py --script-tests --shard I/N`.

On 2026-11-23 the whole scripts/tests run took 370 to 539 s alone, and at a
load average near 15 it was ended by a 598 s limit at 90%: one quick-slot job
(600 s) cannot hold it. So the run is split into N shards, each its own job.
The split is by test file, deterministic, and balanced on the durations in
.config/script-test-durations.txt (pytest's own JUnit timing, summed per file).
Each shard that passes writes a pass record keyed on the hook's script-tests
key; the hook's script-tests stamp is written only when every shard of one
plan has a record on the same key. The pre-check and the hook then skip the
step through gate_hit, as they do for any stamp. The command, the target and
the file list come from scripts/gate-cache.py, which the hook reads.
"""

import json
import os
import pathlib
import signal
import subprocess
import sys
import time

import pytest
from conftest import load
from test_gate_cache_hooks import clean_env, git
from test_precheck_hook import PRECHECK
from test_script_tests_rule import add_script_test, counting_test, pre, runs_of, stage  # noqa: F401 (fixture)

gc = load("gate-cache")
pg = load("pin-gates")
REPO = pathlib.Path(__file__).resolve().parents[2]

FIVE = ["tests/test_a.py", "tests/test_b.py", "tests/test_c.py", "tests/test_d.py", "tests/test_e.py"]


def flat(plan):
    return [f for shard in plan for f in shard]


# ── the plan ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
def test_success_every_file_is_in_exactly_one_shard(count):
    plan = gc.plan_shards(FIVE, {"tests/test_a.py": 9.0, "tests/test_c.py": 4.0}, count)
    assert len(plan) == count, plan
    assert sorted(flat(plan)) == FIVE, f"no file lost or doubled: {plan}"


def test_success_the_plan_is_deterministic_whatever_the_input_order():
    durations = {f: float(i + 1) for i, f in enumerate(FIVE)}
    a = gc.plan_shards(FIVE, durations, 2)
    b = gc.plan_shards(list(reversed(FIVE)), dict(reversed(list(durations.items()))), 2)
    assert a == b == gc.plan_shards(FIVE, durations, 2), (a, b)


def test_success_the_two_longest_files_go_to_different_shards():
    durations = {"tests/test_a.py": 100.0, "tests/test_b.py": 90.0, "tests/test_c.py": 5.0,
                 "tests/test_d.py": 5.0, "tests/test_e.py": 5.0}
    plan = gc.plan_shards(FIVE, durations, 2)
    shard_of = {f: i for i, shard in enumerate(plan) for f in shard}
    assert shard_of["tests/test_a.py"] != shard_of["tests/test_b.py"], plan


def test_success_the_shards_are_balanced_on_the_durations():
    durations = {"tests/test_a.py": 50.0, "tests/test_b.py": 30.0, "tests/test_c.py": 20.0,
                 "tests/test_d.py": 20.0, "tests/test_e.py": 10.0}
    loads = sorted(sum(durations[f] for f in shard) for shard in gc.plan_shards(FIVE, durations, 2))
    assert loads == [60.0, 70.0], f"longest first, each to the lightest shard: {loads}"


def test_success_one_shard_is_the_whole_set():
    assert gc.plan_shards(FIVE, {}, 1) == [FIVE]


def test_success_the_shard_command_is_the_hooks_with_the_files_for_the_target():
    command = gc.script_tests_command()
    argv = gc.shard_argv(["tests/test_b.py", "tests/test_a.py"])
    i = command.index(gc.SCRIPT_TESTS_TARGET)
    assert argv == command[:i] + ["tests/test_b.py", "tests/test_a.py"] + command[i + 1:], argv


def test_success_the_command_and_its_directory_are_the_hooks_own_text():
    hook = (REPO / ".githooks/pre-commit").read_text(encoding="utf-8")
    line = f"cd {gc.SCRIPTS_CWD} && {gc.STEPS['pre-commit']['script-tests'][1]}"
    assert line in hook, f"the hook no longer runs {line!r}: the shards would run another command"


def test_success_the_file_list_is_what_pytest_collects(tmp_path):
    tests = tmp_path / "scripts/tests"
    (tests / "sub").mkdir(parents=True)
    (tests / ".hidden").mkdir()
    for name in ("test_a.py", "b_test.py", "sub/test_c.py", "helper.py", "conftest.py", ".hidden/test_x.py"):
        (tests / name).write_text("def test_one():\n    pass\n")
    assert gc.script_test_files(tmp_path) == ["tests/b_test.py", "tests/sub/test_c.py", "tests/test_a.py"]
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests/"],
        cwd=tmp_path / "scripts", env=clean_env(), capture_output=True, text=True, timeout=120,
    )
    collected = sorted({line.split("::")[0] for line in out.stdout.splitlines() if "::" in line})
    assert collected == gc.script_test_files(tmp_path), out.stdout


def test_success_the_real_file_list_is_what_pytest_collects_from_the_hooks_target():
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", gc.SCRIPT_TESTS_TARGET],
        cwd=REPO / gc.SCRIPTS_CWD, env=clean_env(), capture_output=True, text=True, timeout=300,
    )
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-2000:]
    collected = sorted({line.split("::")[0] for line in out.stdout.splitlines() if "::" in line})
    assert collected == gc.script_test_files(REPO), "the shard file list and pytest's collection differ"


def test_success_the_union_of_the_shards_collects_the_same_tests_as_the_whole_run(tmp_path):
    tests = tmp_path / "scripts/tests"
    tests.mkdir(parents=True)
    for n in range(7):
        (tests / f"test_{n}.py").write_text("".join(f"def test_{n}_{k}():\n    pass\n" for k in range(n + 1)))

    def ids(args):
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *args],
            cwd=tmp_path / "scripts", env=clean_env(), capture_output=True, text=True, timeout=120,
        )
        return [line for line in out.stdout.splitlines() if "::" in line]

    whole = ids([gc.SCRIPT_TESTS_TARGET])
    files = gc.script_test_files(tmp_path)
    shards = [ids(shard) for shard in gc.plan_shards(files, {}, 3)]
    union = [i for shard in shards for i in shard]
    assert len(whole) == 28 and sorted(union) == sorted(whole), "a test lost or doubled"
    assert len(union) == len(set(union)), "a test in two shards"


def test_success_durations_parse_with_comments_and_blank_lines():
    text = "# a comment\n\n12.5\ttests/test_a.py\n0.25  tests/test_b.py\n"
    assert gc.parse_durations(text) == {"tests/test_a.py": 12.5, "tests/test_b.py": 0.25}


def test_success_durations_round_trip_through_their_format():
    durations = {"tests/test_b.py": 3.25, "tests/test_a.py": 10.0}
    assert gc.parse_durations(gc.format_durations(durations)) == durations


def test_success_junit_times_are_summed_per_file():
    xml = (
        '<testsuites><testsuite name="pytest">'
        '<testcase classname="test_a" name="t1" file="test_a.py" time="1.5"/>'
        '<testcase classname="test_a" name="t2" file="test_a.py" time="2.0"/>'
        '<testcase classname="test_b" name="t1" file="test_b.py" time="0.5"/>'
        "</testsuite></testsuites>"
    )
    got = gc.durations_from_junit([xml], ["tests/test_a.py", "tests/test_b.py"])
    assert got == {"tests/test_a.py": 3.5, "tests/test_b.py": 0.5}, got


def test_success_a_shard_spec_parses():
    assert gc.parse_shard("2/4") == (2, 4)


def test_success_the_real_durations_file_parses():
    durations = gc.read_durations(REPO)
    assert durations, "the measured durations are recorded"
    assert all(v >= 0 for v in durations.values())


# ── the plan refuses what it cannot split ──────────────────────────────────


@pytest.mark.parametrize("spec", ["0/3", "4/3", "a/b", "3", "1/0", "-1/2", "", " 1/2", "1/2/3", "01/2"])
def test_failure_a_bad_shard_spec_is_refused(spec):
    with pytest.raises(ValueError):
        gc.parse_shard(spec)


def test_failure_more_shards_than_files_is_refused():
    with pytest.raises(ValueError, match="shards"):
        gc.plan_shards(FIVE[:2], {}, 3)


def test_failure_zero_shards_is_refused():
    with pytest.raises(ValueError):
        gc.plan_shards(FIVE, {}, 0)


def test_failure_a_file_named_twice_is_refused():
    with pytest.raises(ValueError, match="twice"):
        gc.plan_shards(FIVE + FIVE[:1], {}, 2)


@pytest.mark.parametrize("text", ["12.5\n", "x tests/test_a.py\n", "-1 tests/test_a.py\n", "nan tests/test_a.py\n",
                                  "inf tests/test_a.py\n", "1 tests/test_a.py extra\n",
                                  "1 tests/test_a.py\n2 tests/test_a.py\n"])
def test_failure_a_bad_durations_line_is_refused(text):
    with pytest.raises(ValueError, match="line"):
        gc.parse_durations(text)


def test_failure_a_junit_file_that_matches_no_test_file_is_refused():
    xml = '<testsuites><testsuite><testcase file="other.py" name="t" time="1"/></testsuite></testsuites>'
    with pytest.raises(ValueError, match="other.py"):
        gc.durations_from_junit([xml], ["tests/test_a.py"])


def test_failure_a_junit_report_without_file_attributes_is_refused():
    xml = '<testsuites><testsuite><testcase classname="x" name="t" time="1"/></testsuite></testsuites>'
    with pytest.raises(ValueError, match="xunit1"):
        gc.durations_from_junit([xml], ["tests/test_a.py"])


# ── the plan's edges ────────────────────────────────────────────────────────


def test_edge_as_many_shards_as_files_gives_one_file_each():
    plan = gc.plan_shards(FIVE, {}, 5)
    assert sorted(len(s) for s in plan) == [1] * 5, plan


def test_edge_with_no_durations_the_shards_differ_by_one_file_at_most():
    files = [f"tests/test_{n:02}.py" for n in range(11)]
    sizes = [len(s) for s in gc.plan_shards(files, {}, 3)]
    assert max(sizes) - min(sizes) <= 1, sizes


def test_edge_a_file_without_a_duration_weighs_the_median():
    durations = {"tests/test_a.py": 1.0, "tests/test_b.py": 2.0, "tests/test_c.py": 30.0}
    assert gc.shard_weights(FIVE, durations)["tests/test_d.py"] == 2.0


def test_edge_equal_durations_are_split_by_name():
    plan = gc.plan_shards(FIVE, {}, 2)
    assert plan == [["tests/test_a.py", "tests/test_c.py", "tests/test_e.py"],
                    ["tests/test_b.py", "tests/test_d.py"]], plan


def test_edge_each_shard_lists_its_files_by_name():
    durations = {"tests/test_e.py": 9.0, "tests/test_a.py": 1.0}
    for shard in gc.plan_shards(FIVE, durations, 2):
        assert shard == sorted(shard), shard


def test_edge_a_duration_for_a_removed_file_is_ignored():
    plan = gc.plan_shards(FIVE, {"tests/test_gone.py": 500.0}, 2)
    assert "tests/test_gone.py" not in flat(plan)


def test_edge_no_durations_file_means_equal_weights(tmp_path):
    assert gc.read_durations(tmp_path) == {}


def test_edge_a_one_of_one_spec_parses():
    assert gc.parse_shard("1/1") == (1, 1)


def test_edge_the_shard_command_keeps_the_files_in_the_order_given():
    argv = gc.shard_argv(["tests/test_z.py", "tests/test_a.py"])
    assert argv.index("tests/test_z.py") < argv.index("tests/test_a.py")


def test_edge_prune_covers_the_shard_records(tmp_path):
    old = gc.write_shard_record(tmp_path, "a" * 64, 1, 2, ["tests/test_a.py"], 1000.0)
    os.utime(old, (1000.0, 1000.0))
    removed = gc.prune(tmp_path, 1000.0 + gc.MAX_AGE + 10)
    assert old in removed and not old.exists(), removed


# ── one shard's run: records and the stamp ─────────────────────────────────


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "t"
    (root / "scripts/tests").mkdir(parents=True)
    (root / ".githooks").mkdir()
    git(root, "init", "-q", ".")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    git(root, "config", "commit.gpgsign", "false")
    for f in FIVE:
        (root / "scripts" / f).write_text("def test_one():\n    pass\n")
    (root / ".githooks/pre-commit").write_text("# a hook\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    return root


class Runner:
    """Stands in for pytest: records each command, answers with `rc`."""

    def __init__(self, rc=0, during=None):
        self.calls = []
        self.rc = rc
        self.during = during

    def __call__(self, argv, cwd, env, budget):
        self.calls.append(list(argv))
        if self.during:
            self.during()
        return self.rc(len(self.calls)) if callable(self.rc) else self.rc


def shard(tree, index, count, runner=None, **env):
    lines = []
    rc = gc.script_test_shard(tree, clean_env(**env), tree / ".githooks/pre-commit", index, count,
                              run=runner or Runner(), log=lines.append)
    return rc, "\n".join(lines)


def hook_key(tree, **env):
    snap = gc.snapshot(tree, clean_env(**env), str(tree / ".githooks/pre-commit"))
    return gc.script_tests_key(snap)


def stamped(tree, **env):
    return gc.valid_stamp(tree / ".git" / gc.STAMP_DIR, "pre-commit", "script-tests", hook_key(tree, **env), time.time())


def test_success_all_shards_passing_writes_the_hooks_stamp(tree):
    for i in (1, 2, 3):
        rc, out = shard(tree, i, 3)
        assert rc == 0, out
    record = stamped(tree)
    assert record is not None, "every shard passed on this tree: the hook's stamp is there"
    assert record["summary"]["shards"] == 3, record


def test_success_the_stamp_is_under_the_key_the_hook_computes(tree):
    for i in (1, 2):
        assert shard(tree, i, 2)[0] == 0
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts/gate-cache.py"), "keys", "pre-commit",
         "--hook-file", str(tree / ".githooks/pre-commit")],
        cwd=tree, env=clean_env(), capture_output=True, text=True, timeout=120, check=True,
    )
    key = dict(line.split(" ", 1) for line in out.stdout.splitlines() if not line.startswith("info"))["script-tests"]
    hit = subprocess.run(
        [sys.executable, str(REPO / "scripts/gate-cache.py"), "hit", "pre-commit", "script-tests", key],
        cwd=tree, env=clean_env(), capture_output=True, text=True, timeout=120,
    )
    assert hit.returncode == 0, "gate_hit finds the stamp the shards wrote: " + hit.stdout + hit.stderr


def test_success_each_shard_runs_its_planned_files_only(tree):
    runner = Runner()
    plan = gc.plan_shards(gc.script_test_files(tree), gc.read_durations(tree), 2)
    shard(tree, 2, 2, runner)
    assert runner.calls[0][: len(gc.shard_argv(plan[1]))] == gc.shard_argv(plan[1]), runner.calls


def test_success_the_shards_may_pass_in_any_order(tree):
    for i in (3, 1, 2):
        assert shard(tree, i, 3)[0] == 0
    assert stamped(tree) is not None


def test_success_a_shard_writes_a_junit_report_in_the_git_dir(tree):
    runner = Runner()
    shard(tree, 1, 2, runner)
    argv = runner.calls[0]
    report = pathlib.Path(argv[argv.index("--junitxml") + 1])
    assert report.parent == (tree / ".git").resolve() and report.name == "sipnab-script-tests-shard-1-of-2.xml"
    assert "junit_family=xunit1" in argv, argv


def test_failure_one_failing_shard_writes_no_stamp(tree):
    assert shard(tree, 1, 3)[0] == 0
    rc, out = shard(tree, 2, 3, Runner(rc=1))
    assert rc == 1 and "FAILED" in out, out
    assert shard(tree, 3, 3)[0] == 0
    assert stamped(tree) is None, "shard 2 failed: no stamp"


def test_failure_a_failed_shard_leaves_no_record(tree):
    shard(tree, 1, 2, Runner(rc=1))
    plan = gc.plan_shards(gc.script_test_files(tree), {}, 2)
    assert gc.missing_shards(tree / ".git" / gc.STAMP_DIR, hook_key(tree), plan, time.time()) == [1, 2]


def test_failure_a_missing_shard_writes_no_stamp_and_is_named(tree):
    assert shard(tree, 1, 3)[0] == 0
    rc, out = shard(tree, 3, 3)
    assert rc == 0 and "still to pass: 2" in out, out
    assert stamped(tree) is None


def test_failure_a_shard_from_another_tree_is_not_reused(tree):
    assert shard(tree, 1, 2)[0] == 0
    (tree / "scripts/tests/test_a.py").write_text("def test_two():\n    pass\n")
    git(tree, "add", "scripts/tests/test_a.py")
    rc, out = shard(tree, 2, 2)
    assert rc == 0 and "still to pass: 1" in out, out
    assert stamped(tree) is None, "shard 1 passed on another tree"


def test_failure_a_shard_whose_inputs_changed_while_it_ran_records_nothing(tree):
    def edit():
        (tree / "scripts/tests/test_b.py").write_text("def test_x():\n    pass\n")

    rc, out = shard(tree, 1, 1, Runner(during=edit))
    assert rc == 1 and "changed while" in out, out
    assert stamped(tree) is None


def test_failure_shards_of_two_plans_do_not_combine(tree):
    assert shard(tree, 1, 2)[0] == 0
    assert shard(tree, 2, 3)[0] == 0
    assert shard(tree, 3, 3)[0] == 0
    assert stamped(tree) is None, "shard 1/2 is not shard 1/3"


def test_failure_a_record_naming_other_files_is_not_counted(tree):
    key = hook_key(tree)
    directory = tree / ".git" / gc.STAMP_DIR
    plan = gc.plan_shards(gc.script_test_files(tree), {}, 2)
    gc.write_shard_record(directory, key, 1, 2, ["tests/test_other.py"], time.time())
    assert 1 in gc.missing_shards(directory, key, plan, time.time())


def test_failure_a_damaged_record_is_not_counted(tree):
    key = hook_key(tree)
    directory = tree / ".git" / gc.STAMP_DIR
    plan = gc.plan_shards(gc.script_test_files(tree), {}, 1)
    path = gc.write_shard_record(directory, key, 1, 1, plan[0], time.time())
    record = json.loads(path.read_text())
    record["summary"]["files"] = []
    path.write_text(json.dumps(record))
    assert gc.missing_shards(directory, key, plan, time.time()) == [1]


def test_failure_a_shard_that_ran_past_its_budget_fails(tree):
    rc, out = shard(tree, 1, 1, Runner(rc=124))
    assert rc == 124 and "FAILED" in out, out
    assert stamped(tree) is None


def test_failure_a_tree_without_script_tests_is_refused(tmp_path):
    git(tmp_path, "init", "-q", ".")
    (tmp_path / ".githooks").mkdir()
    (tmp_path / ".githooks/pre-commit").write_text("# a hook\n")
    lines = []
    rc = gc.script_test_shard(tmp_path, clean_env(), tmp_path / ".githooks/pre-commit", 1, 1,
                              run=Runner(), log=lines.append)
    assert rc == 2 and "no script test" in "\n".join(lines), lines


def test_edge_a_shard_on_a_stamped_tree_runs_nothing(tree):
    for i in (1, 2):
        shard(tree, i, 2)
    runner = Runner()
    rc, out = shard(tree, 1, 2, runner)
    assert rc == 0 and runner.calls == [] and "already" in out, out


def test_edge_no_cache_runs_a_shard_on_a_stamped_tree(tree):
    for i in (1, 2):
        shard(tree, i, 2)
    runner = Runner()
    assert shard(tree, 1, 2, runner, SIPNAB_GATE_NO_CACHE="1")[0] == 0
    assert len(runner.calls) == 1, "SIPNAB_GATE_NO_CACHE=1 runs every step"


def test_edge_the_same_shard_twice_is_not_two_shards(tree):
    shard(tree, 1, 2)
    rc, out = shard(tree, 1, 2)
    assert "still to pass: 2" in out, out
    assert stamped(tree) is None


def test_edge_a_shard_report_leaves_the_tree_and_its_key_as_they_were(tree):
    before = hook_key(tree)
    shard(tree, 1, 2)
    assert hook_key(tree) == before
    assert git(tree, "status", "--porcelain") == ""


def test_edge_a_one_shard_plan_stamps_at_once(tree):
    rc, out = shard(tree, 1, 1)
    assert rc == 0 and stamped(tree) is not None, out


# ── the runner: a session of its own, ended whole ──────────────────────────


def test_success_the_runner_answers_the_commands_status(tmp_path):
    assert gc.run_in_session(["sh", "-c", "exit 3"], tmp_path, clean_env(), 30) == 3


def gone(pid, deadline):
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_failure_a_run_past_its_budget_ends_the_whole_session(tmp_path):
    pidfile = tmp_path / "pid"
    argv = ["sh", "-c", f'sleep 60 & echo $! > "{pidfile}"; wait']
    t0 = time.monotonic()
    assert gc.run_in_session(argv, tmp_path, clean_env(), 1) == 124
    assert time.monotonic() - t0 < 30
    pid = int(pidfile.read_text())
    try:
        assert gone(pid, time.monotonic() + 15), f"child {pid} outlived the budget"
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_edge_a_runner_ended_by_a_signal_ends_its_session(tmp_path):
    pidfile = tmp_path / "pid"
    program = tmp_path / "runner.py"
    program.write_text(
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('gc_runner', {str(REPO / 'scripts/gate-cache.py')!r})\n"
        "gc = importlib.util.module_from_spec(spec)\n"
        "sys.modules['gc_runner'] = gc\n"
        "spec.loader.exec_module(gc)\n"
        f"argv = ['sh', '-c', 'sleep 60 & echo $! > {pidfile}; wait']\n"
        "sys.exit(gc.run_in_session(argv, '.', None, 120))\n"
    )
    proc = subprocess.Popen([sys.executable, str(program)], cwd=tmp_path, env=clean_env())
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and pidfile.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(0.1)
        pid = int(pidfile.read_text())
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) != 0
        try:
            assert gone(pid, time.monotonic() + 15), f"child {pid} outlived its runner"
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ── pin-gates.py's options ──────────────────────────────────────────────────


def test_success_pin_gates_runs_the_named_shard(monkeypatch):
    seen = []
    monkeypatch.setattr(pg, "run_script_test_shard", lambda index, count, budget: seen.append((index, count)) or 0)
    assert pg.main(["--script-tests", "--shard", "2/3"]) == 0
    assert seen == [(2, 3)]


def test_edge_pin_gates_script_tests_alone_is_one_shard_of_one(monkeypatch):
    seen = []
    monkeypatch.setattr(pg, "run_script_test_shard", lambda index, count, budget: seen.append((index, count)) or 0)
    assert pg.main(["--script-tests"]) == 0
    assert seen == [(1, 1)]


def test_failure_pin_gates_shard_without_script_tests_is_refused(capsys):
    with pytest.raises(SystemExit) as e:
        pg.main(["--shard", "1/2"])
    assert e.value.code == 2 and "--shard goes with --script-tests" in capsys.readouterr().err


def test_failure_pin_gates_refuses_a_bad_shard_spec(capsys):
    with pytest.raises(SystemExit) as e:
        pg.main(["--script-tests", "--shard", "3/2"])
    err = capsys.readouterr().err
    assert e.value.code == 2 and "argument --shard" in err and "3/2" in err, err


# ── the durations, from pytest's own timing ─────────────────────────────────


def test_success_a_real_shard_report_gives_each_files_duration(pre):  # noqa: F811
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    (pre.tree / "scripts/tests/test_other.py").write_text("def test_y():\n    pass\n")
    git(pre.tree, "add", "scripts/tests")
    git(pre.tree, "commit", "-qm", "two")
    lines = []
    rc = gc.script_test_shard(pre.tree, pre.env(SIPNAB_HOOK_ANY_TREE="1"), pre.hook, 1, 1, log=lines.append)
    assert rc == 0, lines
    report = pre.tree / ".git/sipnab-script-tests-shard-1-of-1.xml"
    got = gc.durations_from_junit([report.read_text()], gc.script_test_files(pre.tree))
    assert sorted(got) == ["tests/test_other.py", "tests/test_probe.py"], got


def test_success_the_durations_command_writes_the_file_the_plan_reads(tree):
    xml = tree / ".git/r.xml"
    xml.write_text('<testsuites><testsuite><testcase file="test_a.py" name="t" time="7.5"/>'
                   '</testsuite></testsuites>')
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts/gate-cache.py"), "script-test-durations", str(xml)],
        cwd=tree, env=clean_env(), capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert gc.read_durations(tree) == {"tests/test_a.py": 7.5}


# ── the hook and the pre-check skip on the shards' stamp ───────────────────


def two_probe_files(sb):
    runs, body = counting_test(sb)
    add_script_test(sb, body, commit=False)
    (sb.tree / "scripts/tests/test_probe2.py").write_text(body.replace("test_x", "test_y"))
    git(sb.tree, "add", "scripts/tests")
    git(sb.tree, "commit", "-qm", "two script tests")
    return runs


def run_shards(sb, count):
    for i in range(1, count + 1):
        lines = []
        rc = gc.script_test_shard(sb.tree, sb.env(SIPNAB_HOOK_ANY_TREE="1"), sb.hook, i, count, log=lines.append)
        assert rc == 0, lines


def test_success_the_precheck_skips_the_script_tests_the_shards_passed(pre):  # noqa: F811
    runs = two_probe_files(pre)
    stage(pre, "src/lib.rs", "pub fn a() {}\n")
    run_shards(pre, 2)
    assert runs_of(runs) == 2, "each shard ran its file"
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "Script tests... CACHED" in out, out
    assert runs_of(runs) == 2, "the pre-check ran them no second time"


def test_success_the_hook_skips_the_script_tests_the_shards_passed(pre):  # noqa: F811
    runs = two_probe_files(pre)
    stage(pre, "src/lib.rs", "pub fn a() {}\n")
    run_shards(pre, 2)
    rc, out = pre.run()
    assert rc == 0, out
    assert "Script tests... CACHED" in out, out
    assert runs_of(runs) == 2, "the commit ran them no second time"


def test_failure_the_hook_runs_them_when_one_shard_is_missing(pre):  # noqa: F811
    runs = two_probe_files(pre)
    stage(pre, "src/lib.rs", "pub fn a() {}\n")
    lines = []
    assert gc.script_test_shard(pre.tree, pre.env(SIPNAB_HOOK_ANY_TREE="1"), pre.hook, 1, 2, log=lines.append) == 0
    rc, out = pre.run()
    assert rc == 0, out
    assert "Script tests... OK" in out, out
    assert runs_of(runs) == 3, "one shard, then the whole run in the hook"
