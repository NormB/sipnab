# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""When the script tests run: one rule, scripts/gate-cache.py's
`script_tests_needed`, which the hook and the pre-check both call.

On 2026-11-23 a hook run failed in its Script tests step after more than an
hour in the build queue, although the pre-check had passed: the pre-check
left the script tests out. It now runs them whenever the staged change reaches
a path they read. What they read was measured, not assumed: every path the
whole suite opened, by any process, during one full run (inotify over a
worktree, 4638 tests). It opened every tracked file; test_rfc_links,
test_feature_rows_for, test_check_line_drift and test_pin_gates read the Rust
sources themselves. So no path is outside what they read today
(SCRIPT_TESTS_UNREAD is empty), and a Rust-only change runs them too.
The rule is driven here with other unread sets, as an argument, so the branch
that leaves them out is tested although no real path takes it.
"""

import os
import pathlib
import shutil
import signal
import subprocess
import time

import pytest
from conftest import load
from test_gate_cache_hooks import git, pre_commit_sandbox
from test_precheck_hook import PRECHECK, add_source_gate

gc = load("gate-cache")
REPO = pathlib.Path(__file__).resolve().parents[2]


# ── the rule ────────────────────────────────────────────────────────────────


def test_success_a_scripts_change_runs_them():
    assert gc.script_tests_needed(["scripts/gate-cache.py"]), "scripts/ is what they test"


def test_success_a_hook_change_runs_them():
    assert gc.script_tests_needed([".githooks/pre-commit"]), "test_precheck_hook reads the hook"


def test_success_a_rust_source_change_runs_them():
    # Measured: test_feature_rows_for reads every src/**/*.rs for its cfg gates.
    assert gc.script_tests_needed(["src/cli.rs"]), "the script tests read src/"


def test_success_a_test_binary_change_runs_them():
    # Measured: test_pin_gates and test_parallel_tests_nextest read tests/*.rs.
    assert gc.script_tests_needed(["tests/link_integrity_test.rs"]), "the script tests read tests/"


def test_success_a_crate_change_runs_them():
    # Measured: test_publish_crates and test_rfc_links read crates/.
    assert gc.script_tests_needed(["crates/g729/src/lib.rs"]), "the script tests read crates/"


def test_success_a_docs_change_runs_them():
    # test_advertise_release reads docs/install.md (c1223c892, 21537ddd1).
    assert gc.script_tests_needed(["docs/install.md"]), "the script tests read docs/"


def test_success_a_manifest_change_runs_them():
    assert gc.script_tests_needed(["Cargo.toml", "Cargo.lock"]), "test_feature_rows_for reads Cargo.toml"


def test_success_the_measured_unread_set_is_empty():
    # A new prefix here needs a new measurement: see this module's docstring.
    assert gc.SCRIPT_TESTS_UNREAD == (), gc.SCRIPT_TESTS_UNREAD


def test_success_a_change_only_under_an_unread_prefix_leaves_them_out():
    assert not gc.script_tests_needed(["bench/a.json", "bench/b/c.sh"], ("bench/",)), "nothing they read"


def test_edge_an_empty_change_runs_them():
    # Nothing staged: `git commit --amend` with no new change, or a hook run by hand.
    assert gc.script_tests_needed([]), "no change is not proof that nothing they read changed"
    assert gc.script_tests_needed([], ("bench/",)), "an unread set does not make an empty change safe"


def test_edge_one_read_path_among_unread_ones_runs_them():
    assert gc.script_tests_needed(["bench/a.json", "scripts/x.py"], ("bench/",)), "scripts/x.py is read"


def test_edge_a_prefix_matches_on_a_directory_boundary_only():
    assert gc.script_tests_needed(["benchmarks/a.json"], ("bench/",)), "benchmarks/ is not bench/"


def test_edge_a_path_equal_to_the_directory_name_is_read():
    assert gc.script_tests_needed(["bench"], ("bench/",)), "a file named bench is not under bench/"


def test_edge_paths_may_be_any_iterable():
    assert not gc.script_tests_needed(iter(["bench/a"]), ("bench/",)), "a generator is read once, whole"


def test_failure_an_unread_prefix_without_a_slash_is_refused():
    with pytest.raises(ValueError, match="bench"):
        gc.script_tests_needed(["bench/a"], ("bench",))


def test_failure_an_empty_unread_prefix_is_refused():
    with pytest.raises(ValueError, match="empty"):
        gc.script_tests_needed(["scripts/a"], ("",))


def test_failure_an_absolute_unread_prefix_is_refused():
    with pytest.raises(ValueError, match="/bench/"):
        gc.script_tests_needed(["bench/a"], ("/bench/",))


# ── the command the hook calls ──────────────────────────────────────────────


def run_cli(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(
        ["python3", str(REPO / "scripts/gate-cache.py"), "script-tests", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
    )


def repo_with_staged(tmp_path, *paths):
    git(tmp_path, "init", "-q")
    for p in paths:
        f = tmp_path / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x\n")
        git(tmp_path, "add", p)
    return tmp_path


def test_success_the_command_says_run_for_a_named_path(tmp_path):
    out = run_cli(tmp_path, "src/cli.rs")
    assert out.returncode == 0, out
    assert out.stdout.startswith("run:"), out.stdout


def test_success_the_command_reads_the_staged_change(tmp_path):
    out = run_cli(repo_with_staged(tmp_path, "src/a.rs"), )
    assert out.returncode == 0, out
    assert "1 staged path" in out.stdout, out.stdout


def test_success_the_command_exits_one_when_they_are_not_needed(monkeypatch, capsys):
    monkeypatch.setattr(gc, "SCRIPT_TESTS_UNREAD", ("bench/",))
    assert gc.main(["script-tests", "bench/a.json"]) == 1
    assert capsys.readouterr().out.startswith("not needed:"), "the hook prints why it skips"


def test_edge_the_command_with_nothing_staged_says_run(tmp_path):
    out = run_cli(repo_with_staged(tmp_path))
    assert out.returncode == 0, out
    assert "nothing staged" in out.stdout, out.stdout


def test_failure_the_command_outside_a_repository_exits_two(tmp_path):
    out = run_cli(tmp_path)
    assert out.returncode == 2, out
    assert "gate-cache:" in out.stderr, out.stderr


def test_failure_a_bad_unread_set_exits_two_not_one(monkeypatch, capsys):
    monkeypatch.setattr(gc, "SCRIPT_TESTS_UNREAD", ("bench",))
    assert gc.main(["script-tests", "bench/a"]) == 2, "an error must never read as not needed"
    assert "bench" in capsys.readouterr().err


# ── the hook and the pre-check ──────────────────────────────────────────────


@pytest.fixture
def pre(tmp_path):
    with pre_commit_sandbox(tmp_path / "harness") as sb:
        add_source_gate(sb)
        yield sb


def add_script_test(sb, body, commit=True):
    (sb.tree / "scripts/tests").mkdir(exist_ok=True)
    (sb.tree / "scripts/tests/test_probe.py").write_text(body)
    git(sb.tree, "add", "scripts/tests")
    if commit:
        git(sb.tree, "commit", "-qm", "a script test")


def stage(sb, path, text="changed\n"):
    f = sb.tree / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    git(sb.tree, "add", path)


def counting_test(sb):
    """A passing script test that appends a line to a file per run."""
    runs = sb.harness / "script-test-runs"
    return runs, f"def test_x():\n    open({str(runs)!r}, 'a').write('run\\n')\n"


def runs_of(path):
    return len(path.read_text().splitlines()) if path.exists() else 0


def test_success_the_precheck_runs_the_script_tests_for_a_rust_change(pre):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "src/lib.rs", "pub fn a() {}\n")
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "Script tests... OK" in out, out
    assert runs_of(runs) == 1, "the pre-check ran them once"


def test_failure_a_failing_script_test_fails_the_precheck(pre):
    add_script_test(pre, "def test_x():\n    assert False, 'probe'\n")
    stage(pre, "scripts/x.py", "x = 1\n")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert "Script tests... FAIL" in out and "Pre-check passed" not in out, out


def test_success_the_hook_reuses_the_precheck_pass(pre):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "src/lib.rs", "pub fn a() {}\n")
    assert pre.run(**PRECHECK)[0] == 0
    assert "script-tests" in pre.stamps(), pre.stamps()
    rc, out = pre.run()
    assert rc == 0, out
    assert "Script tests... CACHED" in out, out
    assert runs_of(runs) == 1, "the commit did not run them a second time"


def test_success_the_precheck_still_writes_no_suite_or_hook_stamp(pre):
    add_script_test(pre, "def test_x():\n    pass\n")
    stage(pre, "scripts/x.py", "x = 1\n")
    assert pre.run(**PRECHECK)[0] == 0
    assert "tests" not in pre.stamps() and "hook" not in pre.stamps(), pre.stamps()


def test_edge_the_precheck_of_a_tree_without_script_tests_says_so(pre):
    stage(pre, "scripts/x.py", "x = 1\n")
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert "Script tests... NOT RUN (this tree has no scripts/tests)" in out, out


def test_edge_a_precheck_with_a_cached_pass_runs_nothing(pre):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "scripts/x.py", "x = 1\n")
    assert pre.run(**PRECHECK)[0] == 0
    rc, out = pre.run(**PRECHECK)
    assert rc == 0, out
    assert runs_of(runs) == 1, "a stamp on these inputs covers the second pre-check"


def gone(pid, deadline):
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_failure_a_precheck_that_fails_early_ends_the_script_tests(pre):
    pidfile = pre.harness / "probe.pid"
    add_script_test(pre, (
        "import os, time\n"
        "def test_x():\n"
        f"    open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(120)\n"
    ))
    stage(pre, "scripts/x.py", "x = 1\n")
    pre.switch("fail-clippy")
    (pre.harness / "sleep-clippy").write_text("5")
    rc, out = pre.run(**PRECHECK)
    assert rc == 1, out
    assert pidfile.exists(), "the script tests had started before clippy failed"
    pid = int(pidfile.read_text())
    try:
        assert gone(pid, time.monotonic() + 20), f"script test {pid} outlived the pre-check"
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# A copy of the hook beside a gate-cache.py whose unread set is docs/: the
# branch that leaves the script tests out, which no real path takes today.
def hook_with_unread(tmp_path, prefix):
    root = tmp_path / "hookcopy"
    (root / ".githooks").mkdir(parents=True)
    (root / "scripts").mkdir()
    shutil.copy(REPO / ".githooks/pre-commit", root / ".githooks/pre-commit")
    shutil.copy(REPO / "scripts/check-rustfmt.sh", root / "scripts/check-rustfmt.sh")
    shutil.copy(REPO / ".rustfmt-toolchain", root / ".rustfmt-toolchain")
    src = (REPO / "scripts/gate-cache.py").read_text()
    line = "SCRIPT_TESTS_UNREAD: tuple[str, ...] = ()"
    assert src.count(line) == 1, "the unread set's line moved: update this test"
    (root / "scripts/gate-cache.py").write_text(src.replace(line, f"SCRIPT_TESTS_UNREAD: tuple[str, ...] = ({prefix!r},)"))
    return root / ".githooks/pre-commit"


def test_success_the_hook_leaves_them_out_when_the_rule_says_so(pre, tmp_path):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "docs/a.md", "# a\n")
    rc, out = pre.run(hook=hook_with_unread(tmp_path, "docs/"))
    assert "Script tests... NOT RUN (the staged change reaches nothing they read" in out, out
    assert runs_of(runs) == 0, "the rule said not needed"


def test_success_the_precheck_leaves_them_out_by_the_same_rule(pre, tmp_path):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "docs/a.md", "# a\n")
    rc, out = pre.run(hook=hook_with_unread(tmp_path, "docs/"), **PRECHECK)
    assert "Script tests... NOT RUN (the staged change reaches nothing they read" in out, out
    assert runs_of(runs) == 0, "the pre-check did not start them either"


def test_edge_a_change_beside_an_unread_one_runs_them_in_the_hook(pre, tmp_path):
    runs, body = counting_test(pre)
    add_script_test(pre, body)
    stage(pre, "docs/a.md", "# a\n")
    stage(pre, "scripts/x.py", "x = 1\n")
    rc, out = pre.run(hook=hook_with_unread(tmp_path, "docs/"))
    assert "Script tests... OK" in out, out
    assert runs_of(runs) == 1, "scripts/x.py is read"
