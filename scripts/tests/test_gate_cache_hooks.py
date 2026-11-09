# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The REAL hooks, run against throwaway trees, keep every guarantee with stamps on.

A stamp lets a hook skip a step that already passed on identical inputs. That
is only safe if a tree that would have failed before still fails, so these
tests run .githooks/pre-commit and .githooks/pre-push and observe what they
did: which cargo commands ran (the stub logs every one), what they printed,
which stamps exist afterwards, and the exit status.

The pre-commit sandbox is scripts/lib-hook-sandbox.sh's, the one
scripts/test-pre-commit.sh drives, with its stubs and logs kept OUTSIDE the
tree (SANDBOX_HARNESS_DIR): a stamp covers every file in the tree, and a stub
that rewrote its log inside it would change the tree under every run. The
pre-push sandbox is built here, with its own copy of the hook and stub gates
for everything that is not the cache under test.
"""

import json
import os
import re
import pathlib
import shutil
import signal
import subprocess
import time

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parents[2]
PRE_COMMIT = REPO / ".githooks/pre-commit"
PRE_PUSH = REPO / ".githooks/pre-push"
gc = load("gate-cache")


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def clean_env(**extra):
    """The test's environment without any GIT_* variable a calling hook exported."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    for k in list(env):
        if k.startswith("SIPNAB_GATE_"):
            del env[k]
    env.update(extra)
    return env


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=clean_env(), check=True, capture_output=True, text=True
    ).stdout


class Sandbox:
    """A throwaway tree, its harness directory and how to run a hook in it."""

    def __init__(self, tree: pathlib.Path, harness: pathlib.Path, hook: pathlib.Path):
        self.tree = tree
        self.harness = harness
        self.hook = hook

    def env(self, **extra):
        return clean_env(PATH=f"{self.harness}/bin:{os.environ['PATH']}", **extra)

    def run(self, hook=None, stdin="", own=False, **extra):
        """Run the hook to completion: (exit status, output). Clears the cargo log first."""
        (self.harness / "cargo-invocations").write_text("")
        env = self.env(**extra) if own else self.env(SIPNAB_HOOK_ANY_TREE="1", **extra)
        hook = hook or self.hook
        cmd = ["bash", str(hook)] if hook.name == "pre-commit" else ["sh", str(hook)]
        out = subprocess.run(cmd, cwd=self.tree, env=env, input=stdin, capture_output=True, text=True)
        return out.returncode, ANSI.sub("", out.stdout + out.stderr)

    def cargo(self):
        """The cargo commands the last run made, `--version` probes left out."""
        lines = (self.harness / "cargo-invocations").read_text().splitlines()
        return [line for line in lines if "--version" not in line and not line.endswith(" -V")]

    def stamps(self, worktree_git_dir=None):
        d = pathlib.Path(worktree_git_dir or self.tree / ".git") / gc.STAMP_DIR
        return sorted(p.name.split(".")[1] for p in d.glob("*.json")) if d.is_dir() else []

    def switch(self, name):
        (self.harness / name).write_text("")

    def unswitch(self, name):
        (self.harness / name).unlink(missing_ok=True)


def write_rustc_stub(harness, version="rustc 1.90.0 (stub)\nhost: aarch64-unknown-linux-gnu"):
    (harness / "rustc-version").write_text(version + "\n")
    stub = harness / "bin/rustc"
    stub.write_text(f'#!/bin/sh\necho x >> "{harness}/rustc-calls"\ncat "{harness}/rustc-version"\n')
    stub.chmod(0o755)


@pytest.fixture
def pc(tmp_path):
    """The pre-commit sandbox: one passing binary of two tests."""
    harness = tmp_path / "harness"
    harness.mkdir()
    script = (
        f'REPO_ROOT="{REPO}"; HOOK="{PRE_COMMIT}"; '
        '. "$REPO_ROOT/scripts/lib-git-sandbox.sh"; clear_git_env; '
        '. "$REPO_ROOT/scripts/lib-hook-sandbox.sh"; sandbox 2'
    )
    out = subprocess.run(
        ["sh", "-c", script], env=clean_env(SANDBOX_HARNESS_DIR=str(harness)),
        capture_output=True, text=True, check=True,
    )
    tree = pathlib.Path(out.stdout.strip().splitlines()[-1])
    # The repository ignores bytecode caches (.gitignore); the sandbox has no
    # .gitignore, so say the same in its local exclude file. Without it, the
    # first run's Python gates add scripts/__pycache__ to the tree mid-run.
    with open(tree / ".git/info/exclude", "a") as f:
        f.write("__pycache__/\n")
    write_rustc_stub(harness)
    yield Sandbox(tree, harness, PRE_COMMIT)
    shutil.rmtree(tree, ignore_errors=True)


def junit(*cases):
    """A nextest JUnit report: cases are (binary, test, passed)."""
    suites = {}
    for binary, test, passed in cases:
        suites.setdefault(binary, []).append((test, passed))
    body = []
    for binary, tests in suites.items():
        body.append(f'<testsuite name="{binary}" tests="{len(tests)}">')
        for test, passed in tests:
            inner = "" if passed else '<failure message="boom">panicked at src/x.rs:1:1</failure>'
            body.append(f'<testcase name="{test}" classname="{binary}" time="0.001">{inner}</testcase>')
        body.append("</testsuite>")
    return '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="nextest-run">' + "".join(body) + "</testsuites>\n"


def passed(sb):
    rc, out = sb.run()
    assert rc == 0, out
    return out


# ── pre-commit: the stamp is used for exactly the inputs it was written for ──


def test_a_rerun_on_an_unchanged_tree_prints_one_line_and_runs_nothing(pc):
    passed(pc)
    rc, out = pc.run()
    assert rc == 0, out
    skip = [line for line in out.splitlines() if "PASSED before on these exact inputs" in line]
    assert len(skip) == 1 and "stamp " in skip[0] and "SIPNAB_GATE_NO_CACHE=1" in skip[0], out
    assert "Running pre-commit checks" not in out
    assert pc.cargo() == [], pc.cargo()


def test_the_first_pass_stamps_every_cached_step(pc):
    out = passed(pc)
    assert pc.stamps() == ["bpf-types", "clippy", "hook", "tests"], pc.stamps()
    assert "Pass stamp " in out and "written" in out


def test_a_stamp_from_tree_a_is_never_used_for_tree_b(pc):
    passed(pc)
    (pc.tree / "src/lib.rs").write_text("pub fn prod() -> u8 { 2 }\n")
    git(pc.tree, "add", "src/lib.rs")
    rc, out = pc.run()
    assert rc == 0, out
    assert "PASSED before" not in out
    assert any(c.startswith("clippy") for c in pc.cargo()), pc.cargo()
    assert any(c.startswith("nextest run --profile suite") for c in pc.cargo()), pc.cargo()


def test_returning_to_tree_a_reuses_tree_a_stamp(pc):
    passed(pc)
    original = (pc.tree / "src/lib.rs").read_text()
    (pc.tree / "src/lib.rs").write_text("pub fn prod() -> u8 { 2 }\n")
    passed(pc)
    (pc.tree / "src/lib.rs").write_text(original)
    rc, out = pc.run()
    assert rc == 0 and "PASSED before on these exact inputs" in out, out


def test_an_unstaged_edit_with_the_same_index_is_a_full_run(pc):
    passed(pc)
    (pc.tree / "src/lib.rs").write_text("pub fn prod() -> u8 { 3 }\n")
    rc, out = pc.run()
    assert "PASSED before" not in out and any(c.startswith("clippy") for c in pc.cargo()), out


def test_a_new_untracked_test_file_is_a_full_run(pc):
    passed(pc)
    (pc.tree / "tests").mkdir(exist_ok=True)
    (pc.tree / "tests/new_test.rs").write_text("#[test]\nfn t() {}\n")
    rc, out = pc.run()
    assert "PASSED before" not in out and any(c.startswith("nextest run") for c in pc.cargo()), out


def test_a_cargo_lock_change_is_a_full_run(pc):
    # The sandbox's Cargo.lock is one scripts/check-lockfile-drift.py accepts
    # (gate 3c); the change keeps every package and adds a line.
    lock = (pc.tree / "Cargo.lock").read_text()
    passed(pc)
    (pc.tree / "Cargo.lock").write_text(lock + "# another resolution\n")
    git(pc.tree, "add", "Cargo.lock")
    rc, out = pc.run()
    assert "PASSED before" not in out and any(c.startswith("clippy") for c in pc.cargo()), out


def test_a_toolchain_change_is_a_full_run(pc):
    passed(pc)
    write_rustc_stub(pc.harness, "rustc 1.91.0 (stub)\nhost: aarch64-unknown-linux-gnu")
    rc, out = pc.run()
    assert "PASSED before" not in out and any(c.startswith("clippy") for c in pc.cargo()), out


def own_hook(sb):
    """Install the hook as the sandbox's own, with what it resolves beside it."""
    (sb.tree / ".githooks").mkdir(exist_ok=True)
    shutil.copy(PRE_COMMIT, sb.tree / ".githooks/pre-commit")
    shutil.copy(REPO / "scripts/check-rustfmt.sh", sb.tree / "scripts/check-rustfmt.sh")
    shutil.copy(REPO / ".rustfmt-toolchain", sb.tree / ".rustfmt-toolchain")
    git(sb.tree, "add", "-A")
    git(sb.tree, "commit", "-qm", "own hook")
    return sb.tree / ".githooks/pre-commit"


def test_a_changed_hook_script_is_a_full_run(pc):
    hook = own_hook(pc)
    rc, out = pc.run(hook=hook, own=True)
    assert rc == 0, out
    with open(hook, "a") as f:
        f.write("# one more line\n")
    rc, out = pc.run(hook=hook, own=True)
    assert rc == 0 and "PASSED before" not in out, out
    assert any(c.startswith("clippy") for c in pc.cargo()), out


def test_a_changed_script_the_hook_calls_is_a_full_run(pc):
    hook = own_hook(pc)
    pc.run(hook=hook, own=True)
    with open(pc.tree / "scripts/parallel-tests.py", "a") as f:
        f.write("# changed\n")
    rc, out = pc.run(hook=hook, own=True)
    assert "PASSED before" not in out and any(c.startswith("nextest run") for c in pc.cargo()), out


def test_a_failed_step_writes_no_stamp_for_itself_or_the_hook(pc):
    pc.switch("fail-clippy")
    rc, out = pc.run()
    assert rc != 0, out
    assert "clippy" not in pc.stamps() and "hook" not in pc.stamps(), pc.stamps()


def test_a_failed_suite_writes_no_suite_or_hook_stamp(pc):
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", False), ("sipnab::bin1", "t2", True)))
    rc, out = pc.run()
    assert rc != 0, out
    assert "tests" not in pc.stamps() and "hook" not in pc.stamps(), pc.stamps()
    assert "clippy" in pc.stamps(), "clippy passed before the suite failed, and its stamp stands"


def test_a_failed_run_is_not_skipped_the_next_time(pc):
    pc.switch("fail-clippy")
    pc.run()
    rc, out = pc.run()
    assert rc != 0 and "PASSED before" not in out, out


def test_a_corrupt_stamp_means_a_full_run(pc):
    passed(pc)
    for p in (pc.tree / ".git" / gc.STAMP_DIR).glob("*.json"):
        p.write_text('{"truncated": ')
    rc, out = pc.run()
    assert rc == 0 and "PASSED before" not in out and "CACHED" not in out, out
    assert any(c.startswith("clippy") for c in pc.cargo())


def test_no_cache_forces_a_full_run_and_still_stamps(pc):
    passed(pc)
    for p in (pc.tree / ".git" / gc.STAMP_DIR).glob("*.json"):
        p.unlink()
    rc, out = pc.run(SIPNAB_GATE_NO_CACHE="1")
    assert rc == 0 and "IGNORED (SIPNAB_GATE_NO_CACHE=1)" in out, out
    assert any(c.startswith("clippy") for c in pc.cargo())
    assert "hook" in pc.stamps()
    rc, out = pc.run(SIPNAB_GATE_NO_CACHE="1")
    assert "PASSED before" not in out and any(c.startswith("clippy") for c in pc.cargo()), out


def test_a_docs_only_change_reuses_the_build_stamps_and_runs_the_suite(pc):
    passed(pc)
    (pc.tree / "docs/guide.md").write_text("# Guide\n")
    git(pc.tree, "add", "docs/guide.md")
    rc, out = pc.run()
    assert rc == 0, out
    assert "Staged change: no build input" in out, out
    calls = pc.cargo()
    assert not any(c.startswith("clippy") for c in calls), calls
    assert not any(c.startswith("test -p sipnab-bpf-types") for c in calls), calls
    assert any(c.startswith("nextest run --profile suite") for c in calls), calls
    assert out.count("CACHED (passed on these inputs") == 2, out


def test_a_cache_that_cannot_compute_keys_runs_everything_and_says_so(pc):
    hook = own_hook(pc)
    (pc.tree / "scripts/gate-cache.py").write_text("import sys\nsys.exit(3)\n")
    rc, out = pc.run(hook=hook, own=True)
    assert rc == 0, out
    assert "Pass stamps... NOT USED -- scripts/gate-cache.py could not read the inputs" in out, out
    assert any(c.startswith("clippy") for c in pc.cargo())
    assert pc.stamps() == []


def test_an_edit_during_the_run_leaves_no_stamp(pc):
    (pc.harness / "sleep-nextest").write_text("3")
    proc = subprocess.Popen(
        ["bash", str(PRE_COMMIT)], cwd=pc.tree, env=pc.env(SIPNAB_HOOK_ANY_TREE="1"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    log = pc.harness / "cargo-invocations"
    deadline = time.time() + 120
    while "nextest run" not in log.read_text() and time.time() < deadline:
        time.sleep(0.1)
    (pc.tree / "src/lib.rs").write_text("pub fn prod() -> u8 { 9 }\n")
    out, _ = proc.communicate(timeout=300)
    assert proc.returncode == 0, out
    assert "No pass stamp for tests: its inputs changed while it ran." in out, out
    assert "tests" not in pc.stamps() and "hook" not in pc.stamps(), pc.stamps()


def test_a_run_killed_mid_way_leaves_no_stamp_for_what_it_did_not_finish(pc):
    (pc.harness / "sleep-nextest").write_text("60")
    proc = subprocess.Popen(
        ["bash", str(PRE_COMMIT)], cwd=pc.tree, env=pc.env(SIPNAB_HOOK_ANY_TREE="1"),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    log = pc.harness / "cargo-invocations"
    deadline = time.time() + 120
    while "nextest run" not in log.read_text() and time.time() < deadline:
        time.sleep(0.1)
    os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=30)
    assert "tests" not in pc.stamps() and "hook" not in pc.stamps(), pc.stamps()
    (pc.harness / "sleep-nextest").unlink()
    rc, out = pc.run()
    assert rc == 0 and any(c.startswith("nextest run") for c in pc.cargo()), out


def test_two_worktrees_get_target_directories_of_their_own(pc):
    """The cargo stub names one workspace root and target directory per tree,
    as two worktrees have. With one shared directory, one hook's parallel-tests.py
    could delete the JUnit report the other hook's stub had just written,
    before the other read it, and that hook failed with "wrote no report"."""
    second = pc.tree.parent / (pc.tree.name + "-wt2")
    git(pc.tree, "worktree", "add", "-q", str(second))
    try:
        dirs = []
        for t in (pc.tree, second):
            out = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--no-deps"],
                cwd=t, env=pc.env(), capture_output=True, text=True, check=True,
            ).stdout
            meta = json.loads(out)
            dirs.append((meta["workspace_root"], meta["target_directory"]))
        assert dirs[0][0] != dirs[1][0], f"both trees share one workspace root: {dirs}"
        assert dirs[0][1] != dirs[1][1], f"both trees share one target directory: {dirs}"
        assert all(d.startswith(str(pc.harness)) for pair in dirs for d in pair), (
            f"the directories stay outside the trees: {dirs}"
        )
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_concurrent_runs_in_two_worktrees_share_valid_stamps_in_the_common_dir(pc):
    second = pc.tree.parent / (pc.tree.name + "-wt2")
    git(pc.tree, "worktree", "add", "-q", str(second))
    try:
        (pc.harness / "sleep-nextest").write_text("2")
        env = pc.env(SIPNAB_HOOK_ANY_TREE="1")
        procs = [
            subprocess.Popen(["bash", str(PRE_COMMIT)], cwd=t, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
            for t in (pc.tree, second)
        ]
        outs = [p.communicate(timeout=300)[0] for p in procs]
        assert all(p.returncode == 0 for p in procs), outs
        wt_git = pathlib.Path(git(second, "rev-parse", "--absolute-git-dir").strip())
        assert wt_git != pc.tree / ".git"
        assert pc.stamps(wt_git) == [], "a stamp landed in the worktree's own git dir"
        assert pc.stamps() == ["bpf-types", "clippy", "hook", "tests"], pc.stamps()
        for t in (pc.tree, second):
            listing = subprocess.run(
                ["python3", str(REPO / "scripts/gate-cache.py"), "list"],
                cwd=t, env=pc.env(), capture_output=True, text=True, check=True,
            ).stdout
            assert "INVALID" not in listing and listing.count("\n") == 4, listing
        (pc.harness / "sleep-nextest").unlink()
        for t in (pc.tree, second):
            out = subprocess.run(["bash", str(PRE_COMMIT)], cwd=t, env=env, capture_output=True, text=True)
            assert "PASSED before on these exact inputs" in out.stdout, out.stdout
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def stub_cargo(pc, tree, *args):
    return subprocess.run([str(pc.harness / "bin/cargo"), *args], cwd=tree, env=pc.env(),
                          capture_output=True, text=True, check=True).stdout


def stub_report(pc, tree):
    """Where parallel-tests.py looks for the suite report, as the stub tells it."""
    meta = json.loads(stub_cargo(pc, tree, "metadata", "--format-version", "1"))
    return pathlib.Path(meta["workspace_root"]) / "target/nextest/suite/junit.xml"


# FLAKY-GATE-CACHE-CONCURRENT. The concurrent test above failed on CI now and
# then (main d73a692ea run 42527410714; #711 run 42570996667) with the second
# worktree's tests step failing. The cause was the stub, not the hook: it gave
# every tree one workspace_root, the shared harness, so both runs'
# parallel-tests.py unlinked, wrote and read ONE junit.xml, and one run's
# unlink could delete the report the other had just written. Real cargo gives
# each worktree its own workspace root. These three hold the stub to that.

def test_two_trees_sharing_one_harness_get_separate_suite_reports(pc):
    second = add_worktree(pc)
    try:
        assert stub_report(pc, pc.tree) != stub_report(pc, second)
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_a_suite_run_in_one_tree_writes_no_report_where_another_tree_reads(pc):
    second = add_worktree(pc)
    try:
        stub_report(pc, second).unlink(missing_ok=True)
        stub_cargo(pc, pc.tree, "nextest", "run", "--profile", "suite")
        assert stub_report(pc, pc.tree).is_file()
        assert not stub_report(pc, second).exists()
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_one_tree_reads_the_report_its_own_run_wrote(pc):
    assert stub_report(pc, pc.tree) == stub_report(pc, pc.tree)
    stub_report(pc, pc.tree).unlink(missing_ok=True)
    stub_cargo(pc, pc.tree, "nextest", "run", "--profile", "suite")
    assert stub_report(pc, pc.tree).read_text().startswith("<")


def add_worktree(pc, name="wt2"):
    second = pc.tree.parent / (pc.tree.name + "-" + name)
    git(pc.tree, "worktree", "add", "-q", str(second))
    return second


def run_in(pc, tree, **extra):
    (pc.harness / "cargo-invocations").write_text("")
    out = subprocess.run(["bash", str(PRE_COMMIT)], cwd=tree, env=pc.env(SIPNAB_HOOK_ANY_TREE="1", **extra),
                         capture_output=True, text=True)
    return out.returncode, ANSI.sub("", out.stdout + out.stderr)


def test_a_new_worktree_reuses_the_stamp_another_worktree_wrote(pc):
    passed(pc)
    second = add_worktree(pc)
    try:
        rc, out = run_in(pc, second)
        assert rc == 0 and "PASSED before on these exact inputs" in out, out
        assert pc.cargo() == [], pc.cargo()
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_another_worktree_with_an_edit_runs_fully(pc):
    passed(pc)
    second = add_worktree(pc)
    try:
        (second / "src/lib.rs").write_text("pub fn prod() -> u8 { 7 }\n")
        rc, out = run_in(pc, second)
        assert "PASSED before" not in out and any(c.startswith("clippy") for c in pc.cargo()), out
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_a_copied_ignored_input_with_new_file_times_still_matches(pc):
    with open(pc.tree / ".git/info/exclude", "a") as f:
        f.write("*.local.md\n")
    (pc.tree / "vectors.local.md").write_text("pinned bytes\n")
    passed(pc)
    second = add_worktree(pc)
    try:
        (second / "vectors.local.md").write_text("pinned bytes\n")
        os.utime(second / "vectors.local.md", (1_000_000_000, 1_000_000_000))
        rc, out = run_in(pc, second)
        assert rc == 0 and "PASSED before on these exact inputs" in out, out
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_other_ignored_content_in_another_worktree_runs_fully(pc):
    with open(pc.tree / ".git/info/exclude", "a") as f:
        f.write("*.local.md\n")
    (pc.tree / "vectors.local.md").write_text("pinned bytes\n")
    passed(pc)
    second = add_worktree(pc)
    try:
        (second / "vectors.local.md").write_text("other bytes!\n")
        rc, out = run_in(pc, second)
        assert "PASSED before" not in out and any(c.startswith("nextest run") for c in pc.cargo()), out
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


def test_the_failed_test_record_stays_with_its_worktree(pc):
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", False), ("sipnab::bin1", "t2", True)))
    pc.run()
    assert (pc.tree / ".git/sipnab-pre-commit-failed-tests.json").exists()
    second = add_worktree(pc)
    try:
        (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", True), ("sipnab::bin1", "t2", True)))
        rc, out = run_in(pc, second)
        assert rc == 0, out
        assert "Tests that failed last run" not in out and not any(" -E " in c for c in pc.cargo()), out
    finally:
        git(pc.tree, "worktree", "remove", "--force", str(second))


# ── pre-commit: the tests that failed last run run first ─────────────────────


def failing_run(pc):
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", False), ("sipnab::bin1", "t2", True)))
    rc, out = pc.run()
    assert rc != 0, out
    return out


def test_a_failed_suite_records_the_tests_it_named(pc):
    out = failing_run(pc)
    record = json.loads((pc.tree / ".git/sipnab-pre-commit-failed-tests.json").read_text())
    assert record["failures"] == [["sipnab::bin1", "t1"]], record
    assert "The next run replays these first" in out, out


def test_the_next_run_replays_the_failures_first_and_stops_at_one(pc):
    failing_run(pc)
    (pc.harness / "canned-replay-junit.xml").write_text(junit(("sipnab::bin1", "t1", False)))
    rc, out = pc.run()
    assert rc != 0, out
    assert "Tests that failed last run, first... " in out and "FAIL" in out, out
    assert "Stopped at the first failure: clippy and the full suite did not run." in out, out
    assert "t1" in out
    calls = pc.cargo()
    nextest = [c for c in calls if c.startswith("nextest run")]
    assert len(nextest) == 1 and "-E (binary_id(=sipnab::bin1) & test(=t1))" in nextest[0], calls
    assert "--fail-fast" in nextest[0] and "--no-tests pass" in nextest[0], nextest
    assert not any(c.startswith("clippy") for c in calls), calls


def test_a_replay_that_passes_goes_on_to_clippy_and_the_full_suite(pc):
    failing_run(pc)
    (pc.harness / "canned-replay-junit.xml").write_text(junit(("sipnab::bin1", "t1", True)))
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", True), ("sipnab::bin1", "t2", True)))
    rc, out = pc.run()
    assert rc == 0, out
    assert "they pass now; the full suite still runs" in out, out
    # Clippy passed in the failing run, on these build inputs, so its stamp
    # stands; the replay still comes before it and before the full suite.
    replay = out.index("Tests that failed last run, first... OK")
    assert replay < out.index("Clippy (CI's exact scope)... CACHED") < out.index("  Tests... OK"), out
    calls = [c for c in pc.cargo() if c.startswith("nextest run")]
    assert len(calls) == 2 and " -E " in calls[0] and " -E " not in calls[1], calls
    assert not (pc.tree / ".git/sipnab-pre-commit-failed-tests.json").exists()


def test_a_replay_that_passes_cannot_hide_a_new_failure_in_the_full_suite(pc):
    failing_run(pc)
    (pc.harness / "canned-replay-junit.xml").write_text(junit(("sipnab::bin1", "t1", True)))
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", True), ("sipnab::bin1", "t2", False)))
    rc, out = pc.run()
    assert rc != 0, out
    record = json.loads((pc.tree / ".git/sipnab-pre-commit-failed-tests.json").read_text())
    assert record["failures"] == [["sipnab::bin1", "t2"]], record


def test_a_corrupt_failure_record_replays_nothing_and_runs_the_suite(pc):
    (pc.tree / ".git/sipnab-pre-commit-failed-tests.json").write_text("{nope")
    rc, out = pc.run()
    assert rc == 0, out
    assert not any(" -E " in c for c in pc.cargo()), pc.cargo()
    assert any(c.startswith("nextest run --profile suite") for c in pc.cargo())


# ── pre-push ────────────────────────────────────────────────────────────────


@pytest.fixture
def pp(tmp_path):
    """A crate with fuzz/ and bpf/, the tls, api and wasm features, and stub gates."""
    tree = tmp_path / "crate"
    harness = tmp_path / "harness"
    for d in (tree / "src", tree / "docs", tree / "fuzz", tree / "bpf", tree / "scripts", tree / ".githooks",
              harness / "bin"):
        d.mkdir(parents=True)
    (tree / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n[features]\ntls = []\napi = []\nwasm = []\n'
    )
    (tree / "src/lib.rs").write_text("pub fn a() {}\n")
    (tree / "docs/a.md").write_text("# A\n")
    shutil.copy(PRE_PUSH, tree / ".githooks/pre-push")
    for name in ("gate-cache.py", "check-hook-prerequisites.py", "fetch-g729-vectors.py",
                 "parallel-tests.py", "check-rustfmt.sh", "tag-push-proof.py"):
        shutil.copy(REPO / "scripts" / name, tree / "scripts" / name)
    shutil.copy(REPO / ".rustfmt-toolchain", tree / ".rustfmt-toolchain")
    log = harness / "cargo-invocations"
    stubs = {
        "scripts/commit-signature-check.sh": "cat >/dev/null; exit 0\n",
        "scripts/commit-message-check.sh": "cat >/dev/null; exit 0\n",
        "scripts/cross-arch-target.sh": "echo x86_64-unknown-linux-gnu\n",
        "scripts/check-non-linux.sh": f'echo "nonlinux" >> "{log}"; [ -f "{harness}/nonlinux-rc" ] && exit "$(cat "{harness}/nonlinux-rc")"; exit 0\n',
        "scripts/check-yang.py": "import sys\nprint('YANG: NOT CHECKED -- stub')\nsys.exit(2)\n",
        "scripts/tag-signature-check.sh": f'echo "tagsig $1" >> "{log}"; echo "tag $1: signed (stub)"\n',
        "scripts/code-scanning-clean.py": f"open('{log}', 'a').write('code-scanning\\n')\n",
        "scripts/prose-gates.sh": (
            "PROSE_PIN=0\nPROSE_REASON=stub\n"
            f'prose_vale_run() {{ PROSE_OUTPUT=$(mktemp); echo "vale" >> "{log}"; return 0; }}\n'
            f'prose_codespell_run() {{ PROSE_OUTPUT=$(mktemp); echo "codespell" >> "{log}"; return 0; }}\n'
        ),
    }
    for rel, body in stubs.items():
        (tree / rel).write_text(("#!/bin/sh\n" if rel.endswith(".sh") else "") + body)
    bins = {
        "cargo": (
            f'echo "$(basename "$PWD") $*" >> "{log}"\n'
            f'for a in "$@"; do [ -f "{harness}/fail-$a" ] && exit 1; done\nexit 0\n'
        ),
        "rustfmt": "exit 0\n",
        "rustup": "printf 'wasm32-unknown-unknown\\nx86_64-unknown-linux-gnu\\n'\n",
        # GitHub, as tag-push-proof.py and the tag CI gate read it. Switch files
        # in the harness: gh-down (every call fails), gh-compare (the compare
        # status, default behind), gh-ci (CI success's conclusion, default
        # success). The jq filter (-q) is ignored: each answer is pre-filtered.
        "gh": (
            f'H="{harness}"\n'
            'echo "gh $*" >> "$H/gh-calls"\n'
            '[ -f "$H/gh-down" ] && exit 1\n'
            'ci=$(cat "$H/gh-ci" 2>/dev/null || echo success)\n'
            'case "$1 $2" in\n'
            '"api repos/o/r/compare/"*) cat "$H/gh-compare" 2>/dev/null || echo behind ;;\n'
            '"api repos/o/r/rules/branches/main") printf "CI success\\nlicense/cla\\n" ;;\n'
            '"api repos/o/r/branches/main/protection") echo "gh: Branch not protected (HTTP 404)"; exit 1 ;;\n'
            '"api repos/o/r/commits/"*"/check-runs"*) printf "CI success\\t2026-11-08T04:00:00Z\\t%s\\n" "$ci" ;;\n'
            '"api repos/o/r/commits/"*"/status") printf "license/cla\\tsuccess\\n" ;;\n'
            '"run list") sha=$(git rev-parse HEAD); '
            'printf \'[{"databaseId":1,"headSha":"%s","status":"completed","conclusion":"success","name":"CI","event":"push"}]\' "$sha" ;;\n'
            '*) exit 1 ;;\n'
            'esac\n'
        ),
    }
    for name, body in bins.items():
        (harness / "bin" / name).write_text("#!/bin/sh\n" + body)
        (harness / "bin" / name).chmod(0o755)
    write_rustc_stub(harness)
    subprocess.run(["git", "init", "-q", "."], cwd=tree, env=clean_env(), check=True)
    git(tree, "config", "user.email", "t@example.com")
    git(tree, "config", "user.name", "t")
    git(tree, "config", "commit.gpgsign", "false")
    git(tree, "config", "tag.gpgsign", "false")
    git(tree, "remote", "add", "origin", "https://github.com/o/r.git")
    with open(tree / ".git/info/exclude", "a") as f:
        f.write("__pycache__/\n")
    git(tree, "add", "-A")
    git(tree, "commit", "-qm", "base")
    git(tree, "tag", "v0.0.1")
    yield Sandbox(tree, harness, tree / ".githooks/pre-push")


BUILD_STEPS = ["bpf-clippy", "check-api", "check-tls", "clippy", "clippy-no-default", "cross-arch", "doc",
               "fuzz-clippy", "non-linux", "wasm"]


def push(sb, **extra):
    head = git(sb.tree, "rev-parse", "HEAD").strip()
    return sb.run(stdin=f"refs/heads/main {head} refs/heads/main {'0' * 40}\n", own=True, **extra)


def cargo_steps(sb):
    """What the last push ran of the cached steps, as the stub logged it."""
    ran = []
    for line in sb.cargo():
        where, _, args = line.partition(" ")
        if args.startswith("clippy --workspace"):
            ran.append("clippy")
        elif args.startswith("doc "):
            ran.append("doc")
        elif where == "fuzz" and args.startswith("clippy"):
            ran.append("fuzz-clippy")
        elif where == "bpf" and args.startswith("clippy"):
            ran.append("bpf-clippy")
        elif args.startswith("check --no-default-features --features"):
            ran.append("check-" + args.split()[3])
        elif args.startswith("clippy --no-default-features"):
            ran.append("clippy-no-default")
        elif args.startswith("check --target"):
            ran.append("wasm")
        elif args.startswith("clippy --target"):
            ran.append("cross-arch")
        elif line in ("nonlinux", "vale", "codespell"):
            ran.append("non-linux" if line == "nonlinux" else line)
    return sorted(ran)


def test_the_first_push_runs_and_stamps_every_cached_step(pp):
    rc, out = push(pp)
    assert rc == 0, out
    assert cargo_steps(pp) == sorted(BUILD_STEPS + ["codespell", "vale"]), pp.cargo()
    assert pp.stamps() == sorted(BUILD_STEPS + ["codespell", "vale"]), pp.stamps()


def test_a_second_push_of_the_same_tree_runs_no_cached_step(pp):
    push(pp)
    rc, out = push(pp)
    assert rc == 0, out
    assert cargo_steps(pp) == [], pp.cargo()
    assert out.count("CACHED (passed on these inputs") == len(BUILD_STEPS) + 2, out
    assert any(line.startswith("crate test --features full --test release_delivery_test") for line in pp.cargo()), (
        "the release-delivery test reads tags and is never cached"
    )


def test_a_source_change_reruns_every_cached_step(pp):
    push(pp)
    (pp.tree / "src/lib.rs").write_text("pub fn b() {}\n")
    git(pp.tree, "commit", "-qam", "change")
    rc, out = push(pp)
    assert rc == 0, out
    assert cargo_steps(pp) == sorted(BUILD_STEPS + ["codespell", "vale"]), pp.cargo()


def test_a_docs_change_reruns_only_the_prose_linters(pp):
    push(pp)
    (pp.tree / "docs/a.md").write_text("# A, revised\n")
    git(pp.tree, "commit", "-qam", "docs")
    rc, out = push(pp)
    assert rc == 0, out
    assert cargo_steps(pp) == ["codespell", "vale"], pp.cargo()


def test_a_push_blocked_at_one_step_keeps_the_stamps_before_it(pp):
    pp.switch("fail-doc")
    rc, out = push(pp)
    assert rc != 0 and "Push blocked: rustdoc" in out, out
    assert "clippy" in pp.stamps() and "doc" not in pp.stamps(), pp.stamps()
    pp.unswitch("fail-doc")
    rc, out = push(pp)
    assert rc == 0, out
    ran = cargo_steps(pp)
    assert "clippy" not in ran and "doc" in ran, ran


def test_a_step_that_could_not_run_is_not_stamped(pp):
    (pp.harness / "nonlinux-rc").write_text("2")
    rc, out = push(pp)
    assert rc == 0, out
    assert "non-linux" not in pp.stamps(), pp.stamps()
    (pp.harness / "nonlinux-rc").unlink()
    push(pp)
    assert "non-linux" in cargo_steps(pp), pp.cargo()


def test_a_failing_build_step_is_never_skipped_on_the_same_tree(pp):
    pp.switch("fail-clippy")
    rc, out = push(pp)
    assert rc != 0, out
    rc, out = push(pp)
    assert rc != 0 and "Push blocked: clippy" in out, out


def test_the_hook_notices_a_finished_suite_within_about_a_second(pc):
    """The watchdog polled every 5 s, so every run waited up to 5 s after the
    suite ended. Against the stub suite the step took 5.3 s with that poll and
    1.3 s with a one-second poll (measured 2026-11-07)."""
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", True)))
    proc = subprocess.Popen(
        ["bash", str(PRE_COMMIT)], cwd=pc.tree, env=pc.env(SIPNAB_HOOK_ANY_TREE="1", SIPNAB_GATE_NO_CACHE="1"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    seen = {}
    for line in proc.stdout:
        line = ANSI.sub("", line)
        for mark in ("Clippy (CI's exact scope)... OK", "Tests... OK"):
            if mark in line:
                seen[mark] = time.monotonic()
    proc.wait(timeout=120)
    assert proc.returncode == 0
    assert seen["Tests... OK"] - seen["Clippy (CI's exact scope)... OK"] < 4.0, seen


def test_a_changed_ignored_input_is_a_full_run(pc):
    """Ignored files the suite reads (the G.729 vectors, backlog.local.md) are inputs too."""
    with open(pc.tree / ".git/info/exclude", "a") as f:
        f.write("*.local.md\n")
    (pc.tree / "docs/backlog.local.md").write_text("- [ ] one\n")
    passed(pc)
    (pc.tree / "docs/backlog.local.md").write_text("- [x] one, and longer\n")
    rc, out = pc.run()
    assert rc == 0 and "PASSED before" not in out, out
    assert any(c.startswith("nextest run --profile suite") for c in pc.cargo()), pc.cargo()


def snapshots(sb):
    """How many snapshots gate-cache.py took: each asks `rustc -Vv` once."""
    calls = sb.harness / "rustc-calls"
    n = len(calls.read_text().splitlines()) if calls.exists() else 0
    calls.unlink(missing_ok=True)
    return n


def test_a_pre_commit_run_takes_one_snapshot_for_its_keys_and_one_for_its_stamps(pc):
    """Each snapshot walks the tree and asks every tool its version. One per
    passing step made test-pre-push.sh run past its 180 s test deadline."""
    snapshots(pc)
    passed(pc)
    assert snapshots(pc) == 2


def test_a_push_takes_one_snapshot_for_its_keys_and_one_for_its_stamps(pp):
    snapshots(pp)
    rc, out = push(pp)
    assert rc == 0, out
    assert snapshots(pp) == 2



# ── pre-push: a push of tags only, of a commit GitHub already proved ─────────


def push_tag(sb, tag="v0.0.1", also=None, **extra):
    sha = git(sb.tree, "rev-parse", tag).strip()
    lines = f"refs/tags/{tag} {sha} refs/tags/{tag} {'0' * 40}\n"
    if also:
        lines += also
    return sb.run(stdin=lines, own=True, **extra)


def test_a_tag_only_push_of_a_proven_commit_skips_the_tree_gates(pp):
    rc, out = push_tag(pp)
    assert rc == 0, out
    assert "tag-only push:" in out and "is on origin/main and passed all 2 required checks" in out, out
    assert cargo_steps(pp) == [], pp.cargo()
    assert "scripts/check-rustfmt.sh ..." not in out


def test_a_tag_only_push_still_runs_the_tag_gates(pp):
    rc, out = push_tag(pp)
    assert rc == 0, out
    log = pp.cargo()
    assert any(line.startswith("tagsig ") for line in log), log
    assert "code-scanning" in log, log
    assert any(line.startswith("crate test --features full --test release_delivery_test") for line in log), log


def test_a_tag_only_push_without_github_runs_every_gate(pp):
    pp.switch("gh-down")
    rc, out = push_tag(pp)
    assert "the full gates run" in out, out
    assert "clippy" in cargo_steps(pp), pp.cargo()


def test_a_tag_on_a_commit_not_on_main_runs_every_gate(pp):
    (pp.harness / "gh-compare").write_text("diverged\n")
    rc, out = push_tag(pp)
    assert "is not on origin/main" in out and "clippy" in cargo_steps(pp), out


def test_a_tag_whose_ci_failed_runs_every_gate(pp):
    (pp.harness / "gh-ci").write_text("failure\n")
    rc, out = push_tag(pp)
    assert "CI success: failure" in out and "clippy" in cargo_steps(pp), out


def test_a_tag_pushed_with_a_branch_runs_every_gate(pp):
    head = git(pp.tree, "rev-parse", "HEAD").strip()
    rc, out = push_tag(pp, also=f"refs/heads/main {head} refs/heads/main {'0' * 40}\n")
    assert rc == 0, out
    assert "the push also updates refs/heads/main" in out and "clippy" in cargo_steps(pp), out


def test_no_cache_makes_a_tag_only_push_run_every_gate(pp):
    rc, out = push_tag(pp, SIPNAB_GATE_NO_CACHE="1")
    assert "clippy" in cargo_steps(pp), out


def test_a_branch_push_never_asks_github_for_a_proof(pp):
    push(pp)
    calls = (pp.harness / "gh-calls").read_text() if (pp.harness / "gh-calls").exists() else ""
    assert "compare" not in calls and "check-runs" not in calls, calls
