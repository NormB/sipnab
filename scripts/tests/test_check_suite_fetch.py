# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Every job that runs the test suite fetches every platform's crates first.

tests/release_pipeline_gate_test.rs runs `cargo tree --offline --target all`,
which needs the crates of every platform in the local registry. A build
downloads only the host's. On main b8700e3f2 (CI run 44155082565, attempt 2)
the macOS cargo cache missed after a Cargo.lock change, and macOS shard 2
failed with "failed to download `alsa v0.11.0` ... --offline was specified".
scripts/check-suite-fetch.py holds the rule; these tests hold the script
(success, failure and edge cases) and the repository's own workflows.
"""

import pathlib
import subprocess
import sys

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sf = load("check-suite-fetch")

FETCH = """\
      - name: Fetch every platform's crates
        run: cargo fetch --locked
"""
SUITE = """\
      - name: Test
        run: |
          python3 scripts/parallel-tests.py --shard-index 0 --shard-count 2 -- --all-features
"""
RESTORE = """\
      - name: Restore the cargo cache
        uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6
        with:
          path: |
            ~/.cargo/registry
            target
"""
CHECKOUT = """\
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
"""


def workflow(*job_bodies: tuple[str, str], extra: str = "") -> str:
    out = "name: CI\non:\n  push:\njobs:\n"
    for job_id, steps in job_bodies:
        out += f"  {job_id}:\n    runs-on: ubuntu-24.04\n    steps:\n{steps}"
    return out + extra


def step(text: str):
    return sf.Step(text)


# ── success: the parser and the predicates see what is there ──────────


def test_success_jobs_lists_each_job_by_id():
    wf = workflow(("a", CHECKOUT), ("b", FETCH))
    assert list(sf.jobs(wf)) == ["a", "b"], "both job ids, in file order"


def test_success_jobs_splits_steps():
    wf = workflow(("a", CHECKOUT + FETCH + SUITE))
    assert len(sf.jobs(wf)["a"]) == 3, "three steps in job a"


def test_success_step_name_reads_the_name():
    wf = workflow(("a", FETCH))
    assert sf.step_name(sf.jobs(wf)["a"][0]) == "Fetch every platform's crates"


def test_success_step_name_falls_back_to_uses():
    wf = workflow(("a", CHECKOUT))
    assert sf.step_name(sf.jobs(wf)["a"][0]).startswith("actions/checkout@"), "unnamed step named by uses"


def test_success_parallel_tests_shard_runs_the_suite():
    assert sf.runs_suite(step(SUITE)), "a parallel-tests.py shard is the suite"


def test_success_llvm_cov_collect_runs_the_suite():
    s = step("      - name: Collect coverage\n        run: |\n          cargo llvm-cov --all-features --workspace --no-report -- $SKIPS\n")
    assert sf.runs_suite(s), "cargo llvm-cov collecting is the suite"


def test_success_feature_matrix_runs_the_suite():
    s = step("      - name: Lint\n        run: env -u X python3 scripts/check-feature-matrix.py --group 1 --pool overflow\n")
    assert sf.runs_suite(s), "check-feature-matrix.py runs suite combinations"


def test_success_inline_fetch_is_a_fetch():
    assert sf.fetches_all_targets(step(FETCH)), "run: cargo fetch --locked"


def test_success_block_fetch_is_a_fetch():
    s = step("      - name: Fetch\n        run: |\n          cargo fetch --locked\n")
    assert sf.fetches_all_targets(s), "a run block holding cargo fetch --locked"


def test_success_cache_restore_restores_the_registry():
    assert sf.restores_registry(step(RESTORE)), "actions/cache/restore with ~/.cargo/registry"


def test_success_full_cache_action_restores_the_registry():
    s = step(RESTORE.replace("actions/cache/restore@", "actions/cache@"))
    assert sf.restores_registry(s), "actions/cache also restores"


def test_success_fetch_before_suite_passes():
    assert sf.violations(workflow(("t", CHECKOUT + FETCH + SUITE)), "ci.yml") == [], "fetch then suite"


def test_success_restore_then_fetch_then_suite_passes():
    wf = workflow(("t", CHECKOUT + RESTORE + FETCH + SUITE))
    assert sf.violations(wf, "ci.yml") == [], "restore, fetch, suite"


def test_success_job_without_suite_needs_no_fetch():
    assert sf.violations(workflow(("lint", CHECKOUT)), "ci.yml") == [], "no suite, no rule"


def test_success_alias_job_inherits_the_fetch():
    wf = (
        "name: CI\njobs:\n  test:\n    runs-on: x\n    steps: &test-steps\n"
        + CHECKOUT + FETCH + SUITE
        + "  test-macos:\n    runs-on: macos-26\n    steps: *test-steps\n"
    )
    got = sf.jobs(wf)
    assert len(got["test-macos"]) == 3, "the alias brings the anchor's three steps"
    assert sf.violations(wf, "ci.yml") == [], "both jobs fetch first"


def test_success_main_passes_on_good_workflows(tmp_path):
    p = tmp_path / "ci.yml"
    p.write_text(workflow(("t", FETCH + SUITE)))
    assert sf.main([str(p)]) == 0, "exit 0 when every suite job fetches"


# ── failure: what the rule refuses ───────────────────────────────────


def test_failure_suite_without_fetch_is_refused():
    v = sf.violations(workflow(("t", CHECKOUT + SUITE)), "ci.yml")
    assert len(v) == 1 and "ci.yml" in v[0] and "t" in v[0] and "Test" in v[0], f"one violation naming file, job, step: {v}"


def test_failure_fetch_after_suite_is_refused():
    v = sf.violations(workflow(("t", SUITE + FETCH)), "ci.yml")
    assert len(v) == 1, f"fetch after the suite does not count: {v}"


def test_failure_fetch_before_restore_is_refused():
    v = sf.violations(workflow(("t", FETCH + RESTORE + SUITE)), "ci.yml")
    assert len(v) == 1 and "restore" in v[0], f"a restore after the fetch can replace the registry: {v}"


def test_failure_fetch_with_target_is_not_a_fetch():
    s = step("      - name: Fetch\n        run: cargo fetch --locked --target x86_64-unknown-linux-gnu\n")
    assert not sf.fetches_all_targets(s), "--target limits the fetch to one platform"


def test_failure_fetch_without_locked_is_not_a_fetch():
    s = step("      - name: Fetch\n        run: cargo fetch\n")
    assert not sf.fetches_all_targets(s), "without --locked the fetch may move Cargo.lock"


def test_failure_commented_fetch_is_not_a_fetch():
    s = step("      - name: Fetch\n        run: |\n          # cargo fetch --locked\n          true\n")
    assert not sf.fetches_all_targets(s), "a comment fetches nothing"


def test_failure_echoed_fetch_is_not_a_fetch():
    s = step("      - name: Fetch\n        run: echo cargo fetch --locked\n")
    assert not sf.fetches_all_targets(s), "echo prints, it does not fetch"


def test_failure_fetch_in_another_job_does_not_count():
    wf = workflow(("prep", FETCH), ("t", SUITE))
    v = sf.violations(wf, "ci.yml")
    assert len(v) == 1 and "t" in v[0], f"each job runs on its own machine: {v}"


def test_failure_alias_job_without_fetch_is_refused_once_per_job():
    wf = (
        "name: CI\njobs:\n  test:\n    runs-on: x\n    steps: &test-steps\n"
        + CHECKOUT + SUITE
        + "  test-macos:\n    runs-on: macos-26\n    steps: *test-steps\n"
    )
    v = sf.violations(wf, "ci.yml")
    assert len(v) == 2, f"both the anchor job and the alias job: {v}"


def test_failure_main_exits_1_and_names_the_job(tmp_path, capsys):
    p = tmp_path / "ci.yml"
    p.write_text(workflow(("unit", SUITE)))
    assert sf.main([str(p)]) == 1, "exit 1 on a violation"
    assert "unit" in capsys.readouterr().out, "the message names the job"


def test_failure_main_refuses_a_missing_file(tmp_path, capsys):
    assert sf.main([str(tmp_path / "nope.yml")]) == 2, "exit 2 for a file that does not exist"
    assert "nope.yml" in capsys.readouterr().err, "the message names the file"


def test_failure_main_refuses_no_arguments(capsys):
    assert sf.main([]) == 2, "exit 2 with no workflow named"
    assert "usage" in capsys.readouterr().err, "a usage line"


def test_failure_two_suite_steps_one_violation():
    v = sf.violations(workflow(("t", SUITE + SUITE.replace("name: Test", "name: Test again"))), "ci.yml")
    assert len(v) == 1, f"one violation per job, at its first suite step: {v}"


def test_failure_llvm_cov_without_fetch_is_refused():
    cov = "      - name: Collect coverage\n        run: cargo llvm-cov --all-features --workspace --no-report\n"
    assert len(sf.violations(workflow(("coverage", cov)), "quality.yml")) == 1, "coverage needs the fetch too"


def test_failure_feature_matrix_without_fetch_is_refused():
    fm = "      - name: Lint and test\n        run: python3 scripts/check-feature-matrix.py --group 2 --pool overflow\n"
    assert len(sf.violations(workflow(("features", fm)), "ci.yml")) == 1, "feature combinations need the fetch too"


# ── edge: what is not the suite, and odd shapes ──────────────────────


def test_edge_parallel_tests_merge_is_not_the_suite():
    s = step("      - name: Merge\n        run: python3 scripts/parallel-tests.py merge --output o.txt shards/*\n")
    assert not sf.runs_suite(s), "merge reads outputs and runs no test"


def test_edge_llvm_cov_report_is_not_the_suite():
    s = step("      - name: Summary\n        run: cargo llvm-cov report --summary-only\n")
    assert not sf.runs_suite(s), "report reads profiles and runs no test"


def test_edge_installing_llvm_cov_is_not_the_suite():
    s = step("      - name: Install cargo-llvm-cov\n        uses: ./.github/actions/pinned-tool\n        with:\n          tool: cargo-llvm-cov\n")
    assert not sf.runs_suite(s), "installing the tool runs no test"


def test_edge_commented_suite_is_not_the_suite():
    s = step("      - name: Note\n        run: |\n          # python3 scripts/parallel-tests.py --shard-index 0\n          true\n")
    assert not sf.runs_suite(s), "a comment runs nothing"


def test_edge_cache_without_registry_is_not_a_registry_restore():
    s = step("      - uses: actions/cache@55cc # v6\n        with:\n          path: ~/.cache/sipnab-apt\n")
    assert not sf.restores_registry(s), "an apt cache does not touch the cargo registry"


def test_edge_cache_save_is_not_a_restore():
    s = step(RESTORE.replace("actions/cache/restore@", "actions/cache/save@"))
    assert not sf.restores_registry(s), "save writes the cache, it does not change the registry"


def test_edge_restore_after_suite_does_not_matter():
    wf = workflow(("t", FETCH + SUITE + RESTORE))
    assert sf.violations(wf, "ci.yml") == [], "only a restore before the suite can replace the fetched crates"


def test_edge_fetch_with_trailing_comment_is_a_fetch():
    s = step("      - name: Fetch\n        run: cargo fetch --locked # every platform\n")
    assert sf.fetches_all_targets(s), "a trailing comment changes nothing"


def test_edge_jobs_ignores_a_top_level_key_after_jobs():
    wf = workflow(("t", FETCH + SUITE), extra="concurrency:\n  group: x\n")
    assert list(sf.jobs(wf)) == ["t"], "a top-level key after jobs is not a job"


def test_edge_jobs_ignores_comments_between_jobs():
    wf = workflow(("a", FETCH)) + "  # a note about b\n" + "  b:\n    runs-on: x\n    steps:\n" + CHECKOUT
    assert list(sf.jobs(wf)) == ["a", "b"], "a comment at job indent is not a job"


def test_edge_job_without_steps_has_none():
    wf = "name: CI\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n"
    assert sf.jobs(wf) == {"call": []}, "a reusable-workflow call has no steps"


def test_edge_no_jobs_key_gives_nothing():
    assert sf.jobs("name: CI\non: push\n") == {}, "no jobs, no rule"


def test_edge_run_block_with_comment_lines_before_the_suite():
    s = step("      - name: Test\n        run: |\n          set -eu\n          # the shard\n          python3 scripts/parallel-tests.py --shard-index 1 --shard-count 2\n")
    assert sf.runs_suite(s), "the suite line after a comment still counts"


# ── the repository's own workflows ────────────────────────────────────


def repo_workflow(name: str) -> str:
    return (REPO / ".github/workflows" / name).read_text()


def test_repo_ci_every_suite_job_fetches_first():
    assert sf.violations(repo_workflow("ci.yml"), "ci.yml") == [], "ci.yml"


def test_repo_quality_every_suite_job_fetches_first():
    assert sf.violations(repo_workflow("quality.yml"), "quality.yml") == [], "quality.yml"


def test_repo_every_workflow_passes():
    wfs = sorted((REPO / ".github/workflows").glob("*.yml"))
    bad = [v for p in wfs for v in sf.violations(p.read_text(), p.name)]
    assert bad == [], f"every workflow: {bad}"


def test_repo_the_rule_sees_the_suite_jobs():
    ci = sf.jobs(repo_workflow("ci.yml"))
    suite_jobs = {j for j, steps in ci.items() if any(sf.runs_suite(s) for s in steps)}
    assert {"test", "test-macos", "features"} <= suite_jobs, f"the rule must see the jobs it guards: {suite_jobs}"
    q = sf.jobs(repo_workflow("quality.yml"))
    qjobs = {j for j, steps in q.items() if any(sf.runs_suite(s) for s in steps)}
    assert {"coverage", "coverage-branch"} <= qjobs, f"both coverage jobs: {qjobs}"


def test_repo_script_runs_from_the_command_line():
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/check-suite-fetch.py"), *sorted(str(p) for p in (REPO / ".github/workflows").glob("*.yml"))],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, f"the script passes this repository: {r.stdout}{r.stderr}"
