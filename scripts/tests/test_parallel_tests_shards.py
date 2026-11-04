# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""CI splits the suite into shards, and every test runs in exactly one.

ci.yml's `test` job runs `scripts/parallel-tests.py --shard-index I
--shard-count N` on N runners at once. Each shard compiles and runs only its
own integration-test targets; one of them also takes the library and binary
unit tests and the doctests. The rule that decides which shard runs what is
`partition` in that script, and these hold it: complete, disjoint and
deterministic, so a new `tests/*.rs` file can never fall between shards.

The last tests run the rule on this repository's real target list, as cargo
reports it, with the shard count ci.yml's matrix gives.
"""

import json
import pathlib
import re
import subprocess

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CI = REPO / ".github/workflows/ci.yml"

pt = load("parallel-tests")

TARGETS = [f"t{i:03}" for i in range(50)]


def flat(shards):
    return [item for shard in shards for item in shard]


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 8])
def test_every_target_and_the_unit_tests_run_in_exactly_one_shard(count):
    shards = pt.partition(TARGETS, count)
    assert len(shards) == count
    items = flat(shards)
    assert sorted(items) == sorted([*TARGETS, pt.UNIT_TESTS])
    assert len(items) == len(set(items)), "a target is in two shards"


def test_the_unit_tests_run_in_the_first_shard():
    shards = pt.partition(TARGETS, 3)
    assert pt.UNIT_TESTS in shards[0]
    assert all(pt.UNIT_TESTS not in s for s in shards[1:])


def test_the_partition_does_not_depend_on_the_input_order():
    assert pt.partition(TARGETS, 4) == pt.partition(list(reversed(TARGETS)), 4)


def test_shards_are_balanced_by_weight():
    weight = pt.UNIT_WEIGHT
    for count in (2, 3, 4):
        loads = [
            sum(weight if t == pt.UNIT_TESTS else 1 for t in shard)
            for shard in pt.partition([f"t{i:03}" for i in range(400)], count)
        ]
        assert max(loads) - min(loads) <= 1, (count, loads)


def test_a_new_target_moves_into_some_shard():
    before = pt.partition(TARGETS, 4)
    after = pt.partition([*TARGETS, "zz_new_test"], 4)
    assert "zz_new_test" in flat(after)
    assert "zz_new_test" not in flat(before)


@pytest.mark.parametrize("count", [0, -1])
def test_a_shard_count_below_one_is_refused(count):
    with pytest.raises(ValueError):
        pt.partition(TARGETS, count)


def test_a_shard_that_would_run_nothing_is_refused():
    # An empty shard would hand cargo no target flags, and `cargo test` with
    # none runs EVERYTHING, so it must be refused rather than built.
    with pytest.raises(ValueError):
        pt.partition(["a"], 3, unit_weight=1)


def test_duplicate_target_names_are_refused():
    with pytest.raises(ValueError):
        pt.partition(["a", "a", "b"], 2)


METADATA = {
    "packages": [
        {
            "name": "sipnab",
            "targets": [
                {"name": "sipnab", "kind": ["lib"]},
                {"name": "sipnab", "kind": ["bin"]},
                {"name": "b_test", "kind": ["test"]},
                {"name": "a_test", "kind": ["test"]},
                {"name": "parser_bench", "kind": ["bench"]},
                {"name": "call_summary", "kind": ["example"]},
            ],
        },
        {"name": "sipnab-g729", "targets": [{"name": "examples", "kind": ["test"]}]},
    ]
}


def test_test_targets_are_the_root_packages_integration_tests():
    assert pt.test_targets(METADATA) == ["a_test", "b_test"]


def test_test_targets_refuses_metadata_without_the_package():
    with pytest.raises(ValueError):
        pt.test_targets({"packages": []})


def test_the_first_shard_runs_the_unit_tests_and_doctests_as_cargo_test_would():
    cmds = pt.shard_commands([pt.UNIT_TESTS, "a_test"], ["--all-features"])
    assert cmds == [
        ["build", "--all-features", "--examples"],
        ["test", "--all-features", "--lib", "--bins", "--test", "a_test"],
        ["test", "--all-features", "--doc"],
    ]


def test_another_shard_runs_only_its_integration_tests():
    cmds = pt.shard_commands(["b_test", "c_test"], ["--all-features"])
    assert cmds == [
        ["build", "--all-features", "--examples"],
        ["test", "--all-features", "--test", "b_test", "--test", "c_test"],
    ]


def test_arguments_after_the_separator_reach_only_the_test_runs():
    cmds = pt.shard_commands([pt.UNIT_TESTS, "a"], ["--all-features", "--", "--skip", "x"])
    assert cmds[0] == ["build", "--all-features", "--examples"]
    assert cmds[1][-3:] == ["--", "--skip", "x"]
    assert cmds[2] == ["test", "--all-features", "--doc", "--", "--skip", "x"]


def manifests(shards):
    every = flat(shards)
    return [
        {"index": i, "count": len(shards), "targets": s, "all": every}
        for i, s in enumerate(shards)
    ]


def test_merge_accepts_a_complete_set_of_shards():
    assert pt.merge_problems(manifests(pt.partition(TARGETS, 3))) == []


def test_merge_refuses_a_missing_shard():
    ms = manifests(pt.partition(TARGETS, 3))
    problems = pt.merge_problems(ms[:2])
    assert any("shard 2" in p for p in problems), problems


def test_merge_refuses_a_shard_reported_twice():
    ms = manifests(pt.partition(TARGETS, 3))
    assert pt.merge_problems([*ms, ms[1]]) != []


def test_merge_refuses_a_target_no_shard_ran():
    ms = manifests(pt.partition(TARGETS, 3))
    ms[1]["targets"] = ms[1]["targets"][1:]
    problems = pt.merge_problems(ms)
    assert any("no shard ran" in p for p in problems), problems


def test_merge_refuses_a_target_two_shards_ran():
    ms = manifests(pt.partition(TARGETS, 3))
    ms[2]["targets"] = [*ms[2]["targets"], ms[1]["targets"][0]]
    problems = pt.merge_problems(ms)
    assert any("more than one shard" in p for p in problems), problems


def test_merge_refuses_shards_that_disagree_on_the_count_or_the_targets():
    ms = manifests(pt.partition(TARGETS, 3))
    ms[0]["count"] = 4
    assert pt.merge_problems(ms) != []
    ms = manifests(pt.partition(TARGETS, 3))
    ms[2]["all"] = [*ms[2]["all"], "extra"]
    assert pt.merge_problems(ms) != []


def test_merge_refuses_nothing():
    assert pt.merge_problems([]) != []


def test_merge_writes_the_outputs_in_shard_order(tmp_path):
    shards = pt.partition(TARGETS, 3)
    dirs = []
    for m in reversed(manifests(shards)):
        d = tmp_path / f"shard-{m['index']}"
        d.mkdir()
        (d / pt.SHARD_MANIFEST).write_text(json.dumps(m))
        (d / pt.SHARD_OUTPUT).write_text(f"output of shard {m['index']}\n")
        dirs.append(d)
    out = tmp_path / "test-output.txt"
    proc = subprocess.run(
        ["python3", str(REPO / "scripts/parallel-tests.py"), "merge", "--output", str(out), *map(str, dirs)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.read_text() == "output of shard 0\noutput of shard 1\noutput of shard 2\n"


def test_merge_exits_non_zero_and_writes_nothing_for_an_incomplete_set(tmp_path):
    m = manifests(pt.partition(TARGETS, 2))[0]
    d = tmp_path / "shard-0"
    d.mkdir()
    (d / pt.SHARD_MANIFEST).write_text(json.dumps(m))
    (d / pt.SHARD_OUTPUT).write_text("x\n")
    out = tmp_path / "test-output.txt"
    proc = subprocess.run(
        ["python3", str(REPO / "scripts/parallel-tests.py"), "merge", "--output", str(out), str(d)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert not out.exists()


# --- The real repository -------------------------------------------------


def ci_shard_counts():
    """The shard count of each job in ci.yml that runs the sharded Test step.

    A job's count is the length of its `shard:` matrix list, which must be
    1..N in order; the Test step takes its index and count from
    `strategy.job-index` and `strategy.job-total`, so the list is the only
    place N is written.
    """
    text = CI.read_text()
    counts = {}
    for job, body in re.findall(r"(?m)^  ([a-z0-9_-]+):\n((?:(?:    .*)?\n)*)", text):
        m = re.search(r"(?m)^\s+shard: \[([^\]]*)\]", body)
        if m:
            values = [int(v) for v in m.group(1).split(",")]
            assert values == list(range(1, len(values) + 1)), (job, values)
            # `strategy.job-total` is the shard count only while the matrix
            # has no other dimension with more than one value.
            others = re.findall(r"(?m)^        (?!shard:)[a-z_-]+: \[([^\]]*)\]", body)
            assert all("," not in o for o in others), (job, others)
            counts[job] = len(values)
    return counts


def real_targets():
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    return pt.test_targets(json.loads(out.stdout))


def test_ci_runs_the_sharded_suite_with_the_index_and_count_strategy_gives_it():
    counts = ci_shard_counts()
    assert set(counts) == {"test"}, counts
    text = CI.read_text()
    assert (
        "--shard-index ${{ strategy.job-index }} --shard-count ${{ strategy.job-total }}" in text
    ), "the Test step must take its shard from the matrix, the one place N is written"


def test_every_integration_test_file_is_a_cargo_test_target():
    # The partition reads cargo's own list. A file cargo does not treat as a
    # target (autotests off, `test = false`) would be outside every shard, so
    # the list is held to the files on disk.
    files = {p.stem for p in (REPO / "tests").glob("*.rs")}
    assert files <= set(real_targets())


def test_the_real_targets_split_completely_and_disjointly_for_every_ci_job():
    targets = real_targets()
    assert len(targets) > 400
    for job, count in ci_shard_counts().items():
        shards = pt.partition(targets, count)
        assert pt.merge_problems(manifests(shards)) == [], job
        assert sorted(flat(shards)) == sorted([*targets, pt.UNIT_TESTS]), job


# --- The shard run, against a stand-in cargo ------------------------------


def fake_cargo(tmp_path, build_status=0, fail_tests=""):
    """A `cargo` on PATH that logs each call and answers `metadata`.

    `test` prints one passing result line and exits 0 without calling the
    runner, the shape of a run where cargo ran every test itself.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "cargo.log"
    meta = {
        "target_directory": str(tmp_path / "target"),
        "packages": [
            {
                "name": "sipnab",
                "targets": [{"name": n, "kind": ["test"]} for n in ("a_test", "b_test", "c_test")]
                + [{"name": "sipnab", "kind": ["lib"]}],
            }
        ],
    }
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    cargo = bindir / "cargo"
    cargo.write_text(
        "#!/bin/sh\n"
        f'case "$1" in metadata) cat "{tmp_path}/meta.json"; exit 0 ;; esac\n'
        f'echo "$*" >> "{log}"\n'
        f'[ "$1" = build ] && exit {build_status}\n'
        f'case "$*" in *"{fail_tests or '@@never@@'}"*)\n'
        '  echo "test result: FAILED. 0 passed; 1 failed; 0 ignored"; exit 101 ;;\n'
        "esac\n"
        'echo "test result: ok. 1 passed; 0 failed; 0 ignored"\n'
    )
    cargo.chmod(0o755)
    return bindir, log


def cargo_calls(log):
    """The logged calls, without the `--config` that installs the recorder."""
    return [re.sub(r"^--config .*?\] ", "", c) for c in log.read_text().splitlines()]


def run_shard(tmp_path, bindir, index, count):
    import os

    manifest = tmp_path / f"shard-{index}.json"
    proc = subprocess.run(
        [
            "python3",
            str(REPO / "scripts/parallel-tests.py"),
            "--shard-index",
            str(index),
            "--shard-count",
            str(count),
            "--manifest",
            str(manifest),
            "--",
            "--all-features",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"},
    )
    return proc, manifest


def test_shard_zero_builds_the_examples_then_runs_its_targets_the_unit_tests_and_the_doctests(tmp_path):
    bindir, log = fake_cargo(tmp_path)
    proc, manifest = run_shard(tmp_path, bindir, 0, 2)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    m = json.loads(manifest.read_text())
    expected = pt.partition(["a_test", "b_test", "c_test"], 2)
    assert m["index"] == 0 and m["count"] == 2 and m["targets"] == expected[0]
    calls = cargo_calls(log)
    assert calls == [" ".join(c) for c in pt.shard_commands(expected[0], ["--all-features"])]
    assert calls[0] == "build --all-features --examples"
    assert "--lib --bins" in calls[1] and calls[2] == "test --all-features --doc"
    assert proc.stdout.count("test result: ok.") == 2


def test_another_shard_runs_no_unit_tests_and_no_doctests(tmp_path):
    bindir, log = fake_cargo(tmp_path)
    proc, manifest = run_shard(tmp_path, bindir, 1, 2)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = cargo_calls(log)
    assert len(calls) == 2
    assert "--lib" not in calls[1] and "--doc" not in calls[1]
    assert json.loads(manifest.read_text())["targets"] == pt.partition(["a_test", "b_test", "c_test"], 2)[1]


def test_a_failed_example_build_fails_the_shard_before_any_test_runs(tmp_path):
    bindir, log = fake_cargo(tmp_path, build_status=101)
    proc, _ = run_shard(tmp_path, bindir, 0, 2)
    assert proc.returncode != 0
    assert cargo_calls(log) == ["build --all-features --examples"]


def test_a_shard_index_outside_the_count_is_refused(tmp_path):
    bindir, log = fake_cargo(tmp_path)
    proc, _ = run_shard(tmp_path, bindir, 2, 2)
    assert proc.returncode != 0
    assert not log.exists()


@pytest.mark.parametrize("failing", ["--lib", "--doc"])
def test_a_failing_test_run_fails_the_shard_and_the_other_run_still_happens(tmp_path, failing):
    bindir, log = fake_cargo(tmp_path, fail_tests=failing)
    proc, _ = run_shard(tmp_path, bindir, 0, 2)
    assert proc.returncode != 0, proc.stdout
    assert len(cargo_calls(log)) == 3, "every run of the shard must happen"


def test_merge_of_a_shard_with_no_output_fails_and_leaves_no_file(tmp_path):
    shards = pt.partition(TARGETS, 2)
    dirs = []
    for m in manifests(shards):
        d = tmp_path / f"shard-{m['index']}"
        d.mkdir()
        (d / pt.SHARD_MANIFEST).write_text(json.dumps(m))
        if m["index"] == 0:
            (d / pt.SHARD_OUTPUT).write_text("x\n")
        dirs.append(d)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    proc = subprocess.run(
        ["python3", str(REPO / "scripts/parallel-tests.py"), "merge", "--output", str(out_dir / "o.txt"), *map(str, dirs)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr
    assert list(out_dir.iterdir()) == []
