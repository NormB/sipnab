# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The macOS shards are balanced by a unit weight measured from CI's runs.

MACOS-SHARD-BALANCE: with one unit weight (40 binaries) for both platforms,
main's macOS shard 1 took 16.8 to 22.4 min in its Test step and shard 2 12.6
to 14.8 (runs 43957731312 to 44024489366). Both shards' nextest phases were
already about equal; shard 1's `test` build, which compiles the library's
unit-test binary, took 6m29s to 9m45s against shard 2's 2m32s to 4m07s.

`measured_unit_weight` is the one rule: from the recorded phases of each
shard (build, nextest, doctests), a target's cost is the median per-target
time of the shards without the unit tests, the unit tests' cost is the median
remainder of the shard that has them, and the weight is their ratio.
`UNIT_WEIGHTS["Darwin"]` is that rule applied to `MACOS_SHARD_RECORDS`.
Linux keeps 40.
"""

import json
import pathlib
import subprocess

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
pt = load("parallel-tests")


def rec(index, targets, unit, build, nextest, doc=0.0, run=1):
    return pt.ShardRecord(run=run, index=index, targets=targets, unit=unit, build=build, nextest=nextest, doc=doc)


def pair(run, unit_total, plain_total, n0=10, n1=20):
    """One run: shard 0 (unit tests and n0 targets) and shard 1 (n1 targets)."""
    return [rec(0, n0, True, unit_total, 0.0, run=run), rec(1, n1, False, plain_total, 0.0, run=run)]


def real_targets():
    out = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=REPO,
                         capture_output=True, check=True, timeout=300)
    return pt.test_targets(json.loads(out.stdout))


# ---------------------------------------------------------------- success


def test_success_the_rule_divides_the_unit_remainder_by_a_targets_cost():
    # 20 targets in 40 s: 2 s each. 10 targets + unit in 60 s: unit 40 s = 20 targets.
    assert pt.measured_unit_weight(pair(1, 60.0, 40.0)) == 20, "40 s of unit tests at 2 s a target"


def test_success_the_phases_add_up():
    records = [rec(0, 10, True, 30.0, 20.0, 10.0), rec(1, 20, False, 25.0, 15.0)]
    assert pt.measured_unit_weight(records) == 20, "build + nextest + doctests make a shard's time"


def test_success_the_median_of_several_runs():
    records = pair(1, 60.0, 40.0) + pair(2, 60.0, 40.0) + pair(3, 600.0, 40.0)
    assert pt.measured_unit_weight(records) == 20, "one slow run does not move the median"


def test_success_the_darwin_weight_is_the_rule_on_the_records():
    assert pt.UNIT_WEIGHTS["Darwin"] == pt.measured_unit_weight(pt.MACOS_SHARD_RECORDS), \
        "the macOS weight is derived from the records, never typed"


def test_success_the_darwin_weight_is_198_on_the_recorded_runs():
    assert pt.UNIT_WEIGHTS["Darwin"] == 198, "the six recorded main runs give 198"


def test_success_linux_keeps_its_weight():
    assert pt.UNIT_WEIGHTS["Linux"] == 40 == pt.UNIT_WEIGHT, "the Linux shards are not part of this change"


def test_success_unit_weight_for_darwin():
    assert pt.unit_weight_for("Darwin") == pt.UNIT_WEIGHTS["Darwin"], "macOS reports Darwin"


def test_success_unit_weight_for_linux():
    assert pt.unit_weight_for("Linux") == 40, "Linux keeps 40"


def test_success_the_plan_uses_the_platforms_weight():
    targets = [f"t{i:03}" for i in range(509)]
    assert pt.shard_plan(targets, 2, "Darwin") == pt.partition(targets, 2, pt.UNIT_WEIGHTS["Darwin"]), \
        "the plan on macOS is the partition with the macOS weight"
    assert pt.shard_plan(targets, 2, "Linux") == pt.partition(targets, 2, 40), "and on Linux with 40"


def test_success_the_recorded_runs_are_six_pairs():
    runs = {r.run for r in pt.MACOS_SHARD_RECORDS}
    assert len(runs) == 6 and len(pt.MACOS_SHARD_RECORDS) == 12, "six main runs, both shards each"


def test_success_every_recorded_run_has_one_unit_shard():
    for run in {r.run for r in pt.MACOS_SHARD_RECORDS}:
        shards = [r for r in pt.MACOS_SHARD_RECORDS if r.run == run]
        assert [r.unit for r in sorted(shards, key=lambda r: r.index)] == [True, False], f"run {run}"


def test_success_the_predicted_shards_are_within_five_percent_with_509_targets():
    shards = pt.partition([f"t{i:03}" for i in range(509)], 2, pt.UNIT_WEIGHTS["Darwin"])
    a = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[0]) - 1, True)
    b = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[1]), False)
    assert abs(a - b) <= 0.05 * max(a, b), f"predicted shard 0 {a:.0f} s, shard 1 {b:.0f} s"


def test_success_the_old_weight_predicts_the_recorded_gap():
    shards = pt.partition([f"t{i:03}" for i in range(509)], 2, 40)
    a = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[0]) - 1, True)
    b = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[1]), False)
    assert 300 <= a - b <= 500, f"the model reproduces the measured gap: {a:.0f} vs {b:.0f}"


def test_success_the_real_targets_split_into_two_nonempty_macos_shards():
    shards = pt.shard_plan(real_targets(), 2, "Darwin")
    assert all(shards) and sum(map(len, shards)) == len(real_targets()) + 1, "complete, with the unit item"


# ---------------------------------------------------------------- failure


def test_failure_no_plain_shard_is_refused():
    with pytest.raises(ValueError, match="without the unit tests"):
        pt.measured_unit_weight([rec(0, 10, True, 60.0, 0.0)])


def test_failure_no_unit_shard_is_refused():
    with pytest.raises(ValueError, match="with the unit tests"):
        pt.measured_unit_weight([rec(1, 20, False, 40.0, 0.0)])


def test_failure_no_records_are_refused():
    with pytest.raises(ValueError):
        pt.measured_unit_weight([])


def test_failure_a_plain_shard_with_no_targets_is_refused():
    with pytest.raises(ValueError, match="no targets"):
        pt.measured_unit_weight([rec(0, 10, True, 60.0, 0.0), rec(1, 0, False, 40.0, 0.0)])


def test_failure_a_negative_phase_is_refused():
    with pytest.raises(ValueError, match="negative"):
        pt.measured_unit_weight([rec(0, 10, True, -1.0, 0.0), rec(1, 20, False, 40.0, 0.0)])


def test_failure_a_negative_doctest_phase_is_refused():
    with pytest.raises(ValueError, match="negative"):
        pt.measured_unit_weight([rec(0, 10, True, 60.0, 0.0, -5.0), rec(1, 20, False, 40.0, 0.0)])


def test_failure_a_zero_time_plain_shard_is_refused():
    with pytest.raises(ValueError, match="no time"):
        pt.measured_unit_weight([rec(0, 10, True, 60.0, 0.0), rec(1, 20, False, 0.0, 0.0)])


def test_failure_a_unit_shard_faster_than_its_targets_gives_the_floor():
    # The unit tests cannot weigh less than one target: the rule never returns 0.
    assert pt.measured_unit_weight(pair(1, 5.0, 40.0)) == 1, "the weight floors at 1"


def test_failure_a_duplicate_record_is_refused():
    records = pair(1, 60.0, 40.0) + [rec(1, 20, False, 40.0, 0.0, run=1)]
    with pytest.raises(ValueError, match="twice"):
        pt.measured_unit_weight(records)


def test_failure_doctests_on_a_plain_shard_are_refused():
    with pytest.raises(ValueError, match="doctests"):
        pt.measured_unit_weight([rec(0, 10, True, 60.0, 0.0), rec(1, 20, False, 40.0, 0.0, 3.0)])


def test_failure_an_unknown_platform_keeps_linuxs_weight():
    assert pt.unit_weight_for("Windows") == 40, "an unmeasured platform keeps the old weight"


def test_failure_an_empty_platform_name_keeps_linuxs_weight():
    assert pt.unit_weight_for("") == 40, "platform.system() may answer empty"


def test_failure_a_lowercase_name_is_not_darwin():
    assert pt.unit_weight_for("darwin") == 40, "platform.system() says Darwin; nothing else is guessed"


def test_failure_the_plan_still_refuses_an_empty_shard():
    with pytest.raises(ValueError):
        pt.shard_plan(["a"], 3, "Darwin")


# ---------------------------------------------------------------- edge


def test_edge_a_weight_rounds_to_the_nearest_target():
    # 2 s a target; unit 41 s remainder -> 20.5 -> 20 (round half to even), 43 s -> 21.5 -> 22.
    assert pt.measured_unit_weight(pair(1, 61.0, 40.0)) == 20, "20.5 rounds to 20"
    assert pt.measured_unit_weight(pair(1, 63.0, 40.0)) == 22, "21.5 rounds to 22"


def test_edge_an_even_number_of_runs_takes_the_middle_two():
    records = pair(1, 60.0, 40.0) + pair(2, 100.0, 40.0)
    # Remainders 40 and 80 s: median 60 s = 30 targets.
    assert pt.measured_unit_weight(records) == 30, "the mean of the middle two"


def test_edge_record_order_does_not_matter():
    records = list(pt.MACOS_SHARD_RECORDS)
    assert pt.measured_unit_weight(list(reversed(records))) == pt.measured_unit_weight(records), "order-free"


def test_edge_one_run_is_enough():
    assert pt.measured_unit_weight(pair(1, 60.0, 40.0)) == 20, "one pair gives a weight"


def test_edge_plain_shards_of_different_sizes():
    records = [rec(0, 10, True, 60.0, 0.0), rec(1, 20, False, 40.0, 0.0), rec(1, 40, False, 80.0, 0.0, run=2)]
    assert pt.measured_unit_weight(records) == 20, "per-target cost is per target"


def test_edge_three_shards_per_run():
    records = [rec(0, 10, True, 60.0, 0.0), rec(1, 20, False, 40.0, 0.0), rec(2, 20, False, 40.0, 0.0)]
    assert pt.measured_unit_weight(records) == 20, "more than one plain shard per run"


def test_edge_predicted_seconds_of_a_plain_shard_is_per_target():
    assert pt.predicted_seconds(pair(1, 60.0, 40.0), 7, False) == pytest.approx(14.0), "7 targets at 2 s"


def test_edge_predicted_seconds_of_the_unit_shard_adds_the_unit_cost():
    assert pt.predicted_seconds(pair(1, 60.0, 40.0), 7, True) == pytest.approx(54.0), "14 s + 40 s"


def test_edge_predicted_seconds_of_no_targets():
    assert pt.predicted_seconds(pair(1, 60.0, 40.0), 0, False) == pytest.approx(0.0), "no targets, no time"


def test_edge_the_darwin_weight_moves_targets_to_the_plain_shard():
    targets = [f"t{i:03}" for i in range(509)]
    old = pt.partition(targets, 2, 40)
    new = pt.shard_plan(targets, 2, "Darwin")
    assert len(new[0]) < len(old[0]) and len(new[1]) > len(old[1]), "shard 0 gives targets to shard 1"


def test_edge_the_darwin_split_of_509_targets():
    shards = pt.shard_plan([f"t{i:03}" for i in range(509)], 2, "Darwin")
    assert [len(s) for s in shards] == [157, 353], "156 targets + the unit item, and 353 targets"


def test_edge_a_single_shard_takes_everything_on_darwin():
    targets = [f"t{i:03}" for i in range(5)]
    assert pt.shard_plan(targets, 1, "Darwin") == [[pt.UNIT_TESTS, *targets]], "one shard runs all"


def test_edge_the_records_name_main_runs_only_once_each():
    pairs = [(r.run, r.index) for r in pt.MACOS_SHARD_RECORDS]
    assert len(pairs) == len(set(pairs)), "no run's shard is recorded twice"


def test_edge_the_recorded_unit_shards_held_235_targets():
    assert {r.targets for r in pt.MACOS_SHARD_RECORDS if r.unit} == {235}, "236 items less the unit item"
    assert {r.targets for r in pt.MACOS_SHARD_RECORDS if not r.unit} == {274}, "274 targets"


def test_edge_the_weight_is_an_int():
    assert isinstance(pt.measured_unit_weight(pt.MACOS_SHARD_RECORDS), int), "partition needs an int"


def test_edge_the_unit_tests_stay_in_shard_zero_on_darwin():
    shards = pt.shard_plan([f"t{i:03}" for i in range(50)], 2, "Darwin")
    assert shards[0] == [pt.UNIT_TESTS], "a weight above the target count leaves shard 0 the unit tests"
    assert len(shards[1]) == 50, "and shard 1 every target"


@pytest.mark.parametrize("system", ["Darwin", "Linux"])
def test_edge_run_shard_splits_by_the_platform_it_runs_on(monkeypatch, tmp_path, system):
    targets = [f"t{i:03}" for i in range(300)]
    meta = {"packages": [{"name": pt.PACKAGE, "targets": [{"name": t, "kind": ["test"]} for t in targets]}]}
    monkeypatch.setattr(pt.platform, "system", lambda: system)
    monkeypatch.setattr(pt, "cargo_metadata", lambda: meta)
    monkeypatch.setattr(pt, "check_nextest", lambda: 0)
    monkeypatch.setattr(pt, "run_commands", lambda commands: 0)
    manifest = tmp_path / "shard.json"
    assert pt.run_shard(1, 2, str(manifest), [], None) == 0, "the shard runs"
    got = json.loads(manifest.read_text())["targets"]
    assert got == pt.partition(targets, 2, pt.unit_weight_for(system))[1], f"shard 1 on {system}"


def test_success_both_predicted_macos_shards_stay_under_30_minutes():
    shards = pt.shard_plan([f"t{i:03}" for i in range(509)], 2, "Darwin")
    a = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[0]) - 1, True)
    b = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, len(shards[1]), False)
    assert max(a, b) < 1800, f"the build and test phases stay under 30 min: {a:.0f}, {b:.0f} s"


def test_success_the_unit_cost_of_the_records_is_about_eight_minutes():
    unit = pt.predicted_seconds(pt.MACOS_SHARD_RECORDS, 0, True)
    assert 420 <= unit <= 540, f"the median unit remainder of the six runs: {unit:.0f} s"


def test_failure_negative_targets_are_refused():
    with pytest.raises(ValueError, match="targets"):
        pt.measured_unit_weight([rec(0, -1, True, 60.0, 0.0), rec(1, 20, False, 40.0, 0.0)])


def test_failure_predicted_seconds_without_records_is_refused():
    with pytest.raises(ValueError):
        pt.predicted_seconds([], 10, False)


def test_edge_a_unit_shard_with_no_targets_is_accepted():
    records = [rec(0, 0, True, 40.0, 0.0), rec(1, 20, False, 40.0, 0.0)]
    assert pt.measured_unit_weight(records) == 20, "shard 0 may hold only the unit tests"


def test_edge_the_darwin_weight_is_heavier_than_linuxs():
    assert pt.UNIT_WEIGHTS["Darwin"] > pt.UNIT_WEIGHTS["Linux"], "macOS builds the unit binary slower"


def test_edge_the_script_loads_outside_sys_modules():
    # scripts/pin-gates.py and scripts/check-hook-prerequisites.py load it this way.
    import importlib.util
    spec = importlib.util.spec_from_file_location("parallel_tests_unregistered", REPO / "scripts/parallel-tests.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.UNIT_WEIGHTS["Darwin"] == pt.UNIT_WEIGHTS["Darwin"], "the module loads and derives the same weight"


def test_edge_ci_passes_no_weight_flag():
    ci = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "--unit-weight" not in ci, "the weight comes from the platform, in one place"
