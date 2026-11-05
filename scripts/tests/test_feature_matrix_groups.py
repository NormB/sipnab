# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""CI's feature combinations run in a few jobs, and every one runs in exactly one.

`.github/feature-combos.txt` lists the combinations, the tests that run only
where a feature is absent beside the combination that lacks it, and what a
combination needs from the machine. ci.yml's `features` job runs
`scripts/check-feature-matrix.py --group I --pool P`, one group per leg; `partition` in that script decides which group runs what, given the
pool each group runs on (`GROUPS`) and what each pool can run (`POOLS`).
These hold the rule complete, disjoint and deterministic, and hold the real
file and ci.yml to it, so no combination can drop out of CI unnoticed.
"""

import json
import os
import pathlib
import re
import subprocess

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CI = REPO / ".github/workflows/ci.yml"
COMBOS = REPO / ".github/feature-combos.txt"

fm = load("check-feature-matrix")

SAMPLE = """\
# A comment line, and a blank line below.

native,hep,api,mcp,mcp-http suite
native test=feature_gate_test
tls
wasm needs=wasm32
"tls,api"
opus needs=cmake
"""

# Two pools: one runs everything, one only lints and has no wasm32 or cmake.
POOLS = {"big": {"tests", "wasm32", "cmake"}, "small": set()}
GROUPS = ["big", "big", "small"]


def test_the_file_is_parsed_into_combinations_and_their_tests():
    combos = fm.parse_combos(SAMPLE)
    assert [c.features for c in combos] == ["native,hep,api,mcp,mcp-http", "native", "tls", "wasm", "tls,api", "opus"]
    assert combos[0].suite and combos[0].tests == []
    assert combos[1].tests == ["feature_gate_test"] and not combos[1].suite
    assert combos[2].tests == [] and not combos[2].suite
    assert combos[3].needs == ["wasm32"]


@pytest.mark.parametrize(
    "text",
    [
        "native\nnative\n",  # listed twice
        "native frobnicate\n",  # unknown annotation
        "native test=\n",  # empty test name
        "native needs=\n",  # empty need
        "# nothing\n",  # no combination at all
    ],
)
def test_a_malformed_file_is_refused(text):
    with pytest.raises(ValueError):
        fm.parse_combos(text)


def flat(groups):
    return [c.features for g in groups for c in g]


@pytest.mark.parametrize("groups", [["big"], ["big", "big"], GROUPS, ["big", "small", "small", "big"]])
def test_every_combination_runs_in_exactly_one_group(groups):
    combos = fm.parse_combos(SAMPLE + "".join(f"c{i}\n" for i in range(6)))
    out = fm.partition(combos, groups, POOLS)
    assert len(out) == len(groups)
    assert sorted(flat(out)) == sorted(c.features for c in combos)


def test_a_group_runs_only_what_its_pool_can():
    combos = fm.parse_combos(SAMPLE + "".join(f"c{i}\n" for i in range(6)))
    out = fm.partition(combos, GROUPS, POOLS)
    small = out[2]
    assert small, "the lint-only pool must get work"
    assert all(not c.tests and not c.suite and not c.needs for c in small)


def test_the_partition_does_not_depend_on_the_file_order():
    combos = fm.parse_combos(SAMPLE)
    assert fm.partition(combos, GROUPS, POOLS) == fm.partition(list(reversed(combos)), GROUPS, POOLS)


def test_the_full_suite_is_weighed_so_its_group_gets_little_else():
    combos = fm.parse_combos(SAMPLE + "".join(f"c{i}\n" for i in range(20)))
    groups = fm.partition(combos, ["big", "big", "big"], POOLS)
    suite = next(g for g in groups if any(c.suite for c in g))
    others = [g for g in groups if g is not suite]
    assert all(len(suite) < len(g) for g in others)


def test_no_groups_is_refused():
    with pytest.raises(ValueError):
        fm.partition(fm.parse_combos(SAMPLE), [], POOLS)


def test_a_group_that_would_run_nothing_is_refused():
    with pytest.raises(ValueError):
        fm.partition(fm.parse_combos("native\n"), ["big", "big"], POOLS)


def test_a_combination_no_pool_can_run_is_refused():
    with pytest.raises(ValueError):
        fm.partition(fm.parse_combos("opus needs=cmake\ntls\n"), ["small", "small"], POOLS)


def test_an_unknown_pool_is_refused():
    with pytest.raises(ValueError):
        fm.partition(fm.parse_combos(SAMPLE), ["big", "nowhere"], POOLS)


def test_the_commands_lint_each_combination_and_run_its_tests():
    combos = fm.parse_combos(SAMPLE)
    cmds = fm.group_commands(combos)
    assert ["cargo", "clippy", "--no-default-features", "--features", "native", "--tests", "--", "-D", "warnings"] in cmds
    assert ["cargo", "test", "--no-default-features", "--features", "native", "--test", "feature_gate_test"] in cmds
    assert ["cargo", "check", "--target", "wasm32-unknown-unknown", "--no-default-features", "--features", "wasm", "--lib"] in cmds
    suite = [c for c in cmds if "parallel-tests.py" in " ".join(c)]
    assert suite == [
        ["python3", "scripts/parallel-tests.py", "--", "--no-default-features", "--features", "native,hep,api,mcp,mcp-http"]
    ]
    # wasm is lib-only: no clippy --tests run for it.
    assert not any(c[:2] == ["cargo", "clippy"] and "wasm" in c for c in cmds)


# --- The real repository -------------------------------------------------


def ci_job(job_id):
    text = CI.read_text()
    job = text.split(f"\n  {job_id}:\n", 1)[1]
    return re.split(r"\n  [a-z0-9_-]+:\n", job, maxsplit=1)[0]


def ci_groups():
    """(group index, pool) for every group ci.yml runs, from both jobs.

    A job names its group either literally or as `${{ matrix.group }}`, whose
    values its `group:` matrix list gives.
    """
    out = []
    for job_id in ("features",):
        job = ci_job(job_id)
        m = re.search(r"python3 scripts/check-feature-matrix.py --group (\$\{\{ matrix.group \}\}|\d+) --pool (\S+)", job)
        assert m, f"ci.yml's {job_id} job does not run check-feature-matrix.py --group I --pool P"
        index, pool = m.groups()
        if index.isdigit():
            out.append((int(index), pool))
            continue
        lst = re.search(r"(?m)^\s+group: \[([^\]]*)\]", job)
        assert lst, f"{job_id} names matrix.group and has no group list"
        out += [(int(v), pool) for v in lst.group(1).split(",")]
    return out


def test_ci_runs_every_group_once_on_its_own_pool():
    groups = ci_groups()
    assert sorted(i for i, _ in groups) == list(range(len(fm.GROUPS))), groups
    for index, pool in groups:
        assert fm.GROUPS[index] == pool, (index, pool)


def test_the_real_combinations_split_completely_and_disjointly():
    combos = fm.parse_combos(COMBOS.read_text())
    groups = fm.partition(combos)
    assert sorted(flat(groups)) == sorted(c.features for c in combos)
    assert len(flat(groups)) == len(set(flat(groups)))


# The combinations, and the tests beside them, that CI checked when the
# matrix was folded on 2026-11-03. One may be added; none may silently go.
CHECKED_ON_2026_11_03 = {
    "native,hep,api,mcp,mcp-http": "suite",
    "native": "feature_gate_test",
    "tls": None,
    "api": None,
    "mcp": "app_servers_test",
    "hep": None,
    "metrics": None,
    "tls,api": None,
    "native,tui,audio": None,
    "native,tui,audio,metrics": None,
    "native,tui,tls,hep,api": "tui_snapshot_test",
    "bpf": None,
    "vcon": "vcon_rules_test",
    "opus": None,
    "audio": None,
    "plugins": None,
    "archive": None,
    "g729": None,
    "native,tui,tls,hep,api,mcp,mcp-http,metrics,archive,g729": None,
    "native,tui,tls,hep,api,mcp,mcp-http,metrics,archive,g729,bpf": None,
    "wasm": None,
}


def test_no_combination_or_test_checked_before_the_fold_has_gone():
    combos = {c.features: c for c in fm.parse_combos(COMBOS.read_text())}
    for features, extra in CHECKED_ON_2026_11_03.items():
        assert features in combos, f"the {features} combination is no longer checked"
        if extra == "suite":
            assert combos[features].suite, f"{features} no longer runs its full suite"
        elif extra:
            assert extra in combos[features].tests, f"{features} no longer runs {extra}"


def test_the_local_gate_reads_the_same_list(monkeypatch):
    # Loaded afresh from the repository root, as a developer runs it: the
    # module finds its tree from git at import, and the copy imported at
    # collection may have seen the calling hook's GIT_DIR (the conftest
    # fixture clears those variables only once a test starts).
    monkeypatch.chdir(REPO)
    fresh = load("check-feature-matrix")
    assert fresh.combos() == [c.features for c in fm.parse_combos(COMBOS.read_text())]


# --- The group run, against a stand-in cargo -----------------------------

# What the script runs to see whether the machine has what a pool needs.
PROBE = ("rustup ", "cmake ", "cargo --version", "cargo clippy --version")


def fake_tools(tmp_path, fail=""):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("cargo", "python3", "rustup", "cmake"):
        script = bindir / tool
        body = f'echo "{tool} $*" >> "{log}"\n'
        if tool == "rustup":
            body += 'echo "wasm32-unknown-unknown"\n'
        if tool == "cargo":
            body += f'case "$*" in *"{fail or "@@never@@"}"*) exit 1 ;; esac\n'
        script.write_text("#!/bin/sh\n" + body)
        script.chmod(0o755)
    return bindir, log


def calls(log):
    if not log.exists():
        return []
    return [line for line in log.read_text().splitlines() if not line.startswith(PROBE)]


def run_group(tmp_path, bindir, index, pool, combos_text):
    crate = tmp_path / "crate"
    (crate / ".github/workflows").mkdir(parents=True)
    (crate / ".github/workflows/ci.yml").write_text("name: CI\nenv:\n  RUSTFLAGS: -Dwarnings\njobs: {}\n")
    (crate / ".github/feature-combos.txt").write_text(combos_text)
    subprocess.run(["git", "init", "-q", str(crate)], check=True)
    return subprocess.run(
        ["/usr/bin/python3", str(REPO / "scripts/check-feature-matrix.py"), "--group", str(index), "--pool", pool],
        cwd=crate,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"},
    )


def test_a_group_runs_exactly_its_share(tmp_path):
    groups = fm.partition(fm.parse_combos(SAMPLE))
    for i, group in enumerate(groups):
        d = tmp_path / f"g{i}"
        d.mkdir()
        bindir, log = fake_tools(d)
        proc = run_group(d, bindir, i, fm.GROUPS[i], SAMPLE)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert calls(log) == [" ".join(c) for c in fm.group_commands(group)]


def test_a_failing_command_fails_the_group_and_the_rest_still_run(tmp_path):
    group = fm.partition(fm.parse_combos(SAMPLE))[0]
    victim = fm.lint_command(group[-1].features)
    bindir, log = fake_tools(tmp_path, fail=" ".join(victim[1:]))
    proc = run_group(tmp_path, bindir, 0, fm.GROUPS[0], SAMPLE)
    assert proc.returncode == 1, proc.stdout
    assert len(calls(log)) == len(fm.group_commands(group))


def test_a_group_on_the_wrong_pool_is_refused(capsys):
    # In process: with one pool, the command line's `--pool` choices admit
    # no other name, so run_group is called with one directly.
    assert fm.run_group(0, "not-" + fm.GROUPS[0]) == 2
    assert "ci.yml and GROUPS disagree" in capsys.readouterr().out


def test_a_group_index_outside_the_groups_is_refused(tmp_path):
    bindir, log = fake_tools(tmp_path)
    proc = run_group(tmp_path, bindir, len(fm.GROUPS), fm.GROUPS[0], SAMPLE)
    assert proc.returncode == 2
    assert calls(log) == []


def test_a_machine_missing_what_its_pool_needs_is_refused_with_the_reason(tmp_path):
    bindir, log = fake_tools(tmp_path)
    # A cmake that is not there: the stand-in fails as `command not found` would.
    (bindir / "cmake").write_text("#!/bin/sh\nexit 127\n")
    pool = next(p for p, caps in fm.POOLS.items() if "cmake" in caps)
    index = fm.GROUPS.index(pool)
    proc = run_group(tmp_path, bindir, index, pool, SAMPLE)
    assert proc.returncode == 2
    assert "cmake" in proc.stdout
    assert calls(log) == []


# --- Library unit tests with features off ----------------------------------
#
# `tui::render::popups::tests::the_popup_table_covers_every_popup_entry_point`
# failed in every TUI build without `archive`, the default feature set among
# them, and CI never saw it: the library's unit tests ran only under
# `--all-features` and the hook's `--features full`, and this file named test
# TARGETS, never the library. `lib` runs the library's unit tests with a
# combination's features.


def test_lib_is_parsed_and_runs_the_library_unit_tests():
    combos = fm.parse_combos("native,tui,audio,metrics lib\ntls\n")
    assert combos[0].lib and not combos[1].lib
    cmds = fm.group_commands(combos)
    assert ["cargo", "test", "--no-default-features", "--features", "native,tui,audio,metrics", "--lib"] in cmds
    assert not any("--lib" in c and "tls" in c and c[:2] == ["cargo", "test"] for c in cmds)


def test_lib_is_listed_once_per_combination():
    with pytest.raises(ValueError):
        fm.parse_combos("native lib lib\n")


def test_lib_needs_a_pool_that_runs_tests():
    combo = fm.parse_combos("native lib\n")[0]
    assert "tests" in combo.requires()
    with pytest.raises(ValueError):
        fm.partition(fm.parse_combos("native lib\ntls\n"), ["small", "small"], POOLS)


def test_lib_is_weighed_like_one_test_target():
    plain, lib = fm.parse_combos("tls\nnative lib\n")
    assert lib.weight() == plain.weight() + 1


def default_features():
    m = re.search(r'(?m)^default = \[([^\]]*)\]', (REPO / "Cargo.toml").read_text())
    assert m, "Cargo.toml has no `default = [...]` line"
    return ",".join(f.strip().strip('"') for f in m.group(1).split(",") if f.strip())


def test_the_default_feature_set_runs_the_library_unit_tests():
    """What a bare `cargo test --lib` compiles on a developer's machine."""
    combos = {c.features: c for c in fm.parse_combos(COMBOS.read_text())}
    default = default_features()
    assert default in combos, f"the default feature set {default} is not in the matrix"
    assert combos[default].lib, (
        f"{default} does not run the library unit tests, so a unit test that "
        "fails only with these features never fails in CI"
    )
