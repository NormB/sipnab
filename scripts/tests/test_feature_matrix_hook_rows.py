# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The rows of CI's feature matrix that the pre-push hook lints.

The pre-commit hook builds only `--features full`. In pull request #763 a
binding read only under `#[cfg(feature = "hep")]` passed it, and would have
failed CI's clippy for every feature set without `hep`. A row of
`.github/feature-combos.txt` marked `hook` is linted by `.githooks/pre-push`
with the command CI's Features job runs for it (`lint_command`), under a
pass stamp of its own. The mark is the one rule: the hook reads the rows
through `check-feature-matrix.py --hook-rows`, and `scripts/gate-cache.py`
derives each row's step from the same parser.
"""

import os
import pathlib
import re
import subprocess
import sys

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-feature-matrix.py"
COMBOS = REPO / ".github/feature-combos.txt"
PRE_PUSH = REPO / ".githooks/pre-push"

fm = load("check-feature-matrix")
gc = load("gate-cache")

CLIPPY = "cargo clippy --no-default-features --features {} --tests -- -D warnings"


# ── The annotation ─────────────────────────────────────────────────────────


def test_hook_marks_a_row_and_leaves_the_others_unmarked():
    marked, plain = fm.parse_combos("native hook\ntls\n")
    assert marked.hook and not plain.hook


def test_hook_stands_beside_the_other_annotations_in_any_order():
    a, b = fm.parse_combos("native,tui lib hook\nnative test=feature_gate_test hook suite\n")
    assert a.hook and a.lib
    assert b.hook and b.suite and b.tests == ["feature_gate_test"]


def test_hook_does_not_change_what_ci_runs_or_how_a_row_is_weighed():
    marked = fm.parse_combos("native hook lib\n")
    plain = fm.parse_combos("native lib\n")
    assert fm.group_commands(marked) == fm.group_commands(plain)
    assert marked[0].weight() == plain[0].weight()
    assert marked[0].requires() == plain[0].requires()


@pytest.mark.parametrize(
    "text",
    [
        "native hook hook\n",  # listed twice
        "opus hook needs=cmake\n",  # the pushing machine may lack the tool
        "opus needs=cmake hook\n",  # the same, in the other order
        "wasm hook\n",  # a check for another target, which the hook has its own step for
        "Native hook\n",  # a step name holds lower-case letters, digits and hyphens
        "native,,tui hook\n",  # an empty feature name
        "native--tui hook\n",  # `--` is what separates features in a step name
        "-native hook\n",  # would read as an option to cargo
        "native hook=yes\n",  # the mark takes no value
        "native Hook\n",  # annotations are spelled in lower case
    ],
)
def test_a_malformed_mark_is_refused(text):
    with pytest.raises(ValueError):
        fm.parse_combos(text)


def test_an_unmarked_row_may_still_need_a_tool_or_be_wasm():
    rows = fm.parse_combos("opus needs=cmake\nwasm needs=wasm32\n")
    assert [r.hook for r in rows] == [False, False]


# ── The rows, their steps and their commands ───────────────────────────────


def test_the_rows_are_the_marked_ones_in_file_order():
    rows = fm.hook_rows(fm.parse_combos("tls\nnative,tui hook\napi\nnative hook\n"))
    assert [features for _step, features, _cmd in rows] == ["native,tui", "native"]


def test_a_file_with_no_mark_has_no_rows():
    assert fm.hook_rows(fm.parse_combos("tls\napi\n")) == []


def test_a_row_runs_the_command_ci_runs_for_it():
    for step, features, command in fm.hook_rows(fm.parse_combos("native,hep,api,mcp,mcp-http hook suite\n")):
        assert command == fm.lint_command(features)
        assert " ".join(command) == CLIPPY.format("native,hep,api,mcp,mcp-http")
        assert step == fm.hook_step(features)


def test_a_step_name_is_one_gate_cache_can_store():
    step = fm.hook_step("native,hep,api,mcp,mcp-http")
    assert step == "lint-native--hep--api--mcp--mcp-http"
    assert gc._STAMP_NAME.match(f"pre-push.{step}.{'0' * 64}.json"), step
    assert " " not in step


def test_two_feature_sets_never_share_a_step_name():
    # `mcp-http` holds a hyphen: with one hyphen between features these two
    # sets would be one step, and one's stamp would skip the other's lint.
    assert fm.hook_step("native,mcp-http") != fm.hook_step("native,mcp,http")


def test_a_row_step_never_takes_the_name_of_a_fixed_step():
    for step in gc.STEPS["pre-push"]:
        assert not step.startswith(fm.HOOK_STEP_PREFIX), step


# ── The real file ──────────────────────────────────────────────────────────


def real_rows():
    return [features for _s, features, _c in fm.hook_rows(fm.parse_combos(COMBOS.read_text(encoding="utf-8")))]


def default_features():
    m =re.search(r"(?m)^default = \[([^\]]*)\]", (REPO / "Cargo.toml").read_text(encoding="utf-8"))
    assert m, "Cargo.toml has no `default = [...]` line"
    return ",".join(f.strip().strip('"') for f in m.group(1).split(",") if f.strip())


def test_the_hook_lints_a_set_without_hep():
    """The #763 shape: a binding read only under `hep` is unused without it."""
    assert any("hep" not in row.split(",") for row in real_rows()), real_rows()


def test_the_hook_lints_the_default_set_and_the_headless_recipe():
    rows = real_rows()
    assert default_features() in rows, rows
    assert "native,hep,api,mcp,mcp-http" in rows, rows
    assert "native" in rows, rows


def test_the_hook_lints_few_rows():
    """Each row took 13 to 79 s after a source change (measured 2026-11-12);
    the whole matrix stays in CI."""
    assert 1 <= len(real_rows()) <= 4, real_rows()


# ── The command line the hook calls ────────────────────────────────────────


def repo_with(tmp_path, combos, workflow=True):
    root = tmp_path / "crate"
    (root / ".github/workflows").mkdir(parents=True)
    if combos is not None:
        (root / ".github/feature-combos.txt").write_text(combos)
    subprocess.run(["git", "init", "-q", "."], cwd=root, check=True)
    return root


def cli(root, *args, path=None):
    env = None
    if path is not None:
        env =dict(os.environ, PATH=f"{path}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=root, capture_output=True, text=True, env=env)


def cargo_stub(tmp_path, rc=0):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "cargo.log"
    stub = bin_dir / "cargo"
    stub.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\ncase "$1" in --version) exit 0 ;; esac\nexit {rc}\n')
    stub.chmod(0o755)
    return bin_dir, log


def test_hook_rows_prints_step_features_and_command(tmp_path):
    root = repo_with(tmp_path, "tls\nnative,tui hook\nnative hook\n")
    r = cli(root, "--hook-rows")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines() == [
        "lint-native--tui\tnative,tui\t" + CLIPPY.format("native,tui"),
        "lint-native\tnative\t" + CLIPPY.format("native"),
    ]


def test_hook_rows_of_an_unmarked_file_prints_nothing_and_succeeds(tmp_path):
    r = cli(repo_with(tmp_path, "tls\napi\n"), "--hook-rows")
    assert (r.returncode, r.stdout) == (0, ""), r.stdout + r.stderr


def test_hook_rows_of_a_malformed_file_fails_with_the_line(tmp_path):
    r = cli(repo_with(tmp_path, "tls\nopus hook needs=cmake\n"), "--hook-rows")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "line 2" in r.stdout, r.stdout


def test_hook_rows_without_the_file_fails(tmp_path):
    r = cli(repo_with(tmp_path, None), "--hook-rows")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "feature-combos.txt" in r.stdout, r.stdout


def test_lint_row_runs_the_rows_command_and_nothing_else(tmp_path):
    root = repo_with(tmp_path, "native,tui hook\nnative hook lib test=feature_gate_test\n")
    bin_dir, log = cargo_stub(tmp_path)
    r = cli(root, "--lint-row", "native", path=bin_dir)
    assert r.returncode == 0, r.stdout + r.stderr
    ran = [line for line in log.read_text().splitlines() if line != "--version"]
    assert ran == ["clippy --no-default-features --features native --tests -- -D warnings"], ran


def test_lint_row_fails_when_the_lint_fails(tmp_path):
    root = repo_with(tmp_path, "native hook\n")
    bin_dir, _log = cargo_stub(tmp_path, rc=101)
    assert cli(root, "--lint-row", "native", path=bin_dir).returncode == 1


def test_lint_row_refuses_a_row_that_is_not_marked(tmp_path):
    root = repo_with(tmp_path, "native hook\ntls\n")
    bin_dir, log = cargo_stub(tmp_path)
    r = cli(root, "--lint-row", "tls", path=bin_dir)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "clippy" not in log.read_text(), log.read_text()


def test_lint_row_refuses_a_row_that_is_not_listed(tmp_path):
    root = repo_with(tmp_path, "native hook\n")
    bin_dir, log = cargo_stub(tmp_path)
    r = cli(root, "--lint-row", "native,hep", path=bin_dir)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "clippy" not in log.read_text(), log.read_text()


@pytest.mark.parametrize(
    "args",
    [
        ["--hook-rows", "--lint-row", "native"],
        ["--hook-rows", "--group", "0", "--pool", "overflow"],
        ["--lint-row", "native", "--group", "0", "--pool", "overflow"],
    ],
)
def test_the_modes_do_not_combine(tmp_path, args):
    r = cli(repo_with(tmp_path, "native hook\n"), *args)
    assert r.returncode == 2, r.stdout + r.stderr


# ── The hook and the stamps ────────────────────────────────────────────────


def test_the_hook_takes_rows_steps_and_commands_from_the_script():
    text = PRE_PUSH.read_text(encoding="utf-8")
    assert 'python3 "$FEATURE_MATRIX" --hook-rows' in text
    assert 'python3 "$FEATURE_MATRIX" --lint-row "$row_features"' in text
    assert 'gate_hit "$row_step"' in text and 'gate_pass "$row_step"' in text
    # The command it prints is the one the script gave it, never a second copy.
    assert CLIPPY.format("%s") not in text
    assert "--features native," not in text


def test_gate_cache_gives_each_marked_row_a_build_step(tmp_path):
    root = repo_with(tmp_path, "tls\nnative,tui hook\nnative hook\n")
    rows = gc.matrix_rows(root)
    assert rows == {
        "lint-native--tui": CLIPPY.format("native,tui"),
        "lint-native": CLIPPY.format("native"),
    }


@pytest.mark.parametrize("combos", [None, "tls\napi\n", "opus hook needs=cmake\n", ""])
def test_gate_cache_has_no_row_step_without_a_readable_marked_file(tmp_path, combos):
    assert gc.matrix_rows(repo_with(tmp_path, combos)) == {}
