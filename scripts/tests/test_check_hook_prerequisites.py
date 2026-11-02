# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""check-hook-prerequisites.py: what a hook needs that git does not carry.

A fresh worktree lacks every gitignored input. The pre-commit hook used to
find the missing G.729 test vectors 25 minutes into the suite, and pre-push
the missing Vale style package at its prose step. Each hook now asks this
script first, and is refused in seconds with the command that fixes each
missing input.
"""

import pathlib
import subprocess
import sys

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-hook-prerequisites.py"

prereqs = load("check-hook-prerequisites")
fetch = load("fetch-g729-vectors")

VALE_INI = """StylesPath = .vale/styles
MinAlertLevel = suggestion

Packages = https://github.com/errata-ai/Google/releases/download/v0.7.0/Google.zip
"""


def _tree(tmp_path, g729=False, vale_ini=None):
    root = tmp_path / "tree"
    root.mkdir()
    if g729:
        (root / "crates/g729").mkdir(parents=True)
        (root / "crates/g729/Cargo.toml").write_text('[package]\nname = "sipnab-g729"\n')
    if vale_ini is not None:
        (root / ".vale.ini").write_text(vale_ini)
    return root


def _fetch_vectors(root):
    dest = root / "crates/g729/test-vectors"
    for entry in {**fetch.ALL_PINS, **fetch.G7291_PINS}:
        path = fetch.destination(dest, entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")


def _vale_sync(root, package="Google"):
    (root / ".vale/styles" / package).mkdir(parents=True)


def _missing(root, hook, vale=True):
    """The missing prerequisites, as (fix command, path relative to root)."""
    found = prereqs.missing(root, hook, env={}, vale_binary="/usr/bin/vale" if vale else None)
    return [(m.fix, str(m.path.relative_to(root))) for m in found]


def test_a_tree_without_g729_or_vale_needs_nothing(tmp_path):
    root = _tree(tmp_path)
    assert _missing(root, "pre-commit") == []
    assert _missing(root, "pre-push") == []


def test_pre_commit_needs_the_g729_vectors_when_the_crate_is_there(tmp_path):
    root = _tree(tmp_path, g729=True)
    assert _missing(root, "pre-commit") == [
        ("python3 scripts/fetch-g729-vectors.py", "crates/g729/test-vectors")
    ]


def test_pre_push_runs_no_test_that_reads_the_g729_vectors(tmp_path):
    root = _tree(tmp_path, g729=True)
    assert _missing(root, "pre-push") == []


def test_one_missing_vector_is_enough_to_refuse(tmp_path):
    root = _tree(tmp_path, g729=True)
    _fetch_vectors(root)
    assert _missing(root, "pre-commit") == []
    next((root / "crates/g729/test-vectors/annex-b").iterdir()).unlink()
    assert len(_missing(root, "pre-commit")) == 1


def test_g729_vectors_moved_by_the_environment_are_looked_for_there(tmp_path):
    root = _tree(tmp_path, g729=True)
    elsewhere = tmp_path / "vectors"
    found = prereqs.missing(root, "pre-commit", env={"G729_VECTORS": str(elsewhere)}, vale_binary=None)
    assert [m.path for m in found] == [elsewhere]


def test_both_hooks_need_each_vale_package_the_config_names(tmp_path):
    root = _tree(tmp_path, vale_ini=VALE_INI)
    for hook in ("pre-commit", "pre-push"):
        assert _missing(root, hook) == [("vale sync", ".vale/styles/Google")]
    _vale_sync(root)
    assert _missing(root, "pre-commit") == []
    assert _missing(root, "pre-push") == []


def test_without_a_vale_binary_the_package_is_not_asked_for(tmp_path):
    # the prose gate itself reports a missing vale as NOT CHECKED
    root = _tree(tmp_path, vale_ini=VALE_INI)
    assert _missing(root, "pre-commit", vale=False) == []


def test_every_package_of_a_list_is_read(tmp_path):
    ini = "StylesPath = styles\nPackages = Microsoft, https://example.com/x/proselint.zip\n"
    root = _tree(tmp_path, vale_ini=ini)
    assert _missing(root, "pre-push") == [
        ("vale sync", "styles/Microsoft"),
        ("vale sync", "styles/proselint"),
    ]


def test_the_real_vale_ini_names_the_google_package():
    assert prereqs.vale_packages((REPO / ".vale.ini").read_text()) == (
        ".vale/styles",
        ["Google"],
    )


def _run(root, hook):
    return subprocess.run(
        [sys.executable, str(SCRIPT), hook, "--root", str(root)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )


def test_the_command_refuses_with_each_fix_and_passes_once_fixed(tmp_path):
    root = _tree(tmp_path, g729=True)
    out = _run(root, "pre-commit")
    assert out.returncode == 1, out.stdout + out.stderr
    assert "Prerequisites... FAIL" in out.stdout
    assert "crates/g729/test-vectors" in out.stdout
    assert "run: python3 scripts/fetch-g729-vectors.py" in out.stdout
    _fetch_vectors(root)
    out = _run(root, "pre-commit")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Prerequisites... OK" in out.stdout


def test_the_command_refuses_an_unknown_hook(tmp_path):
    out = _run(_tree(tmp_path), "post-merge")
    assert out.returncode == 2
    assert "pre-commit" in out.stderr and "pre-push" in out.stderr
