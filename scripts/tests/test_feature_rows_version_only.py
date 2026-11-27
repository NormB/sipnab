# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A change to Cargo.toml or Cargo.lock that only moves sipnab's own version
picks no feature row.

PUSH-ROWS-FALLBACK-ON-VERSION-ONLY-LOCK. #948's merge round of release
0.5.277 (d0eca12f2) took pre-push's every-single-row fallback, "a changed file
is outside every feature-gated module (Cargo.lock)": 14 rows, and the push job
ran 1475 s in slot B. Between b6186d60c and d0eca12f2 the only Cargo.lock
change was sipnab's `version = "0.5.276"` -> `"0.5.277"`, and the only
Cargo.toml change its [package] `version` line. Neither changes a dependency,
a feature or a cfg, so no row compiles anything new.

`version_only_change` is the rule, a pure function of the two texts and the
package's name. `changed_files` applies it to each pushed range and leaves
such a file out; any other change to either file still counts.
"""

import os
import pathlib
import subprocess
import sys

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-feature-matrix.py"
ZERO = "0" * 40
OWN = "fixture"

fm = load("check-feature-matrix")


def manifest(version="0.1.0", dep="1.0", features='a = []\n', comment=""):
    return (f'{comment}[package]\nname = "{OWN}"\nversion = "{version}"\nedition = "2021"\n\n'
            f'[dependencies]\nlibc = {{ version = "{dep}", optional = true }}\n\n[features]\n{features}')


def lock_package(name, version, source=True):
    src = 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\n' if source else ""
    return f'[[package]]\nname = "{name}"\nversion = "{version}"\n{src}'


def lock(own="0.1.0", libc="1.0.0", extra=()):
    parts = ["version = 4\n", lock_package(OWN, own, source=False), lock_package("libc", libc)]
    parts += [lock_package(n, v, source=s) for n, v, s in extra]
    return "\n".join(parts)


# ---------------------------------------------------------------- the rule


def test_success_a_lock_that_moves_only_the_own_version_is_version_only():
    assert fm.version_only_change("Cargo.lock", lock(own="0.1.0"), lock(own="0.1.1"), OWN), "own version only"


def test_success_a_manifest_that_moves_only_the_package_version_is_version_only():
    assert fm.version_only_change("Cargo.toml", manifest("0.1.0"), manifest("0.1.1"), OWN), "package version only"


def test_success_a_comment_only_manifest_change_is_version_only():
    assert fm.version_only_change("Cargo.toml", manifest(), manifest(comment="# a note\n"), OWN), \
        "a comment changes no build"


def test_failure_a_dependency_version_in_the_lock_counts():
    assert not fm.version_only_change("Cargo.lock", lock(libc="1.0.0"), lock(libc="1.0.1"), OWN), \
        "a dependency moved"


def test_failure_a_new_package_in_the_lock_counts():
    new = lock(extra=[("zeroize", "1.0.0", True)])
    assert not fm.version_only_change("Cargo.lock", lock(), new, OWN), "a package was added"


def test_failure_a_removed_package_in_the_lock_counts():
    old = lock(extra=[("zeroize", "1.0.0", True)])
    assert not fm.version_only_change("Cargo.lock", old, lock(), OWN), "a package was removed"


def test_failure_the_own_version_and_a_dependency_together_count():
    assert not fm.version_only_change("Cargo.lock", lock("0.1.0", "1.0.0"), lock("0.1.1", "1.0.1"), OWN), \
        "the version and a dependency moved"


def test_failure_another_path_package_version_counts():
    old = lock(extra=[("fixture-codec", "0.1.0", False)])
    new = lock(extra=[("fixture-codec", "0.2.0", False)])
    assert not fm.version_only_change("Cargo.lock", old, new, OWN), "another workspace crate moved"


def test_failure_a_features_change_in_the_manifest_counts():
    assert not fm.version_only_change("Cargo.toml", manifest(), manifest(features='a = []\nb = ["a"]\n'), OWN), \
        "a feature was added"


def test_failure_a_dependency_change_in_the_manifest_counts():
    assert not fm.version_only_change("Cargo.toml", manifest(dep="1.0"), manifest(dep="2.0"), OWN), \
        "a dependency requirement moved"


def test_failure_the_package_version_and_a_feature_together_count():
    new = manifest("0.1.1", features='a = []\nb = []\n')
    assert not fm.version_only_change("Cargo.toml", manifest("0.1.0"), new, OWN), "the version and a feature"


def test_edge_an_added_or_deleted_file_counts():
    assert not fm.version_only_change("Cargo.lock", None, lock(), OWN), "an added lock"
    assert not fm.version_only_change("Cargo.lock", lock(), None, OWN), "a deleted lock"


def test_edge_a_file_that_does_not_parse_counts():
    assert not fm.version_only_change("Cargo.toml", manifest(), "[package\n", OWN), "unreadable TOML"


def test_edge_another_path_is_never_version_only():
    # Valid, equal TOML: only the path decides.
    assert not fm.version_only_change("crates/x/Cargo.toml", "a = 1\n", "a = 1\n", OWN), "only the two Cargo files"


def test_edge_a_registry_package_with_the_own_name_counts():
    # Only the workspace's own entry (no `source`) is the package's version.
    old = lock(extra=[(OWN, "9.0.0", True)])
    new = lock(extra=[(OWN, "9.0.1", True)])
    assert not fm.version_only_change("Cargo.lock", old, new, OWN), "a registry crate of the same name moved"


def test_edge_a_lock_without_the_own_name_counts():
    assert not fm.version_only_change("Cargo.lock", lock("0.1.0"), lock("0.1.1"), None), \
        "without the package's name nothing is the own version"


# ---------------------------------------------------------------- changed_files


def fake_git(files_at):
    """A git(*args) that knows `diff` and `show <rev>:<path>` for two commits."""
    def git(*args):
        if args[0] == "cat-file":
            return ""
        if args[0] == "diff":
            return "\n".join(sorted(set(files_at["a" * 40]) | set(files_at["b" * 40])))
        if args[0] == "show":
            rev, path = args[1].split(":", 1)
            return files_at.get(rev, {}).get(path)
        return None
    return git


RANGE = f"refs/heads/x {'a' * 40} refs/heads/x {'b' * 40}\n"


def test_success_changed_files_leaves_out_a_version_only_manifest_and_lock():
    git = fake_git({"b" * 40: {"Cargo.toml": manifest("0.1.0"), "Cargo.lock": lock("0.1.0"), "src/a.rs": "1"},
                    "a" * 40: {"Cargo.toml": manifest("0.1.1"), "Cargo.lock": lock("0.1.1"), "src/a.rs": "2"}})
    settled = []
    assert fm.changed_files(RANGE, git, settled) == ["src/a.rs"], "the version files are left out"
    assert settled == ["Cargo.lock", "Cargo.toml"], settled


def test_failure_changed_files_keeps_a_lock_whose_dependency_moved():
    git = fake_git({"b" * 40: {"Cargo.toml": manifest("0.1.0"), "Cargo.lock": lock("0.1.0", "1.0.0")},
                    "a" * 40: {"Cargo.toml": manifest("0.1.1"), "Cargo.lock": lock("0.1.1", "1.0.1")}})
    settled = []
    assert fm.changed_files(RANGE, git, settled) == ["Cargo.lock"], "the lock still counts"
    assert settled == ["Cargo.toml"], settled


# ---------------------------------------------------------------- the command line


def repo_with(root, combos, commits):
    """A git repository of `commits`, each a {path: text}; returns each commit."""
    root.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True, text=True,
                              timeout=60).stdout.strip()

    git("init", "-q", "-b", "work")
    shas = []
    for files in [{".github/feature-combos.txt": combos, "src/lib.rs": "\n"}] + commits:
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        git("add", "-A")
        git("-c", "user.name=E", "-c", "user.email=e@example.com", "-c", "commit.gpgsign=false",
            "commit", "-q", "--allow-empty", "-m", "c")
        shas.append(git("rev-parse", "HEAD"))
    return shas


def push_rows(root, base, head):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    r = subprocess.run([sys.executable, str(SCRIPT), "--push-rows"], cwd=root, capture_output=True, text=True,
                       input=f"refs/heads/work {head} refs/heads/work {base}\n", env=env, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    return [line.split("\t")[0] for line in r.stdout.splitlines()], r.stderr


COMBOS = "native hook\ntls\na\n"


def test_success_a_release_version_push_lints_only_the_hook_rows(tmp_path):
    shas = repo_with(tmp_path / "r", COMBOS, [{"Cargo.toml": manifest("0.1.0"), "Cargo.lock": lock("0.1.0")},
                                              {"Cargo.toml": manifest("0.1.1"), "Cargo.lock": lock("0.1.1")}])
    steps, note = push_rows(tmp_path / "r", shas[1], shas[2])
    assert steps == ["lint-native"], (steps, note)
    assert "Cargo.lock and Cargo.toml change only the package version" in note, note


def test_failure_a_dependency_push_still_takes_the_fallback(tmp_path):
    shas = repo_with(tmp_path / "r", COMBOS, [{"Cargo.toml": manifest("0.1.0"), "Cargo.lock": lock("0.1.0")},
                                              {"Cargo.toml": manifest("0.1.0"), "Cargo.lock": lock(libc="1.0.1")}])
    steps, note = push_rows(tmp_path / "r", shas[1], shas[2])
    assert steps == ["lint-native", "lint-tls", "lint-a"], (steps, note)
    assert "outside every feature-gated module (Cargo.lock)" in note, note
