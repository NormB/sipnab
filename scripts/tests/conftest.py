# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Load the hyphenated scripts as importable modules."""

import hashlib
import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolate_from_the_hook(monkeypatch):
    """Drop every GIT_* variable the calling git exported, for every test.

    `git commit` runs the pre-commit hook with GIT_DIR and GIT_INDEX_FILE set,
    and every child git inherits them -- `git -C <tmp>` included, because the
    environment wins over -C's discovery. A fixture's `git add` then writes the
    REAL repository's index: a phantom `docs/public.md` on 2026-09-17, and on
    2026-09-24, in a linked worktree where both paths are absolute, the
    rfc-links fixture replaced the whole index and its `git init` set
    `core.bare = true` in the config the main checkout shares. One copy of
    this lived in test_check_line_drift.py and covered that file alone;
    test_hook_env_isolation.py holds every fixture that runs git to it.
    """
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key)


def _git_out(repo, *args):
    """Standard output of a git command in `repo`, read without the GIT_*
    variables a calling `git commit` exports; None when git refuses."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        r = subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, check=False, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def tree_state(repo):
    """What the tracked files of `repo` differ in from HEAD: {path: (index
    record, digest of the file)}. None when `repo` is no repository.

    A path that is clean is absent. A file that was already modified is held
    by the digest of its content, so a second write to it is seen too."""
    status = _git_out(repo, "status", "--porcelain", "-z", "--untracked-files=no", "--no-renames")
    staged = _git_out(repo, "diff", "--cached", "--raw", "-z", "--no-renames")
    if status is None or staged is None:
        return None
    index = {}
    fields = staged.split(b"\0")
    for record, path in zip(fields[0::2], fields[1::2]):
        index[path.decode(errors="replace")] = record.decode(errors="replace")
    state = {}
    for entry in status.split(b"\0"):
        if len(entry) < 4:
            continue
        path = entry[3:].decode(errors="replace")
        try:
            digest = hashlib.sha256((pathlib.Path(repo) / path).read_bytes()).hexdigest()
        except OSError:
            digest = None
        state[path] = (index.get(path), digest)
    return state


def tree_changes(before, after):
    """The tracked paths whose state differs between two `tree_state` reads."""
    if before is None or after is None:
        return []
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))


@pytest.fixture(autouse=True, scope="module")
def _no_test_file_writes_the_checkout(request):
    """Fail a test file that changed a tracked file, or the index, of the
    checkout it runs in.

    On 2026-11-13 two tests ran a fixer with `--apply` in the real checkout
    and rewrote a staged page; on 2026-11-09 another file had done the same.
    A test that needs to see a fixer write runs it in a clone or a copy.
    SIPNAB_TREE_GUARD_REPO names another checkout to watch (the guard's own
    tests). A file edited by hand while the tests run fails here too: run
    the tests again."""
    repo = os.environ.get("SIPNAB_TREE_GUARD_REPO") or SCRIPTS.parent
    before = tree_state(repo)
    yield
    changed = tree_changes(before, tree_state(repo))
    if changed:
        pytest.fail(
            f"{request.node.name} wrote tracked files of the checkout it runs in ({repo}): "
            + ", ".join(changed)
            + ". Run a fixer in a clone or a copy; restore these files before the next commit.",
            pytrace=False,
        )


def load(stem: str):
    """Import `scripts/<stem>.py` under a module name pytest can hold."""
    name = stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
