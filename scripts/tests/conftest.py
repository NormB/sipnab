"""Load the hyphenated scripts as importable modules."""

import importlib.util
import os
import pathlib
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


def load(stem: str):
    """Import `scripts/<stem>.py` under a module name pytest can hold."""
    name = stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
