# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Every module the scripts and their tests import exists where CI runs them.

On 2026-11-18 scripts/tests/test_check_binary_size.py imported `yaml`. The
pre-commit hook passed, because this host's Python has PyYAML, and CI's
"Check" job failed collecting the file: its Python has the standard library,
pytest, and nothing else this directory may use. Nothing compared an import
with what CI installs, so the first place to learn it was CI.

The rule: an import in scripts/*.py or scripts/tests/*.py names a standard
library module, pytest, or a module of these two directories. Imports are
read with `ast`, so text in a docstring that starts with "from" is not one.
"""

import ast
import sys

import pytest

from conftest import SCRIPTS

TESTS = SCRIPTS / "tests"
ALLOWED_THIRD_PARTY = {"pytest"}
# A script run by hand, never by CI, may need more; each entry says why.
BY_HAND = {
    "scripts/build-icons.py": ({"fontTools"}, "a by-hand icon build whose docstring names fontTools; "
                                              "lockup() imports it, and no test calls lockup()"),
}


def local_modules():
    return {p.stem for d in (SCRIPTS, TESTS) for p in d.glob("*.py")}


def imported(source):
    """Top-level names of every absolute import in `source`."""
    names = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module.split(".")[0])
    return names


def unavailable(source, local):
    return sorted({n for n in imported(source)
                   if n not in sys.stdlib_module_names and n not in ALLOWED_THIRD_PARTY and n not in local})


def test_no_script_or_script_test_imports_a_module_ci_lacks():
    local = local_modules()
    files = sorted([*SCRIPTS.glob("*.py"), *TESTS.glob("*.py")])
    assert len(files) > 100, f"only {len(files)} files read; the scan is reading the wrong place"
    bad = {}
    for f in files:
        rel = str(f.relative_to(SCRIPTS.parent))
        missing = set(unavailable(f.read_text(), local)) - BY_HAND.get(rel, (set(), ""))[0]
        if missing:
            bad[rel] = sorted(missing)
    assert not bad, f"imports CI's Python does not have (stdlib, pytest and local modules only): {bad}"


def test_every_by_hand_exception_is_still_needed():
    local = local_modules()
    for rel, (names, why) in BY_HAND.items():
        assert why, rel
        have = set(unavailable((SCRIPTS.parent / rel).read_text(), local))
        assert names <= have, f"{rel} no longer imports {sorted(names - have)}; drop the exception"


@pytest.mark.parametrize("source", ["import yaml\n", "from yaml import safe_load\n", "import yaml.loader\n",
                                    "def f():\n    import requests\n", "import os, toml\n",
                                    "try:\n    import yaml\nexcept ImportError:\n    yaml = None\n"])
def test_a_third_party_import_is_found(source):
    assert unavailable(source, set()), source


@pytest.mark.parametrize("source", ["import os\n", "from pathlib import Path\n", "import tomllib\n",
                                    "import xml.etree.ElementTree as ET\n", "import pytest\n",
                                    "from . import sibling\n", "from __future__ import annotations\n",
                                    '"""\nfrom a page that names it\n"""\n'])
def test_the_standard_library_pytest_relative_imports_and_docstrings_pass(source):
    assert unavailable(source, set()) == [], source


@pytest.mark.parametrize("name", ["conftest", "lib_markdown", "test_flag_since"])
def test_a_module_of_these_directories_is_local(name):
    assert name in local_modules()
    assert unavailable(f"import {name}\n", local_modules()) == []


def test_a_local_name_is_local_only_when_the_file_exists():
    assert unavailable("import lib_no_such_module\n", local_modules()) == ["lib_no_such_module"]
