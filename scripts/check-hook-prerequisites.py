#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Check the gitignored inputs a git hook needs, before the hook runs anything.

A fresh worktree has none of them, and git carries none of them. The
pre-commit hook used to find the missing G.729 test vectors 25 minutes into
the suite, where 52 tests failed on them, and pre-push found the missing Vale
style package at its prose gate, after the build gates. Each hook runs this
first and stops at once on a missing input, with the command that fixes it.

The prerequisites, and which hook needs each:

* the ITU-T G.729 test vectors and table sources under
  crates/g729/test-vectors (or $G729_VECTORS), which the pre-commit suite
  reads: needed when the tree has the crates/g729 crate. The rule is
  `fetch-g729-vectors.py --check`'s own, read from the same pins the fetch
  writes. Fix: `python3 scripts/fetch-g729-vectors.py`.
* each Vale package .vale.ini names, under its StylesPath, which both hooks'
  prose gates read: needed when there is a .vale.ini and a vale binary
  ($VALE_BIN, else vale on PATH). Without a vale binary the prose gate itself
  reports NOT CHECKED, so the package is not asked for. Fix: `vale sync`.

Usage:
    check-hook-prerequisites.py pre-commit|pre-push [--root DIR]

Exit 0 when every prerequisite is in place, 1 when any is missing (each one
printed with its fix), 2 on a usage error.
"""

import argparse
import configparser
import importlib.util
import os
import pathlib
import shutil
import sys
from dataclasses import dataclass

HOOKS = ("pre-commit", "pre-push")
SCRIPTS = pathlib.Path(__file__).resolve().parent


@dataclass
class Missing:
    """One prerequisite that is not in place."""

    name: str
    path: pathlib.Path
    fix: str


def _fetch_module():
    spec = importlib.util.spec_from_file_location(
        "fetch_g729_vectors", SCRIPTS / "fetch-g729-vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vale_packages(ini_text):
    """(StylesPath, [package names]) of a .vale.ini, packages in file order.

    A package is a name (`Google`) or the URL of a zip (`.../Google.zip`);
    `vale sync` writes each into StylesPath/<name>.
    """
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string("[root]\n" + ini_text)
    root = parser["root"]
    styles = root.get("StylesPath", "").strip()
    names = []
    for item in root.get("Packages", "").split(","):
        item = item.strip()
        if not item:
            continue
        name = item.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".zip"):
            name = name[: -len(".zip")]
        names.append(name)
    return styles, names


def find_vale(env):
    """The vale binary the prose gates would run, or None."""
    given = env.get("VALE_BIN")
    if given and os.access(given, os.X_OK):
        return given
    return shutil.which("vale", path=env.get("PATH"))


def missing(root, hook, env, vale_binary):
    """The prerequisites `hook` needs in the tree at `root` that are missing."""
    root = pathlib.Path(root)
    found = []
    if hook == "pre-commit" and (root / "crates/g729/Cargo.toml").is_file():
        fetch = _fetch_module()
        dest = pathlib.Path(env.get(fetch.ENV_VAR) or root / "crates/g729/test-vectors")
        if fetch.missing(dest):
            found.append(
                Missing("the ITU-T G.729 test vectors and table sources", dest, fetch.FETCH_COMMAND)
            )
    ini = root / ".vale.ini"
    if vale_binary and ini.is_file():
        styles, packages = vale_packages(ini.read_text())
        for package in packages:
            path = root / styles / package
            if not path.is_dir():
                found.append(Missing(f"the Vale style package {package}", path, "vale sync"))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("hook", help="pre-commit or pre-push")
    parser.add_argument("--root", type=pathlib.Path, default=SCRIPTS.parent)
    args = parser.parse_args(argv)
    if args.hook not in HOOKS:
        print(f"check-hook-prerequisites: the hook must be one of {', '.join(HOOKS)}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    found = missing(args.root, args.hook, env, find_vale(env))
    if not found:
        print("  Prerequisites... OK")
        return 0
    print("  Prerequisites... FAIL")
    for item in found:
        print(f"    missing: {item.name} ({item.path})")
        print(f"    run: {item.fix}")
    print(f"  A fresh worktree lacks these; the {args.hook} hook stops here, before any gate runs.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
