#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate the sipnab-diagnosis YANG module with two YANG implementations.

    python3 scripts/check-yang.py

The module under ``yang/`` is generated from the analysis's own tables, and
``tests/yang_module_test.rs`` holds the committed file equal to that
generator. What no Rust test can say is whether the TEXT is a valid YANG
module. Two implementations that did not write it answer that:

* ``pyang -Werror --lint`` and ``yanglint`` compile the newest revision;
* ``pyang --check-update-from`` holds every revision to the one before it --
  RFC 7950 section 11, the rules that let a published module only grow.

Exit codes follow ``scripts/prose-gates.sh``:

    0  checked, and clean
    1  checked, and something failed -- the lines above say what
    2  NOT CHECKED -- the first line of output says why

Return 2 is not a pass, and callers must not render it as one. With
``SIPNAB_YANG_REQUIRED=1`` a missing tool is a failure (exit 1) instead: CI
installs both tools and sets it, so the one place that must check cannot
quietly stop checking.

Tools resolve from ``YANGLINT_BIN`` / ``PYANG_BIN`` first, then ``PATH``. The
override exists for a build of either kept outside ``PATH``, the way
``VALE_BIN`` does for vale.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
MODULE = "sipnab-diagnosis"
REVISION_FILE = re.compile(rf"^{re.escape(MODULE)}@(\d{{4}}-\d{{2}}-\d{{2}})\.yang$")


def resolve(tool: str, env_var: str) -> str | None:
    """The tool's path: the override variable first, then PATH."""
    override = os.environ.get(env_var, "").strip()
    if override:
        return override if os.access(override, os.X_OK) else None
    return shutil.which(tool)


def revisions(module_dir: pathlib.Path) -> list[pathlib.Path]:
    """Every ``sipnab-diagnosis@DATE.yang`` in ``module_dir``, oldest first."""
    if not module_dir.is_dir():
        return []
    found = []
    for path in module_dir.iterdir():
        m = REVISION_FILE.match(path.name)
        if m:
            found.append((m.group(1), path))
    return [p for _, p in sorted(found)]


def bundled_modules(pyang: str) -> list[str]:
    """Where pyang keeps the IETF modules it ships, ietf-yang-types among them.

    ``--check-update-from`` loads the OLD revision in a repository built from
    ``-P`` alone, with pyang's default search path switched off -- so without
    this, the old module's ``import ietf-yang-types`` fails and every update
    check reports an import error instead of a verdict.
    """
    prefix = pathlib.Path(pyang).resolve().parent.parent
    candidates = [
        prefix / "share" / "yang" / "modules",
        pathlib.Path("/usr/share/yang/modules"),
        pathlib.Path("/usr/local/share/yang/modules"),
    ]
    return [str(c) for c in candidates if c.is_dir()]


def run(argv: list[str]) -> tuple[int, str]:
    """Run a tool; its exit status and everything it printed."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check(module_dir: pathlib.Path) -> int:
    """Run every check. See the module docstring for the exit codes."""
    required = os.environ.get("SIPNAB_YANG_REQUIRED") == "1"
    yanglint = resolve("yanglint", "YANGLINT_BIN")
    pyang = resolve("pyang", "PYANG_BIN")
    if yanglint is None or pyang is None:
        missing = [n for n, p in (("yanglint", yanglint), ("pyang", pyang)) if p is None]
        reason = (
            f"{' and '.join(missing)} not installed (yanglint: the libyang2-tools "
            "package; pyang: pip install --require-hashes -r scripts/requirements-yang.txt)"
        )
        if required:
            print(f"FAIL -- {reason}, and SIPNAB_YANG_REQUIRED=1")
            return 1
        print(f"NOT CHECKED -- {reason}")
        return 2

    modules = revisions(module_dir)
    if not modules:
        print(f"FAIL -- no {MODULE}@<revision>.yang under {module_dir}")
        return 1
    newest = modules[-1]
    failures: list[str] = []

    # Any output at all is a finding: -Werror makes pyang's warnings errors,
    # and yanglint prints nothing for a module it accepts.
    rc, out = run([pyang, "-Werror", "--lint", "-p", str(module_dir), str(newest)])
    if rc != 0 or out:
        failures.append(f"pyang --lint {newest.name}:\n{out}")
    rc, out = run([yanglint, "-p", str(module_dir), str(newest)])
    if rc != 0 or out:
        failures.append(f"yanglint {newest.name}:\n{out}")

    # RFC 7950 section 11, between every pair of consecutive revisions. With
    # one revision there is no pair, and that is not a skip: nothing has been
    # published that a change could break.
    old_path = os.pathsep.join([str(module_dir), *bundled_modules(pyang)])
    for older, newer in zip(modules, modules[1:]):
        rc, out = run([pyang, "--check-update-from", str(older), "-P", old_path, str(newer)])
        if rc != 0 or out:
            failures.append(f"pyang --check-update-from {older.name} {newer.name}:\n{out}")

    if failures:
        for failure in failures:
            print(f"FAIL -- {failure}")
        return 1
    print(
        f"OK -- {newest.name}: pyang --lint and yanglint clean, "
        f"{len(modules) - 1} revision update(s) checked"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the checks."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--module-dir",
        type=pathlib.Path,
        default=REPO / "yang",
        help="where the module revisions live (default: yang/)",
    )
    args = parser.parse_args(argv)
    return check(args.module_dir)


if __name__ == "__main__":
    sys.exit(main())
