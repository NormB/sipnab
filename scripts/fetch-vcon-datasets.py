#!/usr/bin/env python3
"""Fetch the public vCon datasets, each at a pinned commit, for the corpus test.

The vcon-dev community publishes real and synthetic vCon containers as git
repositories (listed at https://www.conserver.io/tools/vcon-datasets).
`tests/vcon_dataset_corpus_test.rs` reads every `*.vcon.json` in them when
SIPNAB_VCON_DATASETS names the directory this script fills. The datasets take
about 2.3 GB of disk once fetched, so they are not committed; a small subset is, under
tests/fixtures/vcon-datasets/.

What a fetch guarantees:

* Each dataset is checked out at exactly the commit tests/fixtures/
  vcon-datasets/PINS.tsv names, never a branch tip, and the checkout is
  verified after the fact: HEAD is that commit and the tree is unmodified.
* Only git runs. Nothing in a dataset is executed: hooks are pointed at
  /dev/null, symbolic links are checked out as plain files, and no
  submodule or LFS step runs.
* No GIT_* variable from the caller reaches git. Run from a pre-commit hook,
  an inherited GIT_DIR would point every command at the hook's repository.

Usage:
    fetch-vcon-datasets.py [--pins FILE] [DEST]

DEST defaults to $SIPNAB_VCON_DATASETS. Each dataset lands in DEST/<name>.
Exit codes: 0 every dataset fetched and verified, 1 one or more failed,
2 no destination.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys
from typing import NamedTuple

ENV_VAR = "SIPNAB_VCON_DATASETS"
DEFAULT_PINS = (pathlib.Path(__file__).resolve().parent.parent
                / "tests/fixtures/vcon-datasets/PINS.tsv")

# Settings every git call carries, so nothing in a dataset can run.
SAFE_CONFIG = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.symlinks=false",
    "-c", "submodule.recurse=false",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
    "-c", "advice.detachedHead=false",
]


class FetchError(Exception):
    """A dataset could not be fetched or did not verify."""


class Pin(NamedTuple):
    """One dataset: its directory name, repository, commit and license."""

    name: str
    url: str
    commit: str
    license: str


def read_pins(path):
    """Parse a PINS.tsv: `name<TAB>url<TAB>commit<TAB>license` per line.

    Blank lines and `#` comments are skipped. A line without four fields, or
    whose commit is not a full 40-hex SHA-1, raises FetchError: a short or
    symbolic commit is exactly what a pin exists to rule out.
    """
    pins = []
    for number, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise FetchError(f"{path}:{number}: expected 4 tab-separated fields")
        pin = Pin(*(f.strip() for f in fields))
        if not re.fullmatch(r"[0-9a-f]{40}", pin.commit):
            raise FetchError(f"{path}:{number}: commit {pin.commit!r} is not a "
                             "full 40-character SHA-1")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", pin.name):
            raise FetchError(f"{path}:{number}: name {pin.name!r} is not a plain "
                             "directory name")
        pins.append(pin)
    return pins


def _env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def _git(tree, *args):
    run = subprocess.run(
        ["git", *SAFE_CONFIG, "-C", str(tree), *args],
        env=_env(), capture_output=True, text=True, check=False,
    )
    if run.returncode != 0:
        raise FetchError(f"git {' '.join(args)} in {tree}: "
                         f"{run.stderr.strip() or run.stdout.strip()}")
    return run.stdout.strip()


def verify(pin, dest):
    """Raise FetchError unless DEST/<name> is `pin.commit`, unmodified."""
    tree = pathlib.Path(dest) / pin.name
    head = _git(tree, "rev-parse", "HEAD")
    if head != pin.commit:
        raise FetchError(f"{pin.name}: HEAD is {head}, the pin is {pin.commit}")
    status = _git(tree, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise FetchError(f"{pin.name}: the checkout has been modified or is not "
                         f"clean; delete {tree} and fetch again:\n{status}")


def fetch_one(pin, dest):
    """Check `pin` out into DEST/<name> at its commit, then verify it."""
    tree = pathlib.Path(dest) / pin.name
    if not (tree / ".git").is_dir():
        tree.mkdir(parents=True, exist_ok=True)
        _git(tree, "init", "-q")
        _git(tree, "remote", "add", "origin", pin.url)
    else:
        _git(tree, "remote", "set-url", "origin", pin.url)
    _git(tree, "fetch", "-q", "--depth", "1", "--no-tags",
         "--no-recurse-submodules", "origin", pin.commit)
    _git(tree, "checkout", "-q", "--detach", "--force", pin.commit)
    verify(pin, dest)


def count_containers(tree):
    """The `*.vcon.json` files under `tree`, outside `.git`."""
    return sum(
        1 for p in pathlib.Path(tree).rglob("*.vcon.json")
        if ".git" not in p.parts and p.is_file() and not p.is_symlink()
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dest", nargs="?", help=f"cache directory (default ${ENV_VAR})")
    parser.add_argument("--pins", default=str(DEFAULT_PINS))
    args = parser.parse_args(argv)

    dest = args.dest or os.environ.get(ENV_VAR)
    if not dest:
        print(f"no destination: give DEST or set {ENV_VAR}", file=sys.stderr)
        return 2

    failed = 0
    for pin in read_pins(args.pins):
        try:
            fetch_one(pin, dest)
        except FetchError as err:
            failed += 1
            print(f"FAIL {pin.name}: {err}", file=sys.stderr)
            continue
        count = count_containers(pathlib.Path(dest) / pin.name)
        print(f"{pin.name:36} {pin.commit[:12]}  {pin.license:13} {count} containers")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
