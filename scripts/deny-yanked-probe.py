#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Refuses a yanked crate version in either lock file, and proves that
cargo-deny, with this repository's deny.toml, refuses one.

    python3 scripts/deny-yanked-probe.py [CARGO_DENY_BINARY]

Run from anywhere; it reads the repository this script is in. Exit 0: both
lock files passed the advisories check and cargo-deny refused the probe's
yanked version. Exit 1: a lock file failed, deny.toml does not deny yanked
versions, cargo-deny accepted the yanked version, or cargo-deny could not
run.

NO-YANKED-VERSION-CHECK. A crate version is taken as soon as it is released
(the owner, 2026-11-24) and may be yanked days later. cargo-deny's
`[advisories] yanked` setting defaults to "warn": with it, the advisories
check printed `warning[yanked]` for a yanked version in Cargo.lock and exited
0 (cargo-deny 0.20.2, 2026-11-27). OSV-Scanner does not report a yank. So
deny.toml sets `yanked = "deny"`, and this probe proves the setting acts, with
the cargo-deny that runs it:

1. `config_problem` refuses a deny.toml whose `[advisories] yanked` is not
   exactly "deny", before anything runs.
2. `lock_commands` runs the advisories check on Cargo.lock and, when the
   fuzz workspace is there, on fuzz/Cargo.lock, which CI's `cargo deny
   check` does not read. Each run starts in the repository root, so it reads
   the root deny.toml.
3. `write_crate` writes, in a temporary directory, a crate that depends on
   autocfg 0.1.3, a version crates.io lists as yanked (checked 2026-11-27),
   with a Cargo.lock that holds it: cargo resolves a yanked version only from
   a lock file.
4. cargo-deny runs the advisories check on that crate with deny.toml.
5. `verdict` passes only when cargo-deny failed with an `error[yanked]`
   report that names autocfg 0.1.3 exactly.

The run needs crates.io's index and the RustSec advisory database, so it runs
in CI's Security audit job and in the pre-push hook, never in a test.
scripts/tests/test_deny_yanked_probe.py drives every step without the
network.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
DENY_TOML = ROOT / "deny.toml"

# A version crates.io lists as yanked, with no dependencies of its own, so the
# probe downloads one small crate: (name, version, sha256 of the .crate).
YANKED = ("autocfg", "0.1.3", "dfb37ca32a3d9d88f18d08bac8d28368b8ee1f14f8b08eb62999c51720035b55")

# The cargo-deny run's deadline, in seconds: a fresh advisory database clone
# and one index lookup.
TIMEOUT_S = 600

MANIFEST = """[package]
name = "yanked-probe"
version = "0.0.0"
edition = "2021"
license = "MIT OR Apache-2.0"
publish = false

[dependencies]
{name} = "={version}"

[workspace]
"""

LOCK = """version = 4

[[package]]
name = "{name}"
version = "{version}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"

[[package]]
name = "yanked-probe"
version = "0.0.0"
dependencies = [
 "{name}",
]
"""


def config_problem(text: str) -> str | None:
    """None when the deny.toml text sets `[advisories] yanked = "deny"`, else
    what it holds instead."""
    try:
        config = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return f"deny.toml is not valid TOML: {e}"
    advisories = config.get("advisories")
    if not isinstance(advisories, dict):
        return 'deny.toml has no [advisories] table; it needs yanked = "deny"'
    if "yanked" not in advisories:
        return 'deny.toml [advisories] has no `yanked` setting; cargo-deny then only warns on a yanked version'
    value = advisories["yanked"]
    if value != "deny":
        shown = f'"{value}"' if isinstance(value, str) else repr(value)
        return f'deny.toml [advisories] yanked is {shown}, not "deny"'
    return None


def write_crate(directory, yanked=YANKED) -> pathlib.Path:
    """The probe crate in `directory`; returns its manifest path."""
    name, version, checksum = yanked
    root = pathlib.Path(directory)
    (root / "src").mkdir()
    (root / "src" / "lib.rs").write_text("", encoding="utf-8")
    (root / "Cargo.toml").write_text(MANIFEST.format(name=name, version=version), encoding="utf-8")
    (root / "Cargo.lock").write_text(
        LOCK.format(name=name, version=version, checksum=checksum), encoding="utf-8"
    )
    return root / "Cargo.toml"


def lock_commands(binary: str, root: pathlib.Path) -> list[tuple[str, list[str]]]:
    """(lock file, cargo-deny command line) for each lock file under `root`.

    The fuzz targets are a workspace of their own, with fuzz/Cargo.lock;
    `--manifest-path` points cargo-deny at it, and the run's working
    directory, `root`, gives it the root deny.toml."""
    checks = [("Cargo.lock", [binary, "check", "advisories"])]
    if (pathlib.Path(root) / "fuzz" / "Cargo.toml").is_file():
        checks.append(
            ("fuzz/Cargo.lock", [binary, "--manifest-path", "fuzz/Cargo.toml", "check", "advisories"])
        )
    return checks


def command(binary: str, manifest: pathlib.Path, config: pathlib.Path) -> list[str]:
    """The cargo-deny command line the probe runs: the advisories check only."""
    return [binary, "--manifest-path", str(manifest), "--config", str(config), "check", "advisories"]


def yanked_lines(output: str) -> list[str]:
    """cargo-deny's `error[yanked]` lines, which name the crate to update."""
    return [line.strip() for line in output.splitlines() if "error[yanked]" in line]


def verdict(returncode: int, output: str, yanked=YANKED) -> str | None:
    """None when cargo-deny refused the yanked version, else the problem.

    The crate and version must appear as whole words, as cargo-deny prints
    them on the Cargo.lock line (`autocfg 0.1.3 registry+...`) or the tree
    line (`autocfg v0.1.3`): autocfg 0.1.30 is another version."""
    name, version, _ = yanked
    if returncode == 0:
        return f"cargo-deny accepted {name} {version}, which crates.io lists as yanked"
    named = re.search(
        rf"(?<![\w-]){re.escape(name)} v?{re.escape(version)}(?![\w.+-])", output
    )
    if "error[yanked]" not in output or not named:
        return (
            f"cargo-deny failed (exit {returncode}) without naming {name} {version} as yanked:\n"
            f"{output}"
        )
    return None


def main(argv, run=subprocess.run, config=DENY_TOML, root=ROOT) -> int:
    binary = argv[1] if len(argv) > 1 else "cargo-deny"
    name, version, _ = YANKED

    def fail(problem):
        print(f"deny-yanked-probe: {problem}", file=sys.stderr)
        return 1

    def cargo_deny(argv, cwd):
        """(exit status, output) of one cargo-deny run, or (None, problem)."""
        try:
            done = run(argv, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_S)
        except FileNotFoundError:
            return None, f"{binary} is not installed (cargo install cargo-deny)"
        except subprocess.TimeoutExpired:
            return None, f"{binary} ran past its deadline of {TIMEOUT_S} s"
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    try:
        text = pathlib.Path(config).read_text(encoding="utf-8")
    except OSError as e:
        return fail(f"cannot read {config}: {e}")
    problem = config_problem(text)
    if problem:
        return fail(problem)
    for lock, argv_ in lock_commands(binary, root):
        rc, output = cargo_deny(argv_, root)
        if rc is None:
            return fail(output)
        if rc != 0:
            named = yanked_lines(output)
            said = "\n".join(named) if named else output
            return fail(
                f"{lock} fails cargo-deny's advisories check (exit {rc}); "
                f"reproduce with `{' '.join(argv_)}`:\n{said}"
            )
        print(f"deny-yanked-probe: {lock}: advisories ok")
    with tempfile.TemporaryDirectory(prefix="yanked-probe-") as directory:
        manifest = write_crate(directory)
        rc, output = cargo_deny(command(binary, manifest, pathlib.Path(config)), directory)
    if rc is None:
        return fail(output)
    problem = verdict(rc, output)
    if problem:
        return fail(problem)
    print(f"deny-yanked-probe: ok (cargo-deny refused yanked {name} {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
