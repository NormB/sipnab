#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Fail when fuzz/Cargo.lock resolves a shared crate to a version Cargo.lock does not.

The fuzz workspace (`fuzz/`) is outside the root workspace and has its own
Cargo.lock. It builds the sipnab crate as a path dependency, so every crate
sipnab uses is resolved twice, once in each lockfile. Until 2026-11-10
Dependabot updated the two in separate pull requests (`.github/dependabot.yml`
had an entry per directory); it now has one entry for both directories, and
still resolves each lockfile on its own. Nothing compared them. On 2026-11-08
they disagreed on 56 of the
214 crates they share: clap 4.6.3 in Cargo.lock and 4.6.7 in fuzz/Cargo.lock,
cc 1.2.59 and 1.4.0, hybrid-array 0.4.15 and 0.4.13. The fuzz targets were
fuzzing dependency code the binary does not ship.

THE RULE: for every crate both lockfiles list, each version fuzz/Cargo.lock
holds is a version Cargo.lock holds, unless an entry in EXCEPTIONS names the
crate, those exact versions and the reason. A crate only one lockfile lists
passes: libfuzzer-sys and arbitrary exist only in the fuzz tree, and most of
the root's crates are behind features the fuzz targets do not enable.

Why "within the root's set" and not "equal to it": the root has more
dependents than the fuzz tree, so it can need several semver-incompatible
lines of one crate (hashbrown 0.15, 0.16 and 0.17) where the fuzz tree needs
one. Cargo resolves each semver-compatible line to one version per lockfile,
so a fuzz version that is in the root's set is the version the binary uses on
that line. Equality would demand the fuzz tree carry lines nothing in it uses.

A version both lockfiles list must also come from the same `source` with the
same `checksum`: the same number from a fork is different code.

An exception that no longer matches drift, in whole or in part, is reported
as stale. An exception that outlives its reason hides the next drift on the
same crate.

Usage:
    scripts/check-lockfile-drift.py [--root PATH] [--fuzz PATH]

Exit 0: the fuzz tree builds what ships. Exit 1: it does not; each line names
the crate, both version sets and, when Cargo.lock has a version on the same
semver-compatible line, the `cargo update --precise` that aligns it. Exit 2:
the check could not run (a lockfile missing, unparsable or malformed, or a
malformed exception). A check that did not run is not a pass.

CONTRIBUTING.md ("Keeping fuzz/Cargo.lock aligned with Cargo.lock") has the
how-to.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tomllib
from collections.abc import Iterable, Mapping

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (crate, the fuzz/Cargo.lock versions Cargo.lock may lack, why). Empty: on
# 2026-11-08 every shared crate was aligned to the root's versions, and no
# fuzz-only dependency needed a newer one.
EXCEPTIONS: tuple[tuple[str, tuple[str, ...], str], ...] = ()

ROOT_LABEL = "Cargo.lock"
FUZZ_LABEL = "fuzz/Cargo.lock"


class InputError(ValueError):
    """A lockfile or the exception table is not what the check can compare."""


# name -> version -> (source, checksum)
Packages = dict[str, dict[str, tuple[object, object]]]


def packages(lock: object, label: str) -> Packages:
    """Every package of a parsed Cargo.lock, by name and version."""
    if not isinstance(lock, Mapping) or not isinstance(lock.get("package"), list):
        raise InputError(f"{label}: no [[package]] list")
    entries = lock["package"]
    if not entries:
        raise InputError(f"{label}: no packages; a lockfile that lists nothing passes every comparison")
    out: Packages = {}
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, Mapping):
            raise InputError(f"{label}: package {index} is not a table")
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise InputError(f"{label}: package {index} has no text name and version")
        versions = out.setdefault(name, {})
        if version in versions:
            raise InputError(f"{label}: {name} {version} is listed twice")
        versions[version] = (entry.get("source"), entry.get("checksum"))
    return out


def exception_table(exceptions: Iterable[object]) -> dict[str, frozenset[str]]:
    """The exceptions by crate, each checked for a crate, versions and a reason."""
    table: dict[str, frozenset[str]] = {}
    for index, item in enumerate(exceptions, start=1):
        if not isinstance(item, tuple) or len(item) != 3:
            raise InputError(f"exception {index} is not (crate, versions, reason)")
        crate, versions, reason = item
        if not isinstance(crate, str) or not crate:
            raise InputError(f"exception {index} names no crate")
        if (
            not isinstance(versions, tuple)
            or not versions
            or not all(isinstance(v, str) and v for v in versions)
        ):
            raise InputError(f"exception {index} ({crate}) names no versions; give a tuple of version strings")
        if not isinstance(reason, str) or not reason.strip():
            raise InputError(f"exception {index} ({crate}) gives no reason")
        if crate in table:
            raise InputError(f"two exceptions name {crate}; give one with every version")
        table[crate] = frozenset(versions)
    return table


def release_line(version: str) -> tuple[int, ...] | None:
    """The semver-compatible line Cargo puts a version on, or None if it is not semver.

    1.2.3 and 1.9.0 share line (1,); 0.4.13 and 0.4.15 share (0, 4); every
    0.0.x is its own line. Build metadata and pre-release tags are ignored.
    """
    core = version.split("+", 1)[0].split("-", 1)[0]
    try:
        major, minor, patch = (int(x) for x in core.split("."))
    except ValueError:
        return None
    if major:
        return (major,)
    if minor:
        return (0, minor)
    return (0, 0, patch)


def describe_line(line: tuple[int, ...] | None) -> str:
    if line is None:
        return "no such"
    return ".".join(str(x) for x in line) + ".x"


def drift_message(name: str, extra: str, fuzz_set: set[str], root_set: set[str]) -> str:
    """One unaligned fuzz version, both sets, and the command that aligns it."""
    fuzz_text = ", ".join(sorted(fuzz_set))
    root_text = ", ".join(sorted(root_set))
    head = f"{name}: {FUZZ_LABEL} has {fuzz_text}, {ROOT_LABEL} has {root_text}; {extra} is not in {ROOT_LABEL}"
    line = release_line(extra)
    same_line = sorted(v for v in root_set if line is not None and release_line(v) == line)
    if len(same_line) == 1:
        return (
            f"{head}. Align it: cargo update --manifest-path fuzz/Cargo.toml "
            f"-p {name}@{extra} --precise {same_line[0]}"
        )
    if same_line:
        return (
            f"{head}; {ROOT_LABEL} has {' and '.join(same_line)} on the {describe_line(line)} line: "
            f"move {name}@{extra} in fuzz/Cargo.lock to whichever of them the fuzz tree's "
            f"requirements accept"
        )
    return (
        f"{head}, and {ROOT_LABEL} has no {describe_line(line)} line: move the crate that "
        f"pulls {name} {extra} in, or record an exception in scripts/check-lockfile-drift.py"
    )


def violations(root: object, fuzz: object, exceptions: Iterable[object]) -> list[str]:
    """Every way fuzz/Cargo.lock differs from Cargo.lock under THE RULE, sorted by crate.

    `root` and `fuzz` are parsed lockfiles (tomllib output). `exceptions` is
    a sequence of (crate, versions, reason). Raises InputError when either
    lockfile or the table cannot be compared.
    """
    root_pkgs = packages(root, ROOT_LABEL)
    fuzz_pkgs = packages(fuzz, FUZZ_LABEL)
    table = exception_table(exceptions)
    shared = sorted(set(root_pkgs) & set(fuzz_pkgs))
    if not shared:
        raise InputError(f"{ROOT_LABEL} and {FUZZ_LABEL} have no crate in common; these are not the two lockfiles")
    found: list[tuple[str, str]] = []
    for name in shared:
        root_set, fuzz_set = set(root_pkgs[name]), set(fuzz_pkgs[name])
        allowed = table.get(name, frozenset())
        for extra in sorted(fuzz_set - root_set):
            if extra not in allowed:
                found.append((name, drift_message(name, extra, fuzz_set, root_set)))
        for version in sorted(fuzz_set & root_set):
            source, checksum = root_pkgs[name][version]
            fuzz_source, fuzz_checksum = fuzz_pkgs[name][version]
            if source != fuzz_source:
                found.append(
                    (name, f"{name} {version}: source {fuzz_source} in {FUZZ_LABEL}, {source} in {ROOT_LABEL}")
                )
            elif checksum != fuzz_checksum:
                found.append(
                    (name, f"{name} {version}: checksum {fuzz_checksum} in {FUZZ_LABEL}, {checksum} in {ROOT_LABEL}")
                )
    for name, versions in sorted(table.items()):
        drifting = set(fuzz_pkgs[name]) - set(root_pkgs[name]) if name in shared else set()
        stale = sorted(versions - drifting)
        if stale:
            found.append(
                (
                    name,
                    f"{name}: stale exception for {', '.join(stale)}, which {FUZZ_LABEL} no longer holds "
                    f"outside {ROOT_LABEL}; remove it from EXCEPTIONS in scripts/check-lockfile-drift.py",
                )
            )
    return [message for _name, message in sorted(found, key=lambda item: item[0])]


def read_lock(path: pathlib.Path) -> object:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main(argv: list[str], exceptions: Iterable[object] = EXCEPTIONS) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--root", type=pathlib.Path, default=ROOT / "Cargo.lock")
    ap.add_argument("--fuzz", type=pathlib.Path, default=ROOT / "fuzz" / "Cargo.lock")
    args = ap.parse_args(argv)
    parsed = []
    for path in (args.root, args.fuzz):
        try:
            parsed.append(read_lock(path))
        except (OSError, tomllib.TOMLDecodeError) as e:
            print(f"NOT CHECKED: {path}: {e}", file=sys.stderr)
            return 2
    root, fuzz = parsed
    exceptions = tuple(exceptions)
    try:
        found = violations(root, fuzz, exceptions)
    except InputError as e:
        print(f"NOT CHECKED: {e}", file=sys.stderr)
        return 2
    shared = len(set(packages(root, ROOT_LABEL)) & set(packages(fuzz, FUZZ_LABEL)))
    if found:
        for message in found:
            print(message)
        print(
            f"{len(found)} violations in {shared} crates in both lockfiles: the fuzz targets "
            f"build dependency code the binary does not ship"
        )
        return 1
    print(
        f"ok: {shared} crates in both lockfiles, every {FUZZ_LABEL} version is one "
        f"{ROOT_LABEL} has ({len(exceptions)} exceptions)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
