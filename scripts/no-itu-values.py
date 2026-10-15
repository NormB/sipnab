#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fail if a file holds a run of the G.729 codebook tables.

sipnab ships no ITU-T table values (docs/g729.md). This is the one scan that
enforces it, called by two gates:

* crates/g729/tests/no_itu_values.rs, over every file git tracks and every
  untracked file git does not ignore;
* the release workflow, over the built binaries and packages.

The values come from a table file built by the real importer
(`g729::import_from_itu`), given with --tables; this script holds none.

The rule. For every entry of the table file, every window of 6 consecutive
values is forbidden. A file is reported when:

* its text holds a run of 6 or more integer literals, separated only by
  whitespace, commas, semicolons, brackets, braces or parentheses, that
  contains a forbidden window (a literal touching a letter, digit, `_` or `.`
  is not an integer literal and ends the run); or
* its bytes hold a forbidden window encoded as 16-bit little-endian,
  16-bit big-endian or 32-bit little-endian integers, at any offset, which
  is how a compiled table would sit in a binary.

A directory is walked. A .tar.gz, .tgz, .tar.xz, .tar or .zip is opened and
each member scanned as a file. A report names the file (and member), the line
for text, and the table, never the values.

Usage:
    no-itu-values.py --tables FILE [--names a,b,...] [--git-repo DIR] [PATH ...]

--git-repo scans the files `git ls-files` and `git ls-files --others
--exclude-standard` name in DIR. --names gives the entries' names, in table
file order, for the reports. Exit codes: 0 nothing found, 1 found, 2 usage or
an unreadable table file.
"""

import argparse
import os
import pathlib
import struct
import subprocess
import sys
import tarfile
import zipfile

RUN = 6
MAGIC = b"G729TBL\0"
SEPARATORS = set(b" \t\r\n\v\f,;()[]{}")


def read_table_file(data):
    """The entries of a table file, as lists of values, in file order.

    Layout: magic, u16 version, u16 entry count, then per entry a u16 index,
    a u32 value count and the values as little-endian i16.
    """
    if not data.startswith(MAGIC) or len(data) < 12:
        raise ValueError("not a G.729 table file (bad magic)")
    (count,) = struct.unpack_from("<H", data, 10)
    at = 12
    entries = []
    for _ in range(count):
        if at + 6 > len(data):
            raise ValueError("not a G.729 table file (truncated)")
        _index, n = struct.unpack_from("<HI", data, at)
        at += 6
        if at + 2 * n > len(data):
            raise ValueError("not a G.729 table file (truncated)")
        entries.append(list(struct.unpack_from(f"<{n}h", data, at)))
        at += 2 * n
    if at != len(data):
        raise ValueError("not a G.729 table file (trailing bytes)")
    return entries


def forbidden_windows(entries):
    """Every window of RUN values, mapped to the index of its first entry."""
    windows = {}
    for i, values in enumerate(entries):
        for k in range(len(values) - RUN + 1):
            windows.setdefault(tuple(values[k : k + RUN]), i)
    return windows


def integer_runs(text):
    """Runs of RUN or more integer literals in `text`, each literal with its
    1-based line number."""
    b = text.encode("utf-8", "surrogateescape") if isinstance(text, str) else text
    runs, run, line, i = [], [], 1, 0

    def close():
        nonlocal run
        if len(run) >= RUN:
            runs.append(run)
        run = []

    def touches_word(k):
        c = b[k]
        return chr(c).isalnum() and c < 128 or c in (ord("_"), ord("."))

    while i < len(b):
        c = b[i]
        is_digit = 48 <= c <= 57
        if is_digit or (c == ord("-") and i + 1 < len(b) and 48 <= b[i + 1] <= 57):
            start = i
            if c == ord("-"):
                i += 1
            while i < len(b) and 48 <= b[i] <= 57:
                i += 1
            if (start > 0 and touches_word(start - 1)) or (i < len(b) and touches_word(i)):
                while i < len(b) and touches_word(i):
                    i += 1
                close()
                continue
            value = int(b[start:i])
            if -(2**31) <= value < 2**31:
                run.append((value, line))
            else:
                close()
            continue
        if c == 10:
            line += 1
        if c not in SEPARATORS:
            close()
        i += 1
    close()
    return runs


def binary_keys(windows):
    """Each window's byte encodings: (bytes, entry, encoding name)."""
    keys = {}
    for window, entry in windows.items():
        for name, fmt in (("le16", "<6h"), ("be16", ">6h"), ("le32", "<6i")):
            keys.setdefault(len(struct.pack(fmt, *window)), {})[struct.pack(fmt, *window)] = (
                entry,
                name,
            )
    return keys


def scan_bytes(label, data, windows, keys, names):
    """Reports for one file's contents."""
    found = []
    for run in integer_runs(data):
        for k in range(len(run) - RUN + 1):
            entry = windows.get(tuple(v for v, _ in run[k : k + RUN]))
            if entry is not None:
                found.append(f"{label}:{run[k][1]}: a run of table {names(entry)}")
                break
    seen = set()
    for size, table in keys.items():
        for at in range(len(data) - size + 1):
            hit = table.get(data[at : at + size])
            if hit is not None and hit not in seen:
                seen.add(hit)
                found.append(f"{label}: the values of table {names(hit[0])} as {hit[1]}")
    return found


ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.xz", ".tar")


def members(path):
    """(label, bytes) for a file, or for each member of an archive."""
    name = path.name
    if name.endswith(ARCHIVE_SUFFIXES):
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.isfile():
                    f = t.extractfile(m)
                    if f is not None:
                        yield f"{path}!{m.name}", f.read()
        return
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir():
                    yield f"{path}!{info.filename}", z.read(info)
        return
    yield str(path), path.read_bytes()


def files_under(paths):
    for p in paths:
        p = pathlib.Path(p)
        if p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs.sort()
                for n in sorted(names):
                    yield pathlib.Path(root) / n
        elif p.is_file():
            yield p


def git_files(repo):
    out = []
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    for extra in ([], ["--others", "--exclude-standard"]):
        listed = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", *extra],
            capture_output=True,
            check=True,
            env=env,
        ).stdout
        out += [pathlib.Path(repo) / p.decode() for p in listed.split(b"\0") if p]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tables", required=True, type=pathlib.Path)
    ap.add_argument("--names", default="")
    ap.add_argument("--git-repo", type=pathlib.Path)
    ap.add_argument("paths", nargs="*")
    args = ap.parse_args(argv)
    try:
        entries = read_table_file(args.tables.read_bytes())
    except (OSError, ValueError) as e:
        print(f"{args.tables}: {e}", file=sys.stderr)
        return 2
    given = [n for n in args.names.split(",") if n]
    names = lambda i: given[i] if i < len(given) else str(i)  # noqa: E731
    windows = forbidden_windows(entries)
    keys = binary_keys(windows)
    targets = list(files_under(args.paths))
    if args.git_repo:
        targets += [p for p in git_files(args.git_repo) if p.is_file()]
    found, scanned = [], 0
    for path in targets:
        try:
            for label, data in members(path):
                scanned += 1
                found += scan_bytes(label, data, windows, keys, names)
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as e:
            print(f"{path}: cannot read: {e}", file=sys.stderr)
            return 2
    if found:
        print(f"ITU-T G.729 table values found in {len(found)} place(s):")
        print("\n".join(found))
        return 1
    print(f"no-itu-values: {scanned} file(s) scanned against {len(windows)} runs; none found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
