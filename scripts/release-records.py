#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""The release records, and the advertisement commit that carries them.

    release-records.py ceiling --version X.Y.Z --tarball F --sums SHA256SUMS.txt [--config C]
    release-records.py fetch --tag vX.Y.Z --repo OWNER/NAME --dest DIR
    release-records.py write X.Y.Z --ceiling-line FILE --uprobe-row FILE [--root DIR]

Two records follow every release, and both used to be typed by hand into the
phase-two pull request:

* the binary-ceiling line in website/config.toml: the stripped `sipnab` of
  the published x86_64-musl tarball, in bytes, the change from the last line,
  and the headroom under `binary_size_ceiling_mb`;
* the eBPF load row in docs/internals/uprobe-capture.md, from
  `sudo scripts/verify-bpf-load.sh X.Y.Z` on a host with BTF.

RELEASE-FAST C. `ceiling` runs in release.yml's `records` job against the
published tarball, after checking it against the published SHA256SUMS.txt,
and the job uploads the line as the tag run's `release-records` artifact.
`fetch` downloads that artifact. `write` makes the advertisement commit's
changes in the tree: it inserts both records, regenerates the internals
mirror, and moves the advertised release with scripts/advertise-release.py,
the same writer pages.yml runs. The next release pull request carries that
commit, so no pull request of its own is needed.

Every function refuses rather than guesses: a version already recorded, one
older than the last record, a binary over the ceiling, a checksum mismatch, a
row that did not attach, or a pending-growth line the new measurement now
includes (it may wrap onto several lines, so it is retired by hand).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tarfile

_MEASURE = re.compile(r"(?m)^#\s+(\d+\.\d+\.\d+)\s+([0-9]{1,3}(?:,[0-9]{3})+)\s+bytes\b")
_PENDING = re.compile(r"(?m)^#\s+pending\s+\+[0-9,]+\s+bytes\s+against\s+(\d+\.\d+\.\d+)\b")
_CEILING = re.compile(r'(?m)^binary_size_ceiling_mb = "(\d+)"$')
_ROW = re.compile(r"^\| (\d+\.\d+\.\d+) \|")
ARTIFACT = "release-records"
LEDGER = "docs/internals/uprobe-capture.md"
CONFIG = "website/config.toml"


class RecordError(Exception):
    """A refusal; the message says why."""


def _key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def measurements(config: str) -> list[tuple[str, int]]:
    """(version, bytes) of every measurement line, in file order."""
    return [(m.group(1), int(m.group(2).replace(",", ""))) for m in _MEASURE.finditer(config)]


def ceiling_line(config: str, version: str, nbytes: int) -> str:
    m = _CEILING.search(config)
    if not m:
        raise RecordError(f"{CONFIG} has no binary_size_ceiling_mb")
    ceiling = int(m.group(1))
    found = measurements(config)
    if not found:
        raise RecordError(f"{CONFIG} has no measurement line to follow")
    if any(v == version for v, _ in found):
        raise RecordError(f"{version} is already recorded in {CONFIG}")
    last_v, last_b = found[-1]
    if _key(version) <= _key(last_v):
        raise RecordError(f"{version} is not newer than the last measurement, {last_v}")
    headroom = ceiling * 1048576 - nbytes
    if headroom < 0:
        raise RecordError(f"{nbytes:,} bytes is over the {ceiling} MB ceiling by {-headroom:,} bytes")
    delta = nbytes - last_b
    change = "unchanged" if delta == 0 else f"{delta:+,}"
    return f"#   {version}  {nbytes:,} bytes   ({change}, leaving {headroom:,} bytes of headroom under {ceiling} MB)"


def insert_ceiling(config: str, line: str) -> str:
    version = _MEASURE.match(line)
    if not version:
        raise RecordError(f"{line!r} is not a measurement line")
    included = [m.group(1) for m in _PENDING.finditer(config) if _key(m.group(1)) < _key(version.group(1))]
    if included:
        raise RecordError(
            f"a pending line against {included[0]} is now inside the {version.group(1)} measurement; "
            "retire it by hand first"
        )
    last = list(_MEASURE.finditer(config))[-1]
    end = config.index("\n", last.end())
    return config[: end + 1] + line + "\n" + config[end + 1 :]


def measure(tarball: pathlib.Path, sums: str) -> int:
    """Bytes of the one `sipnab` file in `tarball`, once its sha256 matches
    the line SHA256SUMS.txt gives it."""
    want = None
    for raw in sums.splitlines():
        parts = raw.split()
        if len(parts) == 2 and parts[1].lstrip("*") == tarball.name:
            want = parts[0]
    if want is None:
        raise RecordError(f"SHA256SUMS.txt has no line for {tarball.name}")
    got = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if got != want:
        raise RecordError(f"{tarball.name}: sha256 {got} is not the published {want}")
    with tarfile.open(tarball, "r:gz") as tf:
        found = [m for m in tf.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name == "sipnab"]
    if len(found) != 1:
        raise RecordError(f"{tarball.name} holds {len(found)} sipnab files" if found
                          else f"{tarball.name} holds no sipnab binary")
    return found[0].size


def insert_uprobe_row(md: str, row: str, version: str) -> str:
    row = row.strip()
    cells = [c.strip() for c in row.strip("|").split("|")]
    if not (row.startswith("|") and row.endswith("|")) or len(cells) != 6:
        raise RecordError(f"the row has {len(cells)} cells, not six: {row!r}")
    if cells[0] != version:
        raise RecordError(f"the row names {cells[0]}, not {version}")
    if not cells[5].startswith("attached"):
        raise RecordError(f"the row's result is {cells[5]!r}; only a load that attached is recorded")
    lines = md.split("\n")
    rows = [i for i, line in enumerate(lines) if _ROW.match(line)]
    if not rows:
        raise RecordError(f"{LEDGER} has no ledger row to follow")
    if any(_ROW.match(lines[i]).group(1) == version for i in rows):
        raise RecordError(f"{version} is already in the ledger")
    last = rows[-1]
    return "\n".join(lines[: last + 1] + [row] + lines[last + 1 :])


def records_run(runs: list, tag: str) -> int:
    """The id of the newest successful tag-push run of release.yml for `tag`
    (`gh run list` lists newest first)."""
    for r in runs:
        if r.get("headBranch") == tag and r.get("event") == "push" and r.get("conclusion") == "success":
            return r["databaseId"]
    raise RecordError(f"release.yml has no successful run for {tag}")


def _gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RecordError(f"`gh {' '.join(args)}` exited {out.returncode}: {out.stderr.strip()}")
    return out.stdout


def _advertise():
    path = pathlib.Path(__file__).resolve().parent / "advertise-release.py"
    spec = importlib.util.spec_from_file_location("advertise_release", path)
    mod = importlib.util.module_from_spec(spec)
    # dataclasses resolve their module through sys.modules.
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


def write(root: pathlib.Path, version: str, ceiling: str, row: str) -> None:
    config = (root / CONFIG).read_text(encoding="utf-8")
    ledger = (root / LEDGER).read_text(encoding="utf-8")
    new_config = insert_ceiling(config, ceiling.strip())
    if not ceiling.strip().startswith(f"#   {version}  "):
        raise RecordError(f"the ceiling line does not name {version}: {ceiling.strip()!r}")
    new_ledger = insert_uprobe_row(ledger, row, version)
    (root / CONFIG).write_text(new_config, encoding="utf-8")
    (root / LEDGER).write_text(new_ledger, encoding="utf-8")
    built = subprocess.run([sys.executable, str(root / "scripts/build-site-internals.py")], cwd=root,
                           capture_output=True, text=True)
    if built.returncode != 0:
        raise RecordError(f"build-site-internals.py exited {built.returncode}: {built.stderr.strip()}")
    ad = _advertise()
    try:
        ad.write(root, version)
    except ad.AdvertiseError as e:
        raise RecordError(str(e)) from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ceiling")
    p.add_argument("--version", required=True)
    p.add_argument("--tarball", required=True)
    p.add_argument("--sums", required=True)
    p.add_argument("--config", default=CONFIG)
    p = sub.add_parser("fetch")
    p.add_argument("--tag", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--dest", required=True)
    p = sub.add_parser("write")
    p.add_argument("version")
    p.add_argument("--ceiling-line", required=True)
    p.add_argument("--uprobe-row", required=True)
    p.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "ceiling":
            config = pathlib.Path(args.config).read_text(encoding="utf-8")
            nbytes = measure(pathlib.Path(args.tarball), pathlib.Path(args.sums).read_text(encoding="utf-8"))
            print(ceiling_line(config, args.version, nbytes))
        elif args.cmd == "fetch":
            runs = json.loads(_gh("run", "list", "-R", args.repo, "--workflow", "release.yml", "--branch",
                                  args.tag, "--json", "databaseId,headBranch,event,conclusion", "-L", "20"))
            _gh("run", "download", str(records_run(runs, args.tag)), "-R", args.repo, "-n", ARTIFACT,
                "-D", args.dest)
        else:
            write(pathlib.Path(args.root).resolve(), args.version,
                  pathlib.Path(args.ceiling_line).read_text(encoding="utf-8"),
                  pathlib.Path(args.uprobe_row).read_text(encoding="utf-8"))
    except (RecordError, OSError, json.JSONDecodeError, tarfile.TarError) as e:
        print(f"release-records: refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
