#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Which release the site advertises, and the one writer that moves it.

    advertise-release.py resolve --repo OWNER/NAME [--expect X.Y.Z] [--root DIR]
    advertise-release.py write X.Y.Z [--root DIR]
    advertise-release.py site --repo OWNER/NAME [--expect X.Y.Z] [--root DIR]

Before RELEASE-FAST C a release finished in a second pull request ("phase
two") that moved `published_version`, `release_date` and the download markers
of docs/install.md once the assets existed. On 0.5.238 that pull request, its
hooks and its CI cost about 70 of the 284 minutes from start to site.

THE RULE (`newest_to_advertise`, the one place it is written). The site
advertises the numerically newest GitHub release that

* is tagged vX.Y.Z, and X.Y.Z is not newer than the crate version of the tree
  being built;
* is neither a draft nor a prerelease (marking a release as a prerelease is
  how it is withdrawn from the site);
* is complete: every asset is uploaded, and its asset names, with the version
  written as <v>, include every name of the newest older release that is
  itself complete. The oldest release, with nothing to compare against, must
  carry SHA256SUMS.txt and SHA256SUMS.txt.sigstore.json.

A release that drops an asset is therefore not advertised until this rule
changes with it: the site keeps the previous release rather than offer a
download set nobody checked.

`resolve` prints that version. `write` moves website/config.toml's
`published_version` and `release_date` (the date of the version's CHANGELOG
heading) and every download marker of docs/install.md (the patterns in
scripts/download-markers.txt, which tests/docs_drift_test.rs reads too), then
regenerates the site mirrors with scripts/build-site-pages.py. `site` does
both; pages.yml runs it before `zola build`, so the built site advertises the
newest complete release whatever the committed tree says. With --expect, the
resolved version must be that one, or the command fails: the release workflow
passes the tag it just published, so an incomplete release fails that run
instead of leaving the site on the previous version without a word.

Exit 0 on success, 1 on any refusal, with the reason on stderr. Needs `gh`
with a token that can read the repository's releases for resolve and site.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

_SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_PUBLISHED = re.compile(r'(?m)^published_version = "([^"]*)"$')
_DATE = re.compile(r'(?m)^release_date = "([^"]*)"$')
_CRATE = re.compile(r'(?m)^version = "([^"]*)"$')
# The oldest release has no predecessor to compare with; these it must carry.
BASELINE = ("SHA256SUMS.txt", "SHA256SUMS.txt.sigstore.json")
MARKERS = "scripts/download-markers.txt"
INSTALL = "docs/install.md"
CONFIG = "website/config.toml"


class AdvertiseError(Exception):
    """A refusal; the message says why."""


def version_key(text: str) -> tuple[int, int, int] | None:
    m = _SEMVER.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(g) for g in m.groups()) if m else None


def _names(release: dict, version: str) -> set[str] | None:
    """The release's asset names with the version written as <v>, or None
    when an asset is not fully uploaded."""
    out = set()
    for a in release.get("assets") or []:
        if a.get("state") != "uploaded":
            return None
        out.add(a["name"].replace(version, "<v>"))
    return out


def newest_to_advertise(releases: list, crate_version: str) -> tuple[str, str]:
    """(version, reason) under THE RULE; AdvertiseError when none qualifies."""
    ceiling = version_key(crate_version)
    if ceiling is None:
        raise AdvertiseError(f"the crate version {crate_version!r} is not x.y.z")
    candidates = []
    for r in releases:
        tag = r.get("tag_name", "")
        key = version_key(tag[1:]) if tag.startswith("v") else None
        if key is None or key > ceiling or r.get("draft") or r.get("prerelease"):
            continue
        candidates.append((key, tag[1:], r))
    candidates.sort(key=lambda c: c[0])
    complete: list[tuple[str, set[str]]] = []
    refused: dict[str, str] = {}
    for _key, version, r in candidates:
        names = _names(r, version)
        if names is None:
            refused[version] = f"v{version} has an asset that is not fully uploaded"
            continue
        want = complete[-1][1] if complete else set(BASELINE)
        missing = sorted(want - names)
        if missing:
            against = f"v{complete[-1][0]}" if complete else "the baseline"
            refused[version] = f"v{version} lacks {', '.join(missing)}, which {against} has"
            continue
        complete.append((version, names))
    if not complete:
        why = "; ".join(refused.values()) or "no release is tagged x.y.z, published and at or below the crate version"
        raise AdvertiseError(f"no complete release to advertise: {why}")
    version, names = complete[-1]
    newer = [refused[v] for _k, v, _r in candidates if v in refused and version_key(v) > version_key(version)]
    why = f"v{version} is published with {len(names)} assets"
    if newer:
        why += f" ({'; '.join(newer)})"
    return version, why


def check_expected(resolved: str, expected: str, reason: str) -> None:
    if resolved != expected:
        raise AdvertiseError(
            f"expected to advertise {expected}, but the newest complete release is {resolved}: {reason}"
        )


def load_markers(text: str) -> list[re.Pattern]:
    out = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        pat = re.compile(line)
        if pat.groups != 1:
            raise AdvertiseError(f"marker {line!r} has {pat.groups} capture groups, not exactly one capture group")
        out.append(pat)
    return out


def move_markers(text: str, markers: list, old: str, new: str) -> tuple[str, int]:
    """Every marker's captured version moved from `old` to `new`, and how many
    moved. Refuses a marker that matches nothing or names a third version."""
    spans = []
    for pat in markers:
        found = list(pat.finditer(text))
        if not found:
            raise AdvertiseError(f"{INSTALL}: marker {pat.pattern!r} matches no line; the page changed")
        for m in found:
            if m.group(1) not in (old, new):
                raise AdvertiseError(
                    f"{INSTALL}: marker {pat.pattern!r} names {m.group(1)}, neither {old} nor {new}"
                )
            if m.group(1) == old and old != new:
                spans.append(m.span(1))
    out = text
    for start, end in sorted(set(spans), reverse=True):
        out = out[:start] + new + out[end:]
    return out, len(set(spans))


def published_version(config: str) -> str:
    m = _PUBLISHED.search(config)
    if not m:
        raise AdvertiseError(f"{CONFIG} has no published_version line")
    return m.group(1)


def move_config(config: str, version: str, date: str) -> str:
    published_version(config)
    if not _DATE.search(config):
        raise AdvertiseError(f"{CONFIG} has no release_date line")
    out = _PUBLISHED.sub(f'published_version = "{version}"', config, count=1)
    return _DATE.sub(f'release_date = "{date}"', out, count=1)


def release_date(changelog: str, version: str) -> str:
    m = re.search(rf"(?m)^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})$", changelog)
    if not m:
        raise AdvertiseError(f"CHANGELOG.md has no `## [{version}] - YYYY-MM-DD` heading")
    return m.group(1)


def write(root: pathlib.Path, version: str) -> int:
    """Move the tree at `root` to advertise `version`; the marker count."""
    if version_key(version) is None:
        raise AdvertiseError(f"{version!r} is not x.y.z")
    config = (root / CONFIG).read_text(encoding="utf-8")
    old = published_version(config)
    date = release_date((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    markers = load_markers((root / MARKERS).read_text(encoding="utf-8"))
    install, moved = move_markers((root / INSTALL).read_text(encoding="utf-8"), markers, old, version)
    (root / CONFIG).write_text(move_config(config, version, date), encoding="utf-8")
    (root / INSTALL).write_text(install, encoding="utf-8")
    built = subprocess.run([sys.executable, str(root / "scripts/build-site-pages.py")], cwd=root,
                           capture_output=True, text=True)
    if built.returncode != 0:
        raise AdvertiseError(f"build-site-pages.py exited {built.returncode}: {built.stderr.strip()}")
    print(f"advertise-release: {old} -> {version} ({date}), {moved} download markers", file=sys.stderr)
    return moved


def read_releases(repo: str) -> list:
    out = subprocess.run(["gh", "api", f"repos/{repo}/releases?per_page=30"], capture_output=True, text=True)
    if out.returncode != 0:
        raise AdvertiseError(f"`gh api repos/{repo}/releases` exited {out.returncode}: {out.stderr.strip()}")
    return json.loads(out.stdout)


def resolve(repo: str, root: pathlib.Path, expect: str | None) -> str:
    crate = _CRATE.search((root / "Cargo.toml").read_text(encoding="utf-8"))
    if not crate:
        raise AdvertiseError("Cargo.toml has no version line")
    version, why = newest_to_advertise(read_releases(repo), crate.group(1))
    if expect is not None:
        check_expected(version, expect, why)
    print(f"advertise-release: {why}", file=sys.stderr)
    return version


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("resolve", "site"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
        p.add_argument("--expect")
        p.add_argument("--root", default=".")
    p = sub.add_parser("write")
    p.add_argument("version")
    p.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root).resolve()
    try:
        if args.cmd == "write":
            write(root, args.version)
        else:
            if args.expect is not None and version_key(args.expect) is None:
                raise AdvertiseError(f"--expect {args.expect!r} is not x.y.z")
            version = resolve(args.repo, root, args.expect)
            if args.cmd == "resolve":
                print(version)
            else:
                write(root, version)
    except (AdvertiseError, OSError, json.JSONDecodeError) as e:
        print(f"advertise-release: refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
