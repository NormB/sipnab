#!/usr/bin/env python3
"""Publish this workspace's crates to crates.io, from the release workflow.

Run by the `crates-io` job in `.github/workflows/release.yml` after the GitHub
release exists, with a short-lived token that job exchanges through crates.io
trusted publishing. By hand it is the same command, with a token in
`~/.cargo/credentials.toml` or `CARGO_REGISTRY_TOKEN`:

    python3 scripts/publish-crates.py --tag v0.5.181

A crates.io version can never be replaced -- `cargo yank` stops new lockfiles
resolving to it, and nothing removes it -- so every decision is made before
anything is uploaded:

1. The crates are the workspace members without `publish = false`, each after
   the members it depends on by path.
2. The tag must be `v` plus the root crate's version.
3. crates.io is asked about every crate: 200 means that version is published
   and is skipped (sipnab-bpf-types is bumped only when it changes), 404 means
   it is not and is uploaded. Any other answer stops the run before the first
   upload. crates.io answers 403 to a request without a User-Agent, and
   neither reading of a 403 is safe.

Then `cargo publish --locked -p <name>` runs for each crate in order and the
run stops at the first failure: a crate cannot go up against a path dependency
whose new version did not. `cargo publish` waits until each upload is in the
index, so the next crate resolves against it.
"""

import argparse
import pathlib
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from typing import Callable, NamedTuple

REPO = pathlib.Path(__file__).resolve().parent.parent
USER_AGENT = "sipnab-release (https://github.com/NormB/sipnab)"


class Crate(NamedTuple):
    name: str
    version: str


class PublishError(Exception):
    pass


def _manifest(path: pathlib.Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _path_dependencies(manifest: dict) -> list[str]:
    """Names this manifest depends on by path, from every table cargo keeps in
    a published manifest. Dev-dependencies are left out: cargo drops a path
    dev-dependency that has no version when it packages the crate."""
    tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
    return [
        spec.get("package", name)
        for table in tables
        for name, spec in table.items()
        if isinstance(spec, dict) and "path" in spec
    ]


def publishable(repo: pathlib.Path) -> list[Crate]:
    """The workspace members crates.io should carry, each after the members it
    depends on by path."""
    root = _manifest(repo / "Cargo.toml")
    found: dict[str, tuple[str, list[str]]] = {}
    for member in root["workspace"]["members"]:
        manifest = _manifest(repo / member / "Cargo.toml")
        package = manifest["package"]
        if package.get("publish", True) is False:
            continue
        found[package["name"]] = (package["version"], _path_dependencies(manifest))

    ordered: list[Crate] = []
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if any(c.name == name for c in ordered):
            return
        if name in visiting:
            raise PublishError(f"path dependencies form a cycle through {name}")
        visiting.add(name)
        version, deps = found[name]
        for dep in deps:
            if dep in found:
                visit(dep)
        visiting.discard(name)
        ordered.append(Crate(name, version))

    for name in found:
        visit(name)
    return ordered


def plan(crates: list[Crate], status_of: Callable[[Crate], int]) -> list[Crate]:
    """The crates to upload: those crates.io answers 404 for. Every crate is
    asked before this returns, so an answer that is neither 200 nor 404 stops
    the run before anything goes up."""
    todo = []
    for crate in crates:
        status = status_of(crate)
        if status == 200:
            print(f"{crate.name} {crate.version} is already on crates.io; not uploading it again")
        elif status == 404:
            todo.append(crate)
        else:
            raise PublishError(
                f"crates.io answered {status} for {crate.name} {crate.version}; "
                "only 200 (published) and 404 (not published) say what to do"
            )
    return todo


def crates_io_status(api: str, crate: Crate) -> int:
    url = f"{api.rstrip('/')}/api/v1/crates/{crate.name}/{crate.version}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tag", required=True, help="the release tag, e.g. v0.5.181")
    parser.add_argument("--api", default="https://crates.io", help="registry web API base URL")
    parser.add_argument("--cargo", default="cargo", help="cargo executable")
    args = parser.parse_args(argv)

    try:
        crates = publishable(REPO)
        root = _manifest(REPO / "Cargo.toml")["package"]["version"]
        if args.tag != f"v{root}":
            raise PublishError(
                f"tag {args.tag} does not name the version in Cargo.toml ({root}); "
                "nothing was uploaded"
            )
        todo = plan(crates, lambda crate: crates_io_status(args.api, crate))
    except PublishError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for crate in todo:
        print(f"publishing {crate.name} {crate.version}", flush=True)
        done = subprocess.run([args.cargo, "publish", "--locked", "-p", crate.name], cwd=REPO)
        if done.returncode != 0:
            print(
                f"error: cargo publish failed for {crate.name} {crate.version}; "
                "stopping before the crates that depend on it",
                file=sys.stderr,
            )
            return done.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
