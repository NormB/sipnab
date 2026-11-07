#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Pass stamps for the git hooks: skip a check that already passed on the same inputs.

    gate-cache.py keys HOOK [--hook-file PATH]         "<step> <key>" per cached step, "info <text>" lines
    gate-cache.py hit HOOK STEP KEY [--line hook|step] [--quiet]
    gate-cache.py pass HOOK STEP KEY [STEP KEY ...] [--hook-file PATH]
    gate-cache.py classify [PATH ...]                  each path's class, then the change's
    gate-cache.py list                                 the stamps of this worktree
    gate-cache.py clear                                remove them

In the host's heavy-run log from 2026-11-06T13:04Z to 2026-11-07T22:14Z, hook
runs were 631 of the 1,128 minutes of main-slot run time, and nine times a hand
run of the pre-commit hook that passed was followed, from the same directory,
by `git commit` running it again (40.4 minutes). When a cached step passes, the hook records a stamp under
`<git dir>/sipnab-gate-pass/`. A later run whose key is identical prints one
line naming the stamp and skips the step. Any difference in the key means the
step runs.

THE KEY is a SHA-256 over every input the step reads:

* the files: every tracked and untracked (not ignored) path with its content
  id, as git would store it (so an edit reverted before the run reads as no
  edit), and the ignored files outside build directories by size and
  modification time;
* for a step that reads every file (the suite, the prose linters, the whole
  hook): also the index tree (`git write-tree`), HEAD, and the tags, because
  tests/release_delivery_test.rs and others read git history;
* for a build-only step (clippy, rustdoc, cargo check): only the paths
  `path_class` calls BUILD. A change of documentation alone leaves that key
  as it was, so those steps keep their stamp;
* a hash of the hook file and of every file under its scripts/ and .config/
  directories, so a changed hook or a changed script it calls is a new key;
* Cargo.lock, `rustc -Vv`, the cargo-nextest version, the Python and pytest
  versions, the vale and codespell versions;
* the environment variables that can change a verdict (`cache_env`);
* the step's command, as STEPS spells it (its feature set included). The
  test suite holds each spelling to the hook's text.

THE TEST SUITE READS EVERY TRACKED FILE. tests/repo_hygiene_test.rs scans every
path `git ls-files` lists for conflict markers, tests/private_identity_test.rs
scans every tracked text file, and tests/source_file_headers_test.rs reads the
header of every tracked file. So no change to a tracked path, documentation
included, can skip the suite: its key covers every file. A docs-only change
skips the build-only steps, never the suite.

THE STAMP DIRECTORY is the worktree's own git dir (`git rev-parse --git-dir`),
not the common dir. The key covers the worktree's untracked and ignored files,
which belong to that worktree alone, so a stamp from one worktree could not
match another; a directory per worktree means two worktrees never write the
same directory, and `git worktree remove` deletes the stamps with the worktree.

A stamp is written only after its step passed, to a temporary file renamed into
place, and only when the step's key computed again at that moment equals the
key from the start of the run: a tree edited while the step ran gets no stamp.
A run that fails or is killed writes none. A stamp that does not parse, whose
checksum or key does not match its name, that is older than MAX_AGE or dated
in the future, is no stamp. Every write prunes the directory: stamps older
than MAX_AGE, all but the newest MAX_COUNT, and temporary files older than
TMP_MAX_AGE.

SIPNAB_GATE_NO_CACHE=1 makes every lookup miss, so every step runs; a step
that passes still writes its stamp.

What the key cannot see: a test that reads state outside the repository (the
other worktrees of the clone, the home directory) can change its verdict
without changing the key. MAX_AGE bounds how long a stamp stands for such a
check; SIPNAB_GATE_NO_CACHE=1 re-checks at once.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.metadata
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

SCHEMA = 1
STAMP_DIR = "sipnab-gate-pass"
# A stamp stands for a week at most, and the directory keeps the newest 256.
MAX_AGE = 7 * 24 * 3600
MAX_COUNT = 256
# A temporary file this old belongs to a writer that died.
TMP_MAX_AGE = 3600
# A stamp dated later than this past the clock is from a clock that moved.
FUTURE_SLACK = 60

BUILD = "build"
DOCS = "docs"
ALL = "all"

# The steps each hook caches: (what the step reads, its command as the hook
# spells it). BUILD steps read the BUILD paths; ALL steps read every path.
STEPS: dict[str, dict[str, tuple[str, str]]] = {
    "pre-commit": {
        "hook": (ALL, 'echo -e "${GREEN}All pre-commit checks passed.${NC}"'),
        "clippy": (BUILD, "cargo clippy --workspace --all-features --all-targets --color never -- -D warnings"),
        "tests": (ALL, "-- --features full --color never"),
        "bpf-types": (BUILD, "cargo test -p sipnab-bpf-types --no-fail-fast --color never"),
        "script-tests": (ALL, "python3 -m pytest tests/ -q"),
    },
    "pre-push": {
        "clippy": (BUILD, "cargo clippy --workspace --all-features --all-targets -- -D warnings; then"),
        "doc": (BUILD, 'RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace; then'),
        "fuzz-clippy": (BUILD, "( cd fuzz && cargo clippy --all-targets -- -D warnings ); then"),
        "bpf-clippy": (BUILD, "( cd bpf && cargo clippy -- -D warnings ); then"),
        "check-tls": (BUILD, 'cargo check --no-default-features --features "$combo" --tests; then'),
        "check-api": (BUILD, 'cargo check --no-default-features --features "$combo" --tests; then'),
        "clippy-no-default": (BUILD, "cargo clippy --no-default-features --lib -- -D warnings; then"),
        "wasm": (BUILD, 'cargo check --target "$WASM_TARGET" --no-default-features --features wasm --lib; then'),
        "cross-arch": (BUILD, 'cargo clippy --target "$CROSS_TARGET" --features full --tests -- -D warnings; then'),
        "non-linux": (BUILD, 'NONLINUX_OUTPUT=$(sh "$NONLINUX_GATE" 2>&1)'),
        "vale": (ALL, "prose_vale_run && prose_rc=0 || prose_rc=$?"),
        "codespell": (ALL, "prose_codespell_run && prose_rc=0 || prose_rc=$?"),
    },
}

# ── The classifier ────────────────────────────────────────────────────────
#
# One rule: can this path change what cargo compiles? A path is DOCS only when
# it sits under a documentation root, is not Rust, not a manifest or toolchain
# file, and no Rust file includes it (`include_str!`, `include_bytes!`,
# `include!`). Everything else is BUILD, including every path this rule does
# not know: when unsure, it is code. DOCS does NOT mean the suite may skip it:
# the suite reads every tracked file (see the module docstring).

DOCS_ROOTS = ("docs/", "website/", "man/")
_BUILD_NAMES = re.compile(r"(^|/)(Cargo\.[^/]*|build\.rs|rust-toolchain(\.toml)?|\.rustfmt-toolchain)$")


def path_class(path: str, compiled: frozenset[str] | None) -> str:
    """BUILD when `path` can change what cargo compiles, else DOCS.

    `compiled` is what `compiled_references` found; None means an include
    could not be read, so every path is BUILD.
    """
    if compiled is None or path in compiled:
        return BUILD
    if path.endswith(".rs") or _BUILD_NAMES.search(path):
        return BUILD
    if path.startswith(DOCS_ROOTS):
        return DOCS
    if "/" not in path and path.lower().endswith(".md"):
        return DOCS
    return BUILD


def change_class(paths, compiled: frozenset[str] | None) -> str:
    """BUILD when any of `paths` is BUILD, DOCS when all are DOCS, "none" for no paths."""
    paths = list(paths)
    if not paths:
        return "none"
    if any(path_class(p, compiled) == BUILD for p in paths):
        return BUILD
    return DOCS


# Comments and string literals first, so an include written inside one is
# skipped whole; then the include macros themselves.
_LEX = re.compile(
    r"""
    (?P<line>//[^\n]*)
  | (?P<block>/\*.*?\*/)
  | (?P<raw>(?<![A-Za-z0-9_])b?r(?P<hashes>\#*)".*?"(?P=hashes))
  | (?P<str>(?<![A-Za-z0-9_])b?"(?:\\.|[^"\\])*")
  | (?P<char>(?<![A-Za-z0-9_])b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^'\\\n])')
  | (?P<inc>(?<![A-Za-z0-9_])include(?:_str|_bytes)?!\s*\()
    """,
    re.X | re.S,
)
_LITERAL = re.compile(r'\s*"((?:\\.|[^"\\])*)"\s*\)')
_RAW_LITERAL = re.compile(r'\s*r(#*)"(.*?)"\1\s*\)', re.S)
_CONCAT = re.compile(
    r'\s*concat!\s*\(\s*env!\s*\(\s*"(CARGO_MANIFEST_DIR|OUT_DIR)"\s*\)\s*,\s*"((?:\\.|[^"\\])*)"\s*\)\s*\)'
)


class _Unreadable(Exception):
    """An include whose argument this rule cannot resolve."""


def _includes(source: str):
    """(kind, text) for every include macro in code: ("rel"|"manifest"|"out", path)."""
    for m in _LEX.finditer(source):
        if m.lastgroup != "inc":
            continue
        rest = source[m.end() :]
        lit = _LITERAL.match(rest)
        if lit:
            yield "rel", lit.group(1)
            continue
        raw = _RAW_LITERAL.match(rest)
        if raw:
            yield "rel", raw.group(2)
            continue
        cat = _CONCAT.match(rest)
        if cat:
            yield ("manifest" if cat.group(1) == "CARGO_MANIFEST_DIR" else "out"), cat.group(2)
            continue
        raise _Unreadable(rest[:60])


def _crate_root(path: str, manifests: set[str]) -> str:
    parts = path.split("/")[:-1]
    while parts:
        if "/".join(parts + ["Cargo.toml"]) in manifests:
            return "/".join(parts)
        parts.pop()
    return ""


def compiled_references(sources: dict[str, str], manifests: set[str] | None = None) -> frozenset[str] | None:
    """The repository paths the Rust files in `sources` include at compile time.

    `sources` maps a repository path to its text, `manifests` is the set of
    Cargo.toml paths (a manifest-relative include resolves from the nearest
    one above the file; the repository root when none is given). An include of
    build output (OUT_DIR) names no tree path. None when any include's argument
    cannot be read: the caller must then treat every path as BUILD.
    """
    manifests = manifests or set()
    found: set[str] = set()
    try:
        for path, text in sources.items():
            for kind, arg in _includes(text):
                if kind == "out":
                    continue
                if kind == "manifest":
                    base = _crate_root(path, manifests)
                    joined = os.path.join(base, arg.lstrip("/"))
                else:
                    joined = os.path.join(os.path.dirname(path), arg)
                norm = os.path.normpath(joined)
                if norm.startswith(".."):
                    continue
                found.add(norm.replace(os.sep, "/"))
    except _Unreadable:
        return None
    return frozenset(found)


# ── The snapshot of the inputs ────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Everything a step key is computed from."""

    files: dict[str, str]
    ignored: dict[str, str]
    index_tree: str
    head: str
    tags: str
    tools: dict[str, str]
    env: dict[str, str]
    hook_scripts: str
    compiled: frozenset[str] | None


# Variables that can change a verdict: the toolchain's, cargo's, nextest's,
# the project's own, and the tool overrides the gates read.
_ENV_PREFIXES = ("RUST", "CARGO", "NEXTEST_", "SIPNAB_")
_ENV_NAMES = {"G729_VECTORS", "VALE_BIN", "CODESPELL_BIN", "PYANG_BIN", "YANGLINT_BIN", "ZOLA_BIN", "CC", "CXX"}
# ...and the ones that cannot: terminal styling, and this cache's own controls.
_ENV_SKIP_PREFIXES = ("CARGO_TERM_", "SIPNAB_GATE_")
_ENV_SKIP = {"SIPNAB_HOOK_ANY_TREE"}


def cache_env(env: dict[str, str]) -> dict[str, str]:
    """The variables of `env` that enter the key. GIT_* never do: `git commit`
    exports them to its hooks and a hand-run hook has none."""
    return {
        k: v
        for k, v in sorted(env.items())
        if (k.startswith(_ENV_PREFIXES) or k in _ENV_NAMES)
        and not k.startswith(_ENV_SKIP_PREFIXES)
        and k not in _ENV_SKIP
    }


def _git(root, args, env, check=True, text=False) -> bytes | str:
    out = subprocess.run(["git", *args], cwd=root, env=env, capture_output=True, check=False)
    if check and out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {out.stderr.decode(errors='replace').strip()}")
    return out.stdout.decode(errors="surrogateescape") if text else out.stdout


def _split0(data: bytes) -> list[str]:
    return [p.decode(errors="surrogateescape") for p in data.split(b"\0") if p]


def tree_files(root, env) -> dict[str, str]:
    """Every tracked and untracked (not ignored) path under `root`, with a content id.

    A path whose working copy equals the index has the index's blob id; any
    other has the blob id git would give its working copy, with its mode
    (an executable bit is content to a hook script), a symbolic link's
    target, or "deleted".
    """
    files: dict[str, str] = {}
    for entry in _split0(_git(root, ["ls-files", "-s", "-z"], env)):
        meta, path = entry.split("\t", 1)
        mode, blob, stage = meta.split()
        files[path] = f"{mode}:{blob}" if stage == "0" else f"conflict:{stage}"
    changed = set(_split0(_git(root, ["diff", "--name-only", "--no-renames", "-z"], env)))
    changed |= set(_split0(_git(root, ["ls-files", "-o", "--exclude-standard", "-z"], env)))
    to_hash = []
    for path in sorted(changed):
        full = os.path.join(root, path)
        if os.path.islink(full):
            files[path] = "120000:" + os.readlink(full)
        elif os.path.isfile(full):
            to_hash.append(path)
        elif os.path.isdir(full):
            # A nested repository or a submodule: name it by its HEAD.
            head = _git(full, ["rev-parse", "-q", "--verify", "HEAD"], env, check=False, text=True)
            files[path] = "160000:" + head.strip()
        else:
            files[path] = "deleted"
    if to_hash:
        out = subprocess.run(
            ["git", "hash-object", "--stdin-paths"],
            cwd=root,
            env=env,
            input="\n".join(to_hash).encode(errors="surrogateescape") + b"\n",
            capture_output=True,
            check=True,
        )
        for path, blob in zip(to_hash, out.stdout.decode().split()):
            mode = "100755" if os.access(os.path.join(root, path), os.X_OK) else "100644"
            files[path] = f"{mode}:{blob}"
    return files


# Build output, bytecode and pytest's cache: written by every run, and no
# verdict reads them (the hook never passes pytest --lf or --ff). pytest's
# cache was walked at first, and the hook's own script-test run rewrote it, so
# the script-tests and whole-hook stamps were never written.
_UNWALKED = {"target", "__pycache__", ".pytest_cache", ".git", "node_modules"}


def _stat_id(path: str) -> str:
    st = os.lstat(path)
    return f"{st.st_size}:{st.st_mtime_ns}"


def ignored_files(root, env) -> dict[str, str]:
    """The ignored files under `root` by size and modification time.

    Gitignored inputs change verdicts too: the G.729 test vectors, the Vale
    style packages, docs/design/backlog.local.md, website/data. Build
    directories, bytecode caches and installed node modules are not walked.
    An outside $G729_VECTORS is read the same way.
    """
    found: dict[str, str] = {}

    def walk(top: str, name: str):
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(d for d in dirnames if d not in _UNWALKED)
            for f in sorted(filenames):
                full = os.path.join(dirpath, f)
                rel = os.path.join(name, os.path.relpath(full, top)).replace(os.sep, "/")
                found[rel] = _stat_id(full)

    listing = _git(root, ["ls-files", "-o", "-i", "--exclude-standard", "--directory", "-z"], env)
    for entry in _split0(listing):
        parts = entry.rstrip("/").split("/")
        if _UNWALKED & set(parts):
            continue
        full = os.path.join(root, entry)
        if entry.endswith("/"):
            walk(full, entry.rstrip("/"))
        elif os.path.lexists(full):
            found[entry] = _stat_id(full)
    vectors = env.get("G729_VECTORS")
    if vectors and os.path.isdir(vectors):
        walk(vectors, "$G729_VECTORS")
    return found


def _run_version(cmd, cwd, env) -> str:
    try:
        out = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"absent: {type(e).__name__}"
    if out.returncode != 0:
        return f"absent: exit {out.returncode}"
    return out.stdout.decode(errors="replace").strip()


def _resolve(override: str | None, name: str, env) -> str | None:
    if override and os.access(override, os.X_OK):
        return override
    return shutil.which(name, path=env.get("PATH"))


def tool_versions(root, env) -> dict[str, str]:
    """The versions of every tool a cached step's verdict depends on."""
    tools = {
        "rustc": _run_version(["rustc", "-Vv"], root, env),
        "nextest": _run_version(["cargo", "nextest", "--version"], root, env).split("\n")[0],
        "python": sys.version,
    }
    try:
        tools["pytest"] = importlib.metadata.version("pytest")
    except importlib.metadata.PackageNotFoundError:
        tools["pytest"] = "absent"
    for name, var in (("vale", "VALE_BIN"), ("codespell", "CODESPELL_BIN")):
        binary = _resolve(env.get(var), name, env)
        tools[name] = f"{binary}: {_run_version([binary, '--version'], root, env)}" if binary else "absent"
    return tools


def hook_scripts_hash(hook_file: str) -> str:
    """SHA-256 over the hook file and every file under its ../scripts and ../.config.

    The hook resolves the scripts it calls from its own location, so these are
    the scripts it runs, whichever tree it is pointed at.
    """
    h = hashlib.sha256()
    hook = pathlib.Path(hook_file).resolve()
    base = hook.parent.parent
    paths = [hook]
    for sub in ("scripts", ".config"):
        top = base / sub
        if top.is_dir():
            for dirpath, dirnames, filenames in os.walk(top):
                dirnames[:] = sorted(d for d in dirnames if d not in _UNWALKED)
                paths += [pathlib.Path(dirpath, f) for f in sorted(filenames)]
    for p in paths:
        h.update(str(p.relative_to(base) if p != hook else "HOOK").encode() + b"\0")
        try:
            h.update(hashlib.sha256(p.read_bytes()).digest())
        except OSError:
            h.update(b"unreadable")
    return h.hexdigest()


def snapshot(root, env, hook_file: str) -> Snapshot:
    """Read every input of every step from the tree at `root`."""
    files = tree_files(root, env)
    manifests = {p for p in files if p == "Cargo.toml" or p.endswith("/Cargo.toml")}
    candidates = _split0(
        _git(root, ["grep", "--untracked", "-z", "-l", "-E", r"include(_str|_bytes)?!", "--", "*.rs"], env, check=False)
    )
    sources = {}
    for path in candidates:
        try:
            sources[path] = pathlib.Path(root, path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    tags = _git(root, ["for-each-ref", "--format=%(objectname) %(refname)", "refs/tags"], env)
    return Snapshot(
        files=files,
        ignored=ignored_files(root, env),
        index_tree=_git(root, ["write-tree"], env, text=True).strip(),
        head=_git(root, ["rev-parse", "-q", "--verify", "HEAD"], env, check=False, text=True).strip() or "none",
        tags=hashlib.sha256(tags).hexdigest(),
        tools=tool_versions(root, env),
        env=cache_env(env),
        hook_scripts=hook_scripts_hash(hook_file),
        compiled=compiled_references(sources, manifests),
    )


def _digest(entries: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(entries):
        h.update(path.encode(errors="surrogateescape") + b"\0" + entries[path].encode() + b"\n")
    return h.hexdigest()


def step_parts(hook: str, step: str, snap: Snapshot) -> dict:
    """The inputs of `step` in `hook`, as the key is computed from them."""
    reads, command = STEPS[hook][step]
    parts = {
        "schema": SCHEMA,
        "hook": hook,
        "step": step,
        "command": command,
        "reads": reads,
        "hook_scripts": snap.hook_scripts,
        "tools": snap.tools,
        "env": snap.env,
        "cargo_lock": snap.files.get("Cargo.lock", "absent"),
    }
    if reads == BUILD:
        parts["files"] = _digest({p: i for p, i in snap.files.items() if path_class(p, snap.compiled) == BUILD})
        parts["ignored"] = _digest({p: i for p, i in snap.ignored.items() if path_class(p, snap.compiled) == BUILD})
    else:
        parts["files"] = _digest(snap.files)
        parts["ignored"] = _digest(snap.ignored)
        parts["index_tree"] = snap.index_tree
        parts["head"] = snap.head
        parts["tags"] = snap.tags
    return parts


def key_of(parts: dict) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


# ── The store ─────────────────────────────────────────────────────────────

_STAMP_NAME = re.compile(r"^(pre-commit|pre-push)\.[a-z0-9-]+\.[0-9a-f]{64}\.json$")
_TMP_NAME = re.compile(r"^(pre-commit|pre-push)\.[a-z0-9-]+\.[0-9a-f]{64}\.json\.tmp-")


def stamp_path(directory, hook: str, step: str, key: str) -> pathlib.Path:
    return pathlib.Path(directory, f"{hook}.{step}.{key}.json")


def _check(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "check"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def write_stamp(directory, hook: str, step: str, key: str, now: float, summary: dict) -> pathlib.Path:
    """Write the stamp atomically: a temporary file, renamed into place."""
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": SCHEMA,
        "hook": hook,
        "step": step,
        "key": key,
        "written": now,
        "written_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "summary": summary,
    }
    record["check"] = _check(record)
    final = stamp_path(directory, hook, step, key)
    tmp = final.with_name(f"{final.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    finally:
        if tmp.exists():
            tmp.unlink()
    return final


def valid_stamp(directory, hook: str, step: str, key: str, now: float) -> dict | None:
    """The stamp for (hook, step, key) when it is whole, its own and current; else None."""
    try:
        record = json.loads(stamp_path(directory, hook, step, key).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("check") != _check(record):
        return None
    if (record.get("schema"), record.get("hook"), record.get("step"), record.get("key")) != (SCHEMA, hook, step, key):
        return None
    written = record.get("written")
    if not isinstance(written, (int, float)):
        return None
    if now - written > MAX_AGE or written - now > FUTURE_SLACK:
        return None
    return record


def prune(directory, now: float, max_age: float = MAX_AGE, max_count: int = MAX_COUNT) -> list[pathlib.Path]:
    """Remove stamps older than `max_age`, all but the newest `max_count`, and
    temporary files older than TMP_MAX_AGE. Other files are left alone."""
    directory = pathlib.Path(directory)
    if not directory.is_dir():
        return []
    removed = []
    stamps = []
    for p in directory.iterdir():
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if _TMP_NAME.match(p.name):
            if now - mtime > TMP_MAX_AGE:
                removed.append(p)
        elif _STAMP_NAME.match(p.name):
            if now - mtime > max_age:
                removed.append(p)
            else:
                stamps.append((mtime, p))
    stamps.sort(reverse=True)
    removed += [p for _m, p in stamps[max_count:]]
    for p in removed:
        try:
            p.unlink()
        except OSError:
            pass
    return removed


# ── The command line ──────────────────────────────────────────────────────


def _env() -> dict[str, str]:
    return dict(os.environ)


def _root(env) -> str:
    return _git(".", ["rev-parse", "--show-toplevel"], env, text=True).strip()


def _stamp_dir(env) -> pathlib.Path:
    return pathlib.Path(_git(".", ["rev-parse", "--absolute-git-dir"], env, text=True).strip(), STAMP_DIR)


def _default_hook_file(hook: str) -> str:
    return str(pathlib.Path(__file__).resolve().parent.parent / ".githooks" / hook)


def _no_cache(env) -> bool:
    return env.get("SIPNAB_GATE_NO_CACHE", "") not in ("", "0")


def cmd_keys(args) -> int:
    env = _env()
    root = _root(env)
    snap = snapshot(root, env, args.hook_file or _default_hook_file(args.hook))
    for step in STEPS[args.hook]:
        print(step, key_of(step_parts(args.hook, step, snap)))
    # "info" lines are for the hook to print when it does not skip outright.
    if _no_cache(env):
        print("info   Pass stamps... IGNORED (SIPNAB_GATE_NO_CACHE=1): every step runs")
    elif args.hook == "pre-commit":
        staged = _split0(_git(root, ["diff", "--cached", "--name-only", "--no-renames", "-z"], env, check=False))
        verdict = change_class(staged, snap.compiled)
        what = {
            "none": "nothing staged",
            DOCS: "no build input (clippy and the bpf-types tests can reuse a stamp; the suite reads every file)",
            BUILD: "build inputs",
        }[verdict]
        print(f"info   Staged change: {what}")
    return 0


def cmd_hit(args) -> int:
    env = _env()
    if _no_cache(env) or args.hook not in STEPS or args.step not in STEPS[args.hook]:
        return 1
    record = valid_stamp(_stamp_dir(env), args.hook, args.step, args.key, time.time())
    if record is None:
        return 1
    if not args.quiet:
        when = record["written_utc"]
        if args.line == "hook":
            print(
                f"{args.hook}: PASSED before on these exact inputs; no check re-run "
                f"(stamp {args.key[:12]}, written {when}). Full run: SIPNAB_GATE_NO_CACHE=1"
            )
        else:
            print(f"CACHED (passed on these inputs: stamp {args.key[:12]}, {when})")
    return 0


def cmd_pass(args) -> int:
    """Stamp every (step, key) pair whose key the inputs still give, from ONE
    snapshot: the hooks collect the steps that passed and call this once, when
    they exit. A snapshot per step cost 13 per push."""
    env = _env()
    if len(args.pairs) % 2:
        print("gate-cache: pass takes STEP KEY pairs", file=sys.stderr)
        return 2
    pairs = list(zip(args.pairs[0::2], args.pairs[1::2]))
    unknown = [step for step, _key in pairs if args.hook not in STEPS or step not in STEPS[args.hook]]
    if unknown:
        print(f"gate-cache: no step {unknown[0]!r} in {args.hook}", file=sys.stderr)
        return 2
    root = _root(env)
    snap = snapshot(root, env, args.hook_file or _default_hook_file(args.hook))
    directory = _stamp_dir(env)
    now = time.time()
    for step, key in pairs:
        if key_of(step_parts(args.hook, step, snap)) != key:
            print(f"  No pass stamp for {step}: its inputs changed while it ran.")
            continue
        write_stamp(directory, args.hook, step, key, now, {"head": snap.head, "index_tree": snap.index_tree})
        if step == "hook":
            print(f"  Pass stamp {key[:12]} written: an identical run is skipped (SIPNAB_GATE_NO_CACHE=1 forces one).")
    prune(directory, now)
    return 0


def cmd_classify(args) -> int:
    env = _env()
    root = _root(env)
    snap = snapshot(root, env, _default_hook_file("pre-commit"))
    paths = args.paths or _split0(_git(root, ["diff", "--cached", "--name-only", "--no-renames", "-z"], env))
    for p in paths:
        print(f"{path_class(p, snap.compiled)}\t{p}")
    print(f"change\t{change_class(paths, snap.compiled)}")
    return 0


def cmd_list(_args) -> int:
    directory = _stamp_dir(_env())
    now = time.time()
    for p in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        m = re.match(r"^(pre-commit|pre-push)\.([a-z0-9-]+)\.([0-9a-f]{64})\.json$", p.name)
        if not m:
            continue
        record = valid_stamp(directory, m.group(1), m.group(2), m.group(3), now)
        state = record["written_utc"] if record else "INVALID (ignored)"
        print(f"{m.group(1)} {m.group(2)} {m.group(3)[:12]} {state}")
    return 0


def cmd_clear(_args) -> int:
    directory = _stamp_dir(_env())
    if directory.is_dir():
        shutil.rmtree(directory)
    print(f"removed {directory}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keys")
    k.add_argument("hook", choices=sorted(STEPS))
    k.add_argument("--hook-file")
    h = sub.add_parser("hit")
    h.add_argument("hook")
    h.add_argument("step")
    h.add_argument("key")
    h.add_argument("--line", choices=("hook", "step"), default="step")
    h.add_argument("--quiet", action="store_true")
    s = sub.add_parser("pass")
    s.add_argument("hook")
    s.add_argument("pairs", nargs="+", metavar="STEP KEY")
    s.add_argument("--hook-file")
    c = sub.add_parser("classify")
    c.add_argument("paths", nargs="*")
    sub.add_parser("list")
    sub.add_parser("clear")
    args = p.parse_args(argv)
    handlers = {
        "keys": cmd_keys,
        "hit": cmd_hit,
        "pass": cmd_pass,
        "classify": cmd_classify,
        "list": cmd_list,
        "clear": cmd_clear,
    }
    try:
        return handlers[args.cmd](args)
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        print(f"gate-cache: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
