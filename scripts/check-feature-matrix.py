#!/usr/bin/env python3
"""Run CI's feature-matrix compile checks locally, before the push.

Why this exists as a gate rather than a habit: the pre-commit hook builds
`--features full`, and a break that only appears when a feature is ABSENT is
structurally invisible to it. `--all-features` cannot see it either -- it turns
everything ON. The only build that catches it is one combo at a time, which
until now happened solely in CI, so the feedback loop for that class was a full
push-and-wait cycle.

The combo list is PARSED from .github/workflows/ci.yml rather than restated
here. A gate that duplicates its source of truth drifts from it, and a local
gate that checks a stale set of combos is worse than none: it reports a pass
CI will contradict.

Exit codes follow the convention the other pre-push gates use:
  0  every combo checked and passed
  1  a combo failed to compile
  2  could not run (no cargo, workflow file missing or unparsable)
"""
import os
import re
import subprocess
import sys
from pathlib import Path

def _root() -> Path:
    """The crate being pushed, not the crate this script lives in.

    Resolved from the working directory rather than `__file__` so the hook's
    BDD suite -- which runs the real hook with cwd set to a throwaway fixture
    crate -- exercises this gate against THAT crate. Anchoring on `__file__`
    would make every scenario re-check the real sipnab tree instead: slow, and
    a verdict about the wrong code.
    """
    r = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if r.returncode == 0 and r.stdout.strip():
        return Path(r.stdout.strip())
    return Path.cwd()


ROOT = _root()
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def combos() -> list[str]:
    """The `features:` matrix, read off the workflow."""
    if not WORKFLOW.is_file():
        return []
    text = WORKFLOW.read_text(encoding="utf-8")
    # `features:` appears twice -- once as the JOB name and once as the matrix
    # key -- so take the block that actually yields entries rather than the
    # first one that matches. Comment lines are interleaved with the entries
    # and must not terminate the block.
    for m in re.finditer(r"\n( +)features:\n((?:(?: *#[^\n]*|\1  - [^\n]+)\n)+)", text):
        out = []
        for line in m.group(2).split("\n"):
            line = line.strip()
            if not line.startswith("- "):
                continue
            out.append(line[2:].strip().strip('"').strip("'"))
        if out:
            return out
    return []


def workflow_env() -> dict[str, str]:
    """The workflow-level `env:` block, so this gate runs CI's flags.

    `RUSTFLAGS: -Dwarnings` lives there, and without it `cargo check` reports a
    dead-code warning and exits 0 -- so a break that turns CI red passes here.
    That happened: this gate was written, run against the real break it was
    built for, and SURVIVED, because the combos were right and the flags were
    not. Read them from the same file for the same reason the combos are read
    from it.
    """
    if not WORKFLOW.is_file():
        return {}
    text = WORKFLOW.read_text(encoding="utf-8")
    m = re.search(r"(?m)^env:\n((?:[ \t]+[A-Za-z_][A-Za-z0-9_]*:[^\n]*\n)+)", text)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        k, _, v = line.strip().partition(":")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def has_wasm_target() -> bool:
    r = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.returncode == 0 and "wasm32-unknown-unknown" in r.stdout


def main() -> int:
    if subprocess.run(["cargo", "--version"], cwd=ROOT,
                      capture_output=True).returncode != 0:
        print("cargo is not on PATH")
        return 2
    names = combos()
    if not names:
        print(f"no feature matrix found in {WORKFLOW.relative_to(ROOT)}")
        return 2

    env = dict(os.environ)
    wf = workflow_env()
    if "RUSTFLAGS" not in wf:
        # Refuse rather than run a weaker check than CI. A gate that silently
        # drops `-Dwarnings` reports a pass CI will contradict, which is worse
        # than not running at all.
        print("no RUSTFLAGS in the workflow env block; refusing to check with "
              "weaker flags than CI")
        return 2
    env.update({k: v for k, v in wf.items() if k in ("RUSTFLAGS", "RUSTDOCFLAGS")})

    failed, unchecked = [], []
    for f in names:
        if f == "wasm":
            if not has_wasm_target():
                unchecked.append((f, "wasm32-unknown-unknown target not installed"))
                continue
            cmd = ["cargo", "check", "--target", "wasm32-unknown-unknown",
                   "--no-default-features", "--features", f, "--lib"]
        else:
            # `--tests` is not optional. Without it no test file is built, and
            # a break that lives in a test compiles nowhere -- the gate stays
            # green while CI, which passes it, goes red.
            cmd = ["cargo", "check", "--no-default-features", "--features", f,
                   "--tests"]
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            failed.append((f, r.stdout + r.stderr))

    for f, why in unchecked:
        print(f"  {f}: NOT CHECKED -- {why}")
    if failed:
        for f, out in failed:
            print(f"\n  --- --features {f} ---")
            for line in out.splitlines():
                if line.startswith(("error", "warning:")) or "-->" in line:
                    print(f"  {line}")
        print(f"\n{len(failed)} of {len(names)} feature combos failed.")
        return 1
    print(f"{len(names) - len(unchecked)} of {len(names)} combos checked, all clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
