#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prove every sipnab command in the cookbook still works.

`docs/examples.md` is the one page that promises the reader a command they can
paste. Everything else describes; the cookbook instructs. That makes it the
page a renamed flag breaks silently -- prose about a flag reads fine forever,
while `--json-dialogs` typed at a shell that no longer has it just fails, in
front of someone who trusted the page.

Two modes, because two different things can be checked:

  RUN    The command reads a capture file and exits. The placeholder path is
         replaced with a real fixture and the command is EXECUTED. This is the
         strong check: it proves the flags parse, the run completes, and the
         exit status is zero.

  FLAGS  The command needs something this machine cannot provide -- a live
         interface, root, a listening socket, a collector to send to. The
         command is not run; instead every long flag it names is required to
         exist in `sipnab --help`. Weaker, but it catches the failure that
         actually happens to a cookbook: a flag that was renamed or removed.

Nothing is skipped in silence. Every command lands in one of those two modes
or in UNCOVERED, and UNCOVERED is printed and counted. A checker that quietly
ignores what it cannot handle reports a clean cookbook by not looking at it,
which is the same defect the corpus gate has (see RDR2).

Usage:
    scripts/check-cookbook.py [--binary PATH] [--verbose]

Exits non-zero if any command fails its check.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COOKBOOK = REPO / "docs" / "examples.md"
FIXTURES = REPO / "tests" / "pcap-samples"

# A capture with SIP and RTP on default ports, so a recipe that filters or
# reports has something to find. A fixture whose SIP sits outside --portrange
# would make every recipe "succeed" against zero messages, which is the
# no-measurement-reads-as-a-pass trap.
DEFAULT_FIXTURE = FIXTURES / "sip-rtp-g711.pcap"

# Flags that mean the process does not exit on its own (it serves, or it reads
# a live device). Executing one would hang the check.
NON_TERMINATING = {
    "--hep-listen", "-L",
    "--api",
    "--metrics",
    "--mcp",
    "--device", "-d",
    "--interface", "-i",
}

# Anything ending in these is a placeholder path the reader substitutes.
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")


def extract_commands(text: str) -> list[tuple[str, str]]:
    """Return (recipe, command) for every command in every ```bash block."""
    out: list[tuple[str, str]] = []
    recipe = "preamble"
    block: list[str] | None = None
    for line in text.split("\n"):
        if line.startswith("## "):
            recipe = line[3:].strip()
        if line.startswith("```bash"):
            block = []
            continue
        if block is not None and line.startswith("```"):
            out.extend((recipe, c) for c in _join(block))
            block = None
            continue
        if block is not None:
            block.append(line)
    return out


def _join(lines: list[str]) -> list[str]:
    """Join `\\`-continued lines; drop comments and blanks."""
    cmds: list[str] = []
    buf = ""
    for raw in lines:
        s = raw.rstrip()
        if not s.strip() or s.strip().startswith("#"):
            if buf:
                cmds.append(buf)
                buf = ""
            continue
        if s.endswith("\\"):
            buf += s[:-1].strip() + " "
        else:
            buf += s.strip()
            cmds.append(buf)
            buf = ""
    if buf:
        cmds.append(buf)
    return cmds


def sipnab_part(cmd: str) -> str | None:
    """The `sipnab ...` invocation alone, truncated at a pipe or redirect.

    The gate is about sipnab's own CLI. `jq`, `grep` and shell redirection are
    the reader's business and are not this script's to assert.
    """
    if not re.match(r"^(sudo\s+)?sipnab\b", cmd):
        return None
    # Cut at the first top-level | or > (not inside quotes).
    depth_s = depth_d = False
    for i, ch in enumerate(cmd):
        if ch == "'" and not depth_d:
            depth_s = not depth_s
        elif ch == '"' and not depth_s:
            depth_d = not depth_d
        elif (
            ch == "#"
            and not depth_s
            and not depth_d
            and i > 0
            and cmd[i - 1].isspace()
        ):
            # A trailing comment. Quote-aware on purpose: `--show-frame
            # 'capture.pcap#3@digest'` carries a `#` that is part of the
            # argument, and stripping from the first `#` anywhere would cut a
            # frame pointer in half. Only an unquoted `#` after whitespace
            # starts a comment, which is also what a real shell does.
            return cmd[:i].strip()
        elif ch in "|>" and not depth_s and not depth_d:
            # `2>/dev/null` puts a digit before the `>`; cutting at the `>`
            # alone leaves a stray `2`, which sipnab then reads as a BPF
            # filter and rejects. The failure looked like a broken recipe and
            # was the checker mangling it.
            end = i
            while end > 0 and cmd[end - 1].isdigit():
                end -= 1
            return cmd[:end].strip()
    return cmd.strip()


def long_flags(cmd: str) -> list[str]:
    """Every `--flag` named in the command."""
    return re.findall(r"(?<![\w-])--[a-z][a-z0-9-]+", cmd)


def fixture_call_ids(binary: Path) -> list[str]:
    """Real Call-IDs read out of the fixture, in first-seen order."""
    import json

    proc = subprocess.run(
        [str(binary), "-N", "-I", str(DEFAULT_FIXTURE), "--json"],
        capture_output=True, text=True, timeout=180,
    )
    ids: list[str] = []
    for line in proc.stdout.split("\n"):
        try:
            cid = json.loads(line).get("call_id")
        except (ValueError, AttributeError):
            continue
        if cid and cid not in ids:
            ids.append(cid)
    return ids


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(REPO / "target" / "debug" / "sipnab"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(f"FATAL: no sipnab binary at {binary}", file=sys.stderr)
        print("Build one first: cargo build --features full", file=sys.stderr)
        return 2
    if not DEFAULT_FIXTURE.exists():
        print(f"FATAL: fixture missing: {DEFAULT_FIXTURE}", file=sys.stderr)
        return 2

    help_text = subprocess.run(
        [str(binary), "--help"], capture_output=True, text=True, timeout=60
    ).stdout

    # Derived from the fixture, never written down here. A hardcoded id agrees
    # with whatever it was copied from and stops agreeing with the capture the
    # moment the fixture changes -- and a `--call-report` check that silently
    # stopped matching would still "pass" by finding nothing.
    call_ids = fixture_call_ids(binary)
    if not call_ids:
        print(
            f"FATAL: no Call-IDs found in {DEFAULT_FIXTURE.name}; "
            "--call-report recipes cannot be proved against it",
            file=sys.stderr,
        )
        return 2

    commands = extract_commands(COOKBOOK.read_text())
    ran = flagged = failed = uncovered = 0
    failures: list[str] = []

    for recipe, cmd in commands:
        inv = sipnab_part(cmd)
        if inv is None:
            continue

        try:
            argv = shlex.split(inv)
        except ValueError:
            uncovered += 1
            print(f"UNCOVERED  [{recipe}] unparseable: {cmd[:80]}")
            continue

        argv = [a for a in argv if a not in ("sudo", "sipnab")]
        names = set(argv)

        # FLAGS mode: cannot be executed here.
        if names & NON_TERMINATING:
            flagged += 1
            missing = [f for f in long_flags(inv) if f not in help_text]
            if missing:
                failed += 1
                failures.append(
                    f"[{recipe}] flags not in --help: {', '.join(missing)}\n    {inv[:120]}"
                )
            elif args.verbose:
                print(f"FLAGS  ok  [{recipe}] {inv[:80]}")
            continue

        # A command using a shell variable is a fragment of a loop the reader
        # runs, not a command anything can execute standalone.
        if "$" in inv:
            uncovered += 1
            print(f"UNCOVERED  [{recipe}] shell variable: {inv[:80]}")
            continue

        # RUN mode: substitute the placeholders and execute.
        #
        # Only the INPUT path becomes the fixture. Substituting by suffix alone
        # also rewrote `-O decrypted.pcap`, which pointed output at the input
        # and made sipnab refuse -- correctly, it will not overwrite the
        # capture it is reading. That refusal read as a failing recipe.
        with tempfile.TemporaryDirectory() as tmp:
            subbed: list[str] = []
            replaced = False
            prev = ""
            for a in argv:
                is_capture = a.endswith(CAPTURE_SUFFIXES) and not Path(a).exists()
                if is_capture and prev in ("-O", "--output", "--pcap-export"):
                    subbed.append(str(Path(tmp) / Path(a).name))
                elif is_capture:
                    subbed.append(str(DEFAULT_FIXTURE))
                    replaced = True
                elif prev == "--call-report" and a not in call_ids:
                    # The page says `abc123@host`, a placeholder by design.
                    # A real id from the fixture is what proves the flag.
                    subbed.append(call_ids[0])
                else:
                    subbed.append(a)
                prev = a

            if not replaced and "-I" not in names and "--input" not in names:
                # Reads no file and serves nothing this machine can host --
                # `--uprobe-list` and friends need root and a live process.
                # Executing is out, but the flags are still checkable, and the
                # weaker check beats the nothing this used to do.
                flagged += 1
                missing = [f for f in long_flags(inv) if f not in help_text]
                if missing:
                    failed += 1
                    failures.append(
                        f"[{recipe}] flags not in --help: {', '.join(missing)}\n    {inv[:120]}"
                    )
                elif args.verbose:
                    print(f"FLAGS  ok  [{recipe}] {inv[:80]}")
                continue

            proc = subprocess.run(
                [str(binary), *subbed],
                capture_output=True, text=True, timeout=180, cwd=tmp,
                env={**os.environ, "NO_COLOR": "1"},
            )
        ran += 1
        if proc.returncode != 0:
            failed += 1
            tail = (proc.stderr or proc.stdout).strip().split("\n")[-3:]
            failures.append(
                f"[{recipe}] exit {proc.returncode}\n    {inv[:120]}\n    "
                + "\n    ".join(tail)
            )
        elif args.verbose:
            print(f"RUN    ok  [{recipe}] {inv[:80]}")

    print()
    print(f"cookbook commands checked: {ran + flagged}")
    print(f"  executed against a fixture : {ran}")
    print(f"  flag-checked (needs a host): {flagged}")
    print(f"  UNCOVERED                  : {uncovered}")
    print(f"  FAILED                     : {failed}")
    if failures:
        print("\n--- failures ---")
        for f in failures:
            print(f)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
