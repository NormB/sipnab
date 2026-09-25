#!/usr/bin/env python3
"""One customer's calls out of a directory of rotated captures, as a capture
Wireshark opens (cookbook recipes 39, 32 and 40).

    customer_export.py INPUT --user USER --out FILE [--sipnab PATH]

INPUT is what `-I` takes: a file, a directory of rotated captures or a glob.
sipnab reads the files in the order their packets arrived, not by name, so a
call that crosses files comes out as one call (recipe 39).

1. Finds the calls whose From or To user is USER, with every address their
   signaling and SDP name.
2. Exports with `-O` and a BPF expression over those addresses. `-O` is
   narrowed by BPF alone, which selects addresses, not SIP users (recipe 32).
3. Reads the export back: each call must come out whole, and no other call
   may be in it. Another customer's call that shares an address with this one
   is a disclosure BPF cannot prevent, so the export is removed, not kept.
4. Prints the tshark command that opens the export filtered to these calls,
   as `--tshark-filter` writes it (recipe 40), for the reader to run.

Exits 0 with the export written, 1 when there is no such call, the export
lost part of a call or carried another, or sipnab failed. sipnab comes from
`--sipnab`, else `$SIPNAB_BIN`, else `sipnab` on PATH. Standard library only.
"""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys

from sipnab_dsl import quote

SDP_CONNECTION = re.compile(r"c=IN IP[46] ([0-9A-Fa-f.:]+)")


def user_filter(user: str) -> str:
    return f"from.user == {quote(user)} OR to.user == {quote(user)}"


def collect(messages: list[dict]) -> dict:
    """Per Call-ID: how many SIP messages, and every address they name."""
    calls: dict[str, dict] = {}
    for m in messages:
        call = calls.setdefault(m["call_id"], {"messages": 0, "hosts": set()})
        call["messages"] += 1
        call["hosts"].update((m["src"], m["dst"]))
        call["hosts"].update(SDP_CONNECTION.findall(m.get("sdp") or ""))
    return calls


def hosts(calls: dict) -> list[str]:
    return sorted({h for c in calls.values() for h in c["hosts"]}, key=ipaddress.ip_address)


def bpf(addresses: list[str]) -> str:
    return " or ".join(f"host {a}" for a in sorted(addresses, key=ipaddress.ip_address))


def check_export(wanted: dict, got: dict) -> list[str]:
    """What is wrong with the export, one line per call; empty when nothing is."""
    # snippet:start export-check
    problems = []
    for call_id, call in sorted(wanted.items()):
        found = got.get(call_id)
        if found is None:
            problems.append(f"{call_id}: not in the export")
        elif found["messages"] != call["messages"]:
            problems.append(
                f"{call_id}: {found['messages']} of its {call['messages']} message(s) are in the export"
            )
    for call_id in sorted(set(got) - set(wanted)):
        problems.append(
            f"{call_id}: another customer's call shares an address with this one, "
            "and BPF cannot separate them"
        )
    return problems
    # snippet:end export-check


def wireshark_filter(call_ids: list[str]) -> str:
    return " || ".join(f'sip.Call-ID == "{c}"' for c in call_ids)


def sipnab_run(sipnab: str, args: list[str]) -> str:
    # NO_COLOR: sipnab's log lines, quoted in an error, as plain text.
    run = subprocess.run(
        [sipnab, "-N", "--quiet", *args],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "NO_COLOR": "1"},
    )
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip() or f"{sipnab} exited {run.returncode}")
    return run.stdout


def messages_in(sipnab: str, inputs: list[str], *extra: str) -> list[dict]:
    args = [a for i in inputs for a in ("-I", i)] + ["--json", *extra]
    return [json.loads(l) for l in sipnab_run(sipnab, args).splitlines() if l.startswith("{")]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("inputs", nargs="+", help="capture files, directories or globs")
    ap.add_argument("--user", required=True, help="the customer's SIP user, From or To")
    ap.add_argument("--out", required=True, help="the capture to write")
    ap.add_argument("--sipnab", default=os.environ.get("SIPNAB_BIN") or "sipnab")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    try:
        wanted = collect(messages_in(args.sipnab, args.inputs, "--filter", user_filter(args.user)))
        if not wanted:
            print(f"customer_export: no call for {args.user} in {' '.join(args.inputs)}", file=sys.stderr)
            return 1
        print(f"{args.user}: {len(wanted)} call(s)")
        for call_id, call in sorted(wanted.items()):
            print(f"  {call_id}  {call['messages']} message(s)")
        expression = bpf(hosts(wanted))
        print(f"BPF: {expression}")
        inputs = [a for i in args.inputs for a in ("-I", i)]
        sipnab_run(args.sipnab, [*inputs, "-O", str(out), "--no-cli-print", expression])
        problems = check_export(wanted, collect(messages_in(args.sipnab, [str(out)])))
        if problems:
            out.unlink(missing_ok=True)
            print("\n".join(problems))
            print(f"refused: removed {out} rather than hand over a partial or wider capture")
            return 1
        total = sum(c["messages"] for c in wanted.values())
        print(f"wrote {out}: {total} SIP message(s), every call whole, no other call")
        tshark = sipnab_run(
            args.sipnab,
            ["-I", str(out), "--tshark-filter", wireshark_filter(sorted(wanted)), "--no-cli-print"],
        )
        print(tshark.strip())
    except (OSError, RuntimeError, ValueError) as e:
        print(f"customer_export: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
