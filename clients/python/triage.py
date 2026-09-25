#!/usr/bin/env python3
"""Triage a capture to one machine verdict (cookbook recipes 1 and 16).

    triage.py capture.pcap [more.pcap ...] [--sipnab PATH]

Runs `sipnab -N -I <capture> --json-analyze` and prints one verdict line,
then each finding with the calls or endpoints that carry it. The exit status
is the verdict, for a pipeline that reads nothing else:

    0  clean         dialogs or streams were examined and nothing was found
    1  problems      at least one finding
    2  inconclusive  sipnab did not analyze all of the capture, or it held no
                     SIP dialog and no RTP stream, so "no findings" proves
                     nothing
    3  sipnab could not read the capture

The third state is why this exists rather than `--json-analyze` alone. A
capture whose SIP sits outside `--portrange`, or that holds no SIP at all,
analyzes to an empty finding list, which reads as clean (recipe 16's
pitfall). Standard library only; sipnab comes from `--sipnab`, else
`$SIPNAB_BIN`, else `sipnab` on PATH.
"""

import argparse
import json
import os
import subprocess
import sys

EXIT = {"clean": 0, "problems": 1, "inconclusive": 2}


def evidence_lines(finding: dict) -> list[str]:
    """One line per piece of evidence: the call, else the endpoints, and why."""
    out = []
    for e in finding.get("evidence", []):
        where = e.get("call_id") or ", ".join(e.get("endpoints", [])) or "-"
        why = e.get("note") or " ".join(f"{k}={v}" for k, v in sorted(e.get("counts", {}).items()))
        out.append(f"    {where}  {why}".rstrip())
    if finding.get("evidence_omitted"):
        out.append(f"    ... and {finding['evidence_omitted']} more")
    return out


def verdict(analysis: dict) -> tuple[str, list[str]]:
    """The verdict and the lines that justify it."""
    # snippet:start triage-verdict
    seen = (
        f"{analysis['frames_read']} frame(s), {analysis['dialogs_examined']} dialog(s), "
        f"{analysis['streams_examined']} stream(s)"
    )
    findings = analysis["findings"]
    if not analysis["complete"]:
        head, result = f"inconclusive: sipnab did not analyze all of the capture ({seen})", "inconclusive"
    elif findings:
        head, result = f"problems: {seen}", "problems"
    elif analysis["dialogs_examined"] == 0 and analysis["streams_examined"] == 0:
        head = (
            f"inconclusive: {analysis['frames_read']} frame(s) and no SIP dialog or RTP "
            "stream to judge, so an empty finding list proves nothing"
        )
        result = "inconclusive"
    else:
        head, result = f"clean: {seen}", "clean"
    lines = [head]
    for f in findings:
        lines.append(f"  {f['severity']}  {f['kind']}  {f['occurrences']} {f['unit']}(s)")
        lines.extend(evidence_lines(f))
    return result, lines
    # snippet:end triage-verdict


def analyze(sipnab: str, captures: list[str]) -> dict:
    """sipnab's one-object analysis of the captures, read as one run."""
    cmd = [sipnab, "-N", "--quiet", "--no-cli-print", "--json-analyze"]
    for c in captures:
        cmd += ["-I", c]
    # NO_COLOR: sipnab's log lines, quoted in an error, as plain text.
    run = subprocess.run(
        cmd, capture_output=True, text=True, check=False, env={**os.environ, "NO_COLOR": "1"}
    )
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip() or f"{sipnab} exited {run.returncode}")
    return json.loads(run.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="+", help="capture files, directories or globs")
    ap.add_argument("--sipnab", default=os.environ.get("SIPNAB_BIN") or "sipnab")
    args = ap.parse_args()
    try:
        analysis = analyze(args.sipnab, args.captures)
    except (OSError, RuntimeError, json.JSONDecodeError) as e:
        print(f"triage: sipnab could not analyze {' '.join(args.captures)}: {e}", file=sys.stderr)
        return 3
    result, lines = verdict(analysis)
    print("\n".join(lines))
    return EXIT[result]


if __name__ == "__main__":
    sys.exit(main())
