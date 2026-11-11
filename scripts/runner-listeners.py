#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Report a self-hosted runner directory that does not have exactly one
Runner.Listener process, and a runner unit whose restart count is climbing.

The defect this exists for: on 2026-11-10 every job sent to two of the
self-hosted runners failed in 2 s in actions/checkout. Each runner had two
listeners. The unit's supervisor (run.sh) had exited eight days earlier; the
unit's KillMode=process left run-helper.sh and Runner.Listener running
outside the unit; Restart=always then started a new supervisor about every
4 minutes, each refused by GitHub as a second session (NRestarts 1342 and
1345), until GitHub accepted one and each job got two workers.

What it reports, per runner directory:
  - other than exactly one process whose program is <dir>/bin/Runner.Listener
  - a listener that does not descend from the main process of the unit
    whose WorkingDirectory is that directory: a process the unit left behind
and per unit:
  - NRestarts higher than at the previous read. Two reads --interval seconds
    apart, or with --state FILE one read compared with the file's, which is
    then rewritten (for a timer or cron).

It only reads. Every command goes through `read_command`, which refuses
anything but `ps -eo ...`, `systemctl show ...` and `systemctl list-units
...`. It signals no process and writes no unit file; with --state it writes
that one file. It needs no root.

Exit codes:
  exit 0  every directory has exactly one listener, inside its unit, and no
          restart count rose
  exit 1  findings, one per line
  exit 2  the process table or the units could not be read, or there was
          nothing to check
"""
import argparse
import collections
import glob
import json
import os
import subprocess
import sys
import time

Proc = collections.namedtuple("Proc", "pid ppid args")

SHOW_PROPERTIES = "Id,WorkingDirectory,MainPID,NRestarts,KillMode,ActiveState"


def parse_ps(text):
    """The rows of `ps -eo pid=,ppid=,args=`. A row that is not two numbers
    and the rest, or no row at all, is an answer nobody understood."""
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            raise ValueError(f"not a ps row: {line!r}")
        out.append(Proc(int(parts[0]), int(parts[1]), parts[2].rstrip("\n") if len(parts) == 3 else ""))
    if not out:
        raise ValueError("ps printed no process")
    return out


def listeners_in(procs, runner_dir):
    """The processes whose program is this directory's Runner.Listener. The
    whole first word must be that path: `actions-runner` is the start of
    `actions-runner-2`, and a `grep` for the path is not a listener."""
    program = os.path.join(runner_dir.rstrip("/"), "bin", "Runner.Listener")
    return [p for p in procs if p.args.split(None, 1)[:1] == [program]]


def descends_from(procs, pid, ancestor):
    """Whether `ancestor` is `pid` or one of its parents, in this table."""
    parent = {p.pid: p.ppid for p in procs}
    seen = set()
    while pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        if pid not in parent:
            return False
        pid = parent[pid]
    return False


def parse_show(text):
    """`systemctl show` output, KEY=VALUE per line, as a dictionary."""
    out = {}
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if eq and key and " " not in key:
            out[key] = value
    if not out:
        raise ValueError(f"not systemctl show output: {text[:80]!r}")
    return out


def listener_findings(runner_dirs, units, procs):
    """One line per thing wrong with a runner directory's listeners."""
    if not runner_dirs:
        raise ValueError("no runner directory to check")
    out = []
    for d in runner_dirs:
        d = d.rstrip("/")
        found = listeners_in(procs, d)
        if not found:
            out.append(f"{d}: no Runner.Listener process (expected exactly one)")
        elif len(found) > 1:
            pids = ", ".join(str(p.pid) for p in found)
            out.append(f"{d}: {len(found)} Runner.Listener processes (PIDs {pids}), expected exactly one")
        for u in units:
            if u.get("WorkingDirectory", "").rstrip("/") != d:
                continue
            if not u.get("MainPID", "").isdigit():
                raise ValueError(f"{u.get('Id', '?')}: MainPID is {u.get('MainPID')!r}")
            main = int(u["MainPID"])
            for p in found:
                if main == 0 or not descends_from(procs, p.pid, main):
                    out.append(f"{d}: Runner.Listener PID {p.pid} runs outside {u['Id']} (main PID {main}):"
                               " a process the unit left behind")
    return out


def restart_counts(units):
    """{unit: NRestarts} from the units' properties."""
    out = {}
    for u in units:
        if not u.get("NRestarts", "").isdigit():
            raise ValueError(f"{u.get('Id', '?')}: NRestarts is {u.get('NRestarts')!r}")
        out[u["Id"]] = int(u["NRestarts"])
    return out


def restart_findings(before, after, secs):
    """One line per unit whose count rose between two reads. A lower count
    is a unit somebody restarted, and a high count that stands still is
    history: neither is a climb."""
    return [
        f"{name}: NRestarts rose from {before[name]} to {after[name]} in {int(secs)} s: the unit keeps restarting"
        for name in sorted(after)
        if name in before and after[name] > before[name]
    ]


def notes(units):
    """Lines worth reading that are not findings."""
    return [
        f"note: {u['Id']} has KillMode=process: when its main process exits, systemd leaves the listener"
        " running outside the unit"
        for u in units if u.get("KillMode") == "process"
    ]


def check_read_only(argv):
    """Refuse any command but the three that only read."""
    ok = (
        (len(argv) >= 3 and argv[:2] == ["ps", "-eo"])
        or (len(argv) >= 3 and argv[:2] == ["systemctl", "show"])
        or (len(argv) >= 3 and argv[:2] == ["systemctl", "list-units"])
    )
    if not ok:
        raise PermissionError(f"runner-listeners.py only reads; refusing to run {argv!r}")


def read_command(argv):
    """The output of one read-only command, or OSError when it failed."""
    check_read_only(argv)
    p = subprocess.run(argv, capture_output=True, text=True)
    if p.returncode != 0:
        raise OSError(f"{' '.join(argv)}: exit {p.returncode}: {p.stderr.strip()}")
    return p.stdout


def read_units(unit_glob):
    listing = read_command(["systemctl", "list-units", "--all", "--plain", "--no-legend", unit_glob])
    names = [line.split()[0] for line in listing.splitlines() if line.split()]
    return [parse_show(read_command(["systemctl", "show", n, "-p", SHOW_PROPERTIES])) for n in names]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runner-dir", action="append",
                    help="a runner directory; repeatable (default: every ~/actions-runner* directory)")
    ap.add_argument("--unit-glob", default="gh-runner-sipnab*.service", help="the runner units")
    ap.add_argument("--interval", type=float, default=300,
                    help="seconds between the two reads of NRestarts; 0 reads once and does not judge it")
    ap.add_argument("--state", help="compare NRestarts with this file's, then rewrite it, instead of reading twice")
    a = ap.parse_args()

    dirs = a.runner_dir or sorted(d for d in glob.glob(os.path.expanduser("~/actions-runner*")) if os.path.isdir(d))
    try:
        procs = parse_ps(read_command(["ps", "-eo", "pid=,ppid=,args="]))
        units = read_units(a.unit_glob)
        if not units:
            print(f"runner listeners: no unit matches {a.unit_glob}: nothing to check")
            sys.exit(2)
        found = listener_findings(dirs, units, procs)
        counts = restart_counts(units)
        if a.state:
            before, since = {}, None
            if os.path.exists(a.state):
                saved = json.loads(open(a.state).read())
                before, since = dict(saved["units"]), float(saved["at"])
            now = time.time()
            found += restart_findings(before, counts, now - since if since else 0)
            with open(a.state, "w") as f:
                json.dump({"at": now, "units": counts}, f)
            restarts = "NRestarts did not rise since the last run" if since else "NRestarts recorded; not judged on a first run"
        elif a.interval > 0:
            time.sleep(a.interval)
            found += restart_findings(counts, restart_counts(read_units(a.unit_glob)), a.interval)
            restarts = f"NRestarts did not rise in {a.interval:g} s"
        else:
            restarts = "NRestarts not judged: one read"
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"runner listeners: could not read: {e}")
        sys.exit(2)

    for line in notes(units):
        print(line)
    if found:
        print(f"runner listeners: {len(found)} finding(s):")
        for line in found:
            print(f"  {line}")
        sys.exit(1)
    print(f"runner listeners: {len(dirs)} runner directories, exactly one Runner.Listener each, inside its unit;"
          f" {restarts}")


if __name__ == "__main__":
    main()
