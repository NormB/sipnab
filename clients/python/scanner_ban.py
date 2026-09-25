#!/usr/bin/env python3
"""Ban the scanners a capture accuses through TFPS, then check TFPS holds
them (cookbook recipes 10 and 23).

    scanner_ban.py CAPTURE [--ttl SECONDS] [--reg-flood-threshold N] [--sipnab PATH]

1. Runs `sipnab -N -I CAPTURE --kill-scanner --reg-flood --recommend-block`,
   which groups the scanner and registration-flood detections by source and
   says, for each source, whether it also completed a registration or a call
   (recipe 10c). sipnab recommends and applies nothing.
2. Bans, through `POST /v1/tfps/ban` on a running sipnab, only the sources
   with no such counter-evidence. A source that completed a registration is
   a working peer whose credentials went wrong, the device recipe 23 finds,
   and a ban would disconnect it: it is withheld and named.
3. Reads `GET /v1/tfps/banned` and counts a ban only if TFPS lists the
   address as enforced.

It exits 0 when every ban was applied and verified, 1 when TFPS refused one,
a ban is missing from TFPS's list, TFPS is not installed beside that sipnab,
or a request failed.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token); the TFPS routes
need a full-scope token. sipnab comes from `--sipnab`, else `$SIPNAB_BIN`,
else `sipnab` on PATH. Standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"

BLOCK = re.compile(r"^# ---- sipnab block recommendation ---- (\S+) ----$")
RULES = re.compile(r"^# EVIDENCE: rule\(s\) tripped: (.+)$")
COUNTER = {
    "# COUNTER-EVIDENCE: none.": "none",
    "# COUNTER-EVIDENCE: UNKNOWN.": "unknown",
}
REFUSED = {
    "local": "it is an address of the TFPS host",
    "declared": "TFPS's ignoreip says never enforce against it",
    "kernel": "TFPS could not write the block",
}


def parse_recommendations(text: str) -> list[dict]:
    """Each `--recommend-block` block as {ip, rules, counter}."""
    accused, current = [], None
    for line in text.splitlines():
        if m := BLOCK.match(line):
            current = {"ip": m.group(1), "rules": "", "counter": None}
            accused.append(current)
        elif current is None:
            continue
        elif m := RULES.match(line):
            current["rules"] = m.group(1)
        elif line.startswith("# COUNTER-EVIDENCE:"):
            current["counter"] = next(
                (v for k, v in COUNTER.items() if line.startswith(k)),
                "established" if "also completed a registration or a call" in line else None,
            )
    for a in accused:
        if a["counter"] is None:
            raise ValueError(f"no readable COUNTER-EVIDENCE line for {a['ip']}")
    return accused


def plan(accused: list[dict]) -> tuple[list[dict], list[str]]:
    """The sources to ban, and a line for each one withheld."""
    ban, withheld = [], []
    for a in accused:
        if a["counter"] == "none":
            ban.append(a)
        elif a["counter"] == "established":
            withheld.append(
                f"withheld {a['ip']} ({a['rules']}): it also completed a registration "
                "or a call in this capture"
            )
        else:
            withheld.append(
                f"withheld {a['ip']} ({a['rules']}): no scanner detector ran, so nothing "
                "asked whether it is a working peer"
            )
    return ban, withheld


def describe_action(action: dict, rules: str) -> str:
    """What TFPS did with one ban, as it said it."""
    if action["applied"]:
        if action["expires"] is None:
            until = "with no expiry"
        else:
            at = datetime.fromtimestamp(action["expires"], timezone.utc)
            until = f"until {at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        return f"banned {action['ip']} ({rules}) {until}"
    why = REFUSED.get(action["refused"], "TFPS refused it")
    return f"refused {action['ip']} ({rules}): {why} ({action['refused']})"


def unverified(applied: list[str], banned_rows: list[dict]) -> list[str]:
    """The applied bans TFPS does not list as enforced."""
    enforced = {r["ip"] for r in banned_rows if r.get("enforced")}
    return [ip for ip in applied if ip not in enforced]


def call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(
        f"{BASE}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=30) as resp:
        return json.load(resp)


def accusations(sipnab: str, capture: str, threshold: int | None) -> list[dict]:
    cmd = [sipnab, "-N", "--quiet", "--no-cli-print", "-I", capture,
           "--kill-scanner", "--reg-flood", "--recommend-block", "nftables"]
    if threshold is not None:
        cmd += ["--reg-flood-threshold", str(threshold)]
    # NO_COLOR: sipnab's log lines, quoted in an error, as plain text.
    run = subprocess.run(
        cmd, capture_output=True, text=True, check=False, env={**os.environ, "NO_COLOR": "1"}
    )
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip() or f"{sipnab} exited {run.returncode}")
    return parse_recommendations(run.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--ttl", type=int, help="ban length in seconds, 0 for none (TFPS default: 3600)")
    ap.add_argument("--reg-flood-threshold", type=int)
    ap.add_argument("--sipnab", default=os.environ.get("SIPNAB_BIN") or "sipnab")
    args = ap.parse_args()
    try:
        accused = accusations(args.sipnab, args.capture, args.reg_flood_threshold)
    except (OSError, RuntimeError, ValueError) as e:
        print(f"scanner_ban: sipnab could not read {args.capture}: {e}", file=sys.stderr)
        return 1
    ban, withheld = plan(accused)
    if not accused:
        print(f"no source accused in {args.capture}")
        return 0
    try:
        status = call("GET", "/v1/tfps/status")
        if not status["installed"]:
            print(f"scanner_ban: no TFPS beside {BASE}: {status.get('reason')}", file=sys.stderr)
            return 1
        # snippet:start tfps-ban
        failed, applied = False, []
        for a in ban:
            body = {"ip": a["ip"]} if args.ttl is None else {"ip": a["ip"], "ttl_secs": args.ttl}
            action = call("POST", "/v1/tfps/ban", body)["action"]
            print(describe_action(action, a["rules"]))
            if action["applied"]:
                applied.append(a["ip"])
            else:
                failed = True
        for line in withheld:
            print(line)
        missing = unverified(applied, call("GET", "/v1/tfps/banned")["rows"])
        for ip in missing:
            print(f"NOT in TFPS's banned list: {ip}")
        print(f"verified {len(applied) - len(missing)} of {len(applied)} ban(s) in TFPS's banned list")
        # snippet:end tfps-ban
    except HTTPError as e:
        print(f"scanner_ban: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"scanner_ban: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 1 if failed or missing else 0


if __name__ == "__main__":
    sys.exit(main())
