#!/usr/bin/env python3
"""GET /v1/hep/senders: who is feeding this sipnab's HEP listener.

A sipnab started with --hep-listen is a collector, and several agents can
feed it at once: SBCs, proxies, or other sipnabs running --hep-send. This
prints one line per sender, keyed by the capture id it claims and the address
it sent from, and one per source whose packets the listener refused, so a
dead or misconfigured agent shows up as a missing or refused line rather than
as a quiet network. The capture id is the sender's claim; without --hep-auth
nothing proves it.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token); the route needs a
full-scope token. Standard library only.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"


def render(report: dict) -> list[str]:
    """The roster as lines of text, or SystemExit for a run with no listener."""
    # snippet:start hep-senders
    if not report["listening"]:
        raise SystemExit("hep_senders: this sipnab has no HEP listener (start it with --hep-listen)")
    lines = []
    for s in report["senders"]:
        silent = "  SILENT" if s["silent"] else ""
        lines.append(f"{s['source']}  capture id {s['capture_id']}  {s['packets']} packets{silent}")
    for r in report["refused_sources"]:
        reasons = " ".join(f"{k}={v}" for k, v in sorted(r["by_reason"].items()))
        lines.append(f"refused {r['peer']}  {r['packets']} packets  {reasons}")
    lines.append(
        f"{len(report['senders'])} sender(s), {report['packets_admitted']} packet(s) admitted, "
        f"{report['packets_refused']} refused"
    )
    return lines
    # snippet:end hep-senders


def main() -> int:
    req = Request(f"{BASE}/v1/hep/senders", headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urlopen(req, timeout=10) as resp:
            report = json.load(resp)
    except HTTPError as e:
        print(f"hep_senders: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"hep_senders: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    print("\n".join(render(report)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
