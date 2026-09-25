#!/usr/bin/env python3
"""Why calls failed, grouped by final response code (cookbook recipes 3 and 30).

    failed_calls.py

Asks a running sipnab three things over REST:

1. `GET /v1/aggregate?by=response_code` over the failed dialogs: one bucket
   per final response code. Recipe 3's shell histogram counts every response
   inside a failed call, `100 Trying` included; this counts each call once.
2. `GET /v1/dialogs?filter=...` per bucket: which calls those are.
3. `GET /v1/report`: the capture's findings, for the calls that answered and
   were never acknowledged (recipe 30). A missing `ACK` does not make a call
   fail, so the grouping cannot show it, and sipnab reports one only after
   the answer has waited `--ack-timeout` (RFC 3261 Timer H, 32 s, unless the
   server was started with a shorter one).

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token). Standard library
only.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote as urlquote
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"
FAILED = "state == 'Failed'"


def get(path: str, **params) -> dict:
    query = f"?{urlencode(params, quote_via=urlquote)}" if params else ""
    req = Request(f"{BASE}{path}{query}", headers={"Authorization": f"Bearer {TOKEN}"})
    with urlopen(req, timeout=10) as resp:
        return json.load(resp)


def gather() -> tuple[dict, dict, dict]:
    """The grouping, the calls in each group and the capture's findings."""
    # snippet:start failed-calls
    aggregate = get("/v1/aggregate", by="response_code", filter=FAILED)
    calls = {}
    for bucket in aggregate["buckets"]:
        code = bucket["value"]
        if code == "(none)":
            # No final code to filter on: counted, not listed.
            calls[code] = ([], bucket["count"])
            continue
        page = get("/v1/dialogs", filter=f"{FAILED} AND response_code == {code}")
        calls[code] = ([d["call_id"] for d in page["dialogs"]], page["total"])
    report = get("/v1/report")
    # snippet:end failed-calls
    return aggregate, calls, report


def render(aggregate: dict, calls: dict, report: dict) -> list[str]:
    total = aggregate["total_matched"]
    if total == 0:
        lines = ["0 failed call(s)"]
    else:
        lines = [f"{total} failed call(s), by final response code:"]
    for bucket in aggregate["buckets"]:
        ids, matched = calls.get(bucket["value"], ([], bucket["count"]))
        lines.append(f"  {bucket['value']}  {bucket['count']} call(s)")
        lines.extend(f"    {call_id}" for call_id in ids)
        if matched > len(ids):
            lines.append(f"    ... and {matched - len(ids)} more")
    if aggregate.get("other_count"):
        lines.append(f"  other codes  {aggregate['other_count']} call(s)")

    unacked = [f for f in report["findings"] if f["kind"] == "ack_missing"]
    count = sum(f["occurrences"] for f in unacked)
    if count == 0:
        lines.append(
            "0 call(s) answered and never acknowledged "
            "(a call counts once its answer has waited sipnab's --ack-timeout)"
        )
        return lines
    lines.append(f"{count} call(s) answered and never acknowledged:")
    for f in unacked:
        for e in f["evidence"]:
            sent = e.get("counts", {}).get("answer_transmissions")
            tail = f", answer sent {sent} time(s)" if sent is not None else ""
            lines.append(f"  {e.get('call_id', '-')}  {e.get('note', '')}{tail}")
        if f.get("evidence_omitted"):
            lines.append(f"  ... and {f['evidence_omitted']} more")
    return lines


def main() -> int:
    try:
        aggregate, calls, report = gather()
    except HTTPError as e:
        print(f"failed_calls: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"failed_calls: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    print("\n".join(render(aggregate, calls, report)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
