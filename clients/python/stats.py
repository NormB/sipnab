#!/usr/bin/env python3
"""GET /v1/stats: dialog totals and post-dial delay percentiles.

The example docs/rest-api.md shows is the body of show(), between the snippet
markers; this file adds where the inputs come from and what a failure prints.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token).
Standard library only.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"


def show() -> None:
    # snippet:start stats
    req = Request(
        f"{BASE}/v1/stats",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urlopen(req, timeout=10) as resp:
        stats = json.load(resp)
    d = stats["dialogs"]
    print(f"Dialogs: {d['total']} total, {d['active']} active, {d['failed']} failed")
    t = stats["timing"]
    print(f"PDD: p50={t['pdd_p50_ms']}ms, p95={t['pdd_p95_ms']}ms")
    # snippet:end stats


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"stats: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"stats: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
