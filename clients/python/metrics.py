#!/usr/bin/env python3
"""GET /metrics: the Prometheus exposition, as a scraper sees it.

The example docs/prometheus-metrics.md shows is the body of show(), between the snippet
markers; this file adds where the inputs come from and what a failure prints.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token).
Standard library only.
"""

import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"


def show() -> None:
    # snippet:start metrics
    req = Request(
        f"{BASE}/metrics",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urlopen(req, timeout=10) as resp:
        print(resp.read().decode(), end="")  # Prometheus text format
    # snippet:end metrics


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"metrics: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"metrics: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
