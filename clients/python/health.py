#!/usr/bin/env python3
"""GET /health: is the REST API up? Prints ok.

The example docs/rest-api.md shows is the body of show(), between the snippet
markers; this file adds where the inputs come from and what a failure prints.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080).
Standard library only.
"""

import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"


def show() -> None:
    # snippet:start health
    with urlopen(f"{BASE}/health", timeout=10) as resp:
        print(resp.read().decode())  # "ok"
    # snippet:end health


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"health: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"health: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
