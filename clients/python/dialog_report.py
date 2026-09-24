#!/usr/bin/env python3
"""GET /v1/dialogs/{call_id}/report: what the media diagnosis says about one call.

The example docs/rest-api.md shows is the body of show(), between the snippet
markers; this file adds where the inputs come from and what a failure prints.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token).
The first argument is the Call-ID (default 12013223@203.0.113.195).
Standard library only.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"
CALL_ID = sys.argv[1] if len(sys.argv) > 1 else "12013223@203.0.113.195"


def show() -> None:
    # snippet:start dialog-report
    req = Request(
        f"{BASE}/v1/dialogs/{quote(CALL_ID, safe='')}/report",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urlopen(req, timeout=10) as resp:
        report = json.load(resp)
    # `diagnosis` carries four booleans plus `hints` — there is no `summary` field.
    hints = report["diagnosis"]["hints"]
    print(f"Diagnosis: {'; '.join(hints) if hints else 'no issues detected'}")
    # snippet:end dialog-report


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"dialog_report: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"dialog_report: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
