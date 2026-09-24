#!/usr/bin/env python3
"""GET /v1/streams?mos_below=3.0: the RTP streams that sound bad.

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
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE = os.environ.get("SIPNAB_URL") or "http://127.0.0.1:8080"
TOKEN = os.environ.get("SIPNAB_API_KEY") or "my-secret-token"


def show() -> None:
    # snippet:start list-streams
    query = urlencode({"mos_below": 3.0})
    req = Request(
        f"{BASE}/v1/streams?{query}",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    for s in data["streams"]:
        print(f"SSRC {s['ssrc']}: MOS={s['mos']:.1f}, loss={s['loss_pct']:.1f}%")
    # snippet:end list-streams


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"list_streams: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"list_streams: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
