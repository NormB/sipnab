#!/usr/bin/env python3
"""GET /v1/streams/{id}: one RTP stream's codec and packet count.

The example docs/rest-api.md shows is the body of show(), between the snippet
markers; this file adds where the inputs come from and what a failure prints.

SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
SIPNAB_API_KEY the bearer token (default my-secret-token).
The first argument is the SSRC (default 0x1a2b3c4d).
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
SSRC = sys.argv[1] if len(sys.argv) > 1 else "0x1a2b3c4d"


def show() -> None:
    # snippet:start get-stream
    req = Request(
        f"{BASE}/v1/streams/{quote(SSRC, safe='')}",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urlopen(req, timeout=10) as resp:
        stream = json.load(resp)
    print(f"Codec: {stream['codec']}, Packets: {stream['packets']}")
    # snippet:end get-stream


def main() -> int:
    try:
        show()
    except HTTPError as e:
        print(f"get_stream: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except URLError as e:
        print(f"get_stream: cannot reach {BASE}: {e.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
