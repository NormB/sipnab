# snippet:start tail-dialogs
"""sipnab REST client — async, periodic polling."""
import asyncio
import os
from datetime import datetime, timezone

import httpx

API = os.environ.get("SIPNAB_URL", "http://localhost:8080")
KEY = os.environ["SIPNAB_API_KEY"]


async def tail_dialogs(poll_interval: float = 2.0) -> None:
    """Poll /v1/dialogs every `poll_interval` and print newly-completed calls."""
    seen: set[str] = set()
    headers = {"Authorization": f"Bearer {KEY}"}

    async with httpx.AsyncClient(base_url=API, headers=headers,
                                  timeout=10.0) as client:
        while True:
            try:
                r = await client.get("/v1/dialogs",
                                     params={"limit": 100})
                r.raise_for_status()
                for d in r.json()["dialogs"]:
                    if d["call_id"] in seen:
                        continue
                    seen.add(d["call_id"])
                    if d["state"] in ("Completed", "Failed", "Canceled"):
                        print(f"{datetime.now(timezone.utc).isoformat()}  "
                              f"{d['state']:10s}  {d['call_id']}  "
                              f"{d.get('from_user')} → {d.get('to_user')}")
            except httpx.HTTPError as e:
                print(f"warning: {e}")
            await asyncio.sleep(poll_interval)


if __name__ == "__main__":
    asyncio.run(tail_dialogs())
# snippet:end tail-dialogs
