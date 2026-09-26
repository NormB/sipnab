# snippet:start monitor-failed
import os
import time

import requests

API = os.environ.get("SIPNAB_URL", "http://127.0.0.1:8080")
KEY = os.environ["SIPNAB_API_KEY"]
HEADERS = {"Authorization": f"Bearer {KEY}"}

seen = set()
while True:
    resp = requests.get(f"{API}/v1/dialogs", headers=HEADERS,
                        params={"state": "Failed"})
    resp.raise_for_status()
    for d in resp.json()["dialogs"]:
        cid = d["call_id"]
        if cid not in seen:
            seen.add(cid)
            print(f"FAILED: {cid} from={d.get('from_user')} to={d.get('to_user')}")
    time.sleep(5)
# snippet:end monitor-failed
