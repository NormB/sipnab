# snippet:start paginate-dialogs
import os

import requests

API = os.environ.get("SIPNAB_URL", "http://127.0.0.1:8080")
HEADERS = {"Authorization": f"Bearer {os.environ['SIPNAB_API_KEY']}"}

offset = 0
limit = 100
all_dialogs = []

while True:
    resp = requests.get(f"{API}/v1/dialogs",
                        headers=HEADERS,
                        params={"limit": limit, "offset": offset})
    resp.raise_for_status()
    data = resp.json()
    all_dialogs.extend(data["dialogs"])
    if offset + limit >= data["total"]:
        break
    offset += limit

print(f"Fetched {len(all_dialogs)} dialogs")
# snippet:end paginate-dialogs
