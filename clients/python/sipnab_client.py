# snippet:start sipnab-client
"""sipnab REST client — sync version using requests."""
from __future__ import annotations

import os
import sys
from typing import Any

import requests

API = os.environ.get("SIPNAB_URL", "http://localhost:8080")
KEY = os.environ["SIPNAB_API_KEY"]  # raises KeyError if unset


class SipnabError(Exception):
    pass


class SipnabClient:
    def __init__(self, base_url: str = API, token: str = KEY,
                 timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.timeout = timeout

    def _get(self, path: str, **params: Any) -> Any:
        r = self.session.get(f"{self.base}{path}", params=params,
                             timeout=self.timeout)
        if r.status_code == 401:
            raise SipnabError("authentication failed (401)")
        if r.status_code == 503:
            raise SipnabError("rate-limited or connection cap reached (503)")
        r.raise_for_status()
        return r.json()

    def health(self) -> bool:
        r = self.session.get(f"{self.base}/health", timeout=self.timeout)
        return r.ok

    def list_dialogs(self, *, state: str | None = None,
                     from_regex: str | None = None,
                     limit: int = 50, offset: int = 0) -> list[dict]:
        """List dialog summaries.

        The REST API supports filtering by `state` (exact match against
        DialogState e.g. 'Failed', 'Completed', 'InCall') and `from` (regex).
        For full DSL filtering use the MCP server's list_dialogs tool.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if state:
            params["state"] = state
        if from_regex:
            params["from"] = from_regex
        return self._get("/v1/dialogs", **params)["dialogs"]

    def get_dialog(self, call_id: str) -> dict:
        from urllib.parse import quote
        return self._get(f"/v1/dialogs/{quote(call_id, safe='')}")

    def call_report(self, call_id: str) -> dict:
        from urllib.parse import quote
        return self._get(f"/v1/dialogs/{quote(call_id, safe='')}/report")

    def stats(self) -> dict:
        return self._get("/v1/stats")

    def metrics(self) -> str:
        r = self.session.get(f"{self.base}/metrics", timeout=self.timeout)
        if r.status_code == 401:
            raise SipnabError("authentication failed")
        if r.status_code == 503:
            raise SipnabError("rate-limited")
        r.raise_for_status()
        return r.text


# ── Usage ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    c = SipnabClient()

    if not c.health():
        sys.exit("sipnab not reachable")

    print("Stats:", c.stats())

    # Pull every failed call, page through
    failed: list[dict] = []
    offset = 0
    while True:
        page = c.list_dialogs(state="Failed", limit=100, offset=offset)
        if not page:
            break
        failed.extend(page)
        offset += len(page)
    print(f"{len(failed)} failed dialogs")

    # Show the first few — note the REST shape doesn't expose
    # per-message status_code. See module-level note above for how to
    # build a response-code histogram via CLI or MCP.
    for d in failed[:5]:
        full = c.get_dialog(d["call_id"])
        diag = full.get("diagnosis", {})
        print(f"  {d['call_id']:30s}  state={d['state']:10s}  "
              f"diagnosis={ {k: v for k, v in diag.items() if v} }")
# snippet:end sipnab-client
