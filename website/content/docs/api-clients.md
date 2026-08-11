+++
title = "API Client Examples"
weight = 12
description = "Client code for the sipnab REST API in curl, Python, Node/TypeScript, Rust, and Go."
+++

Ready-to-adapt clients for the [REST API](@/docs/api.md) in curl, Python, Node/TypeScript, Rust, and Go.

## Client examples

End-to-end examples in five languages. Each one covers: bearer-token auth, listing dialogs filtered by state, fetching a single dialog with pagination, scraping `/metrics`, and error handling. Adapt to your environment.

> **Filter parameters:** the REST API accepts `state` (e.g. `Failed`, `Completed`, `InCall`) and `from` (regex on the From header) as query parameters on `/v1/dialogs`, plus `orphaned` and `mos_below` on `/v1/streams`. Full DSL filtering — anything more complex than a single state/from match — is **not** available over REST. For arbitrary DSL queries, use the [MCP server](@/docs/mcp.md)'s `list_dialogs` tool, which accepts a `filter` argument that runs through the same evaluator as `sipnab --filter`.

> **Status codes:** the REST API returns **503 Service Unavailable** when the rate limiter turns a request away or the connection cap (not 429). 401 on bad/missing token, 404 on unknown call_id.

> **Per-call response code / per-message data is not on REST.** The REST API aggregates each dialog into a summary (`call_id`, `state`, `from`, `to`, `duration_sec`, `msg_count`, `timing`, `diagnosis`, `sdp_timeline`, `streams`) — individual SIP messages and per-response status codes are **not** exposed by `/v1/dialogs` or `/v1/dialogs/{id}`. To work with per-message data programmatically, use either: (a) the CLI `sipnab -N --json ...` mode, which emits one JSON object per SIP message with `is_request`, `status_code`, `reason`, etc. (field reference: [Output Formats](@/docs/output-formats.md); see also [cookbook Recipe 3](@/docs/cookbook.md#3-find-every-failed-call-grouped-by-response-code)), or (b) the MCP `get_dialog` tool, which returns paginated `messages[]` (see [MCP](@/docs/mcp.md)).

### curl + jq one-liners

The snippet sets `$API`, `$KEY` and `$H` at the top and every call below uses them, so this
block is one paste into one shell. Lifting a single line out of the middle gives
you a curl with unset variables, which requests `/v1/dialogs` on no host with no
bearer token. Every call here is a read, and running the block start to finish
changes nothing on the server.

```bash
# Run all of these, in order.
# Setup
API="http://localhost:8080"
KEY="my-secret-token"
H="-H 'Authorization: Bearer $KEY'"

# Health check (no auth required)
curl -fsS $API/health

# List failed dialogs (state= query param)
curl -fsS "$API/v1/dialogs?state=Failed&limit=20" $H | jq

# List dialogs from a specific user (from= regex)
curl -fsS "$API/v1/dialogs?from=alice&limit=20" $H | jq

# Get one full (aggregated) dialog — no per-message data over REST
curl -fsS "$API/v1/dialogs/abc123@host" $H | jq

# Get a call report (JSON — this endpoint is JSON-only)
curl -fsS "$API/v1/dialogs/abc123@host/report" $H | jq

# Non-orphaned streams (orphaned=false)
curl -fsS "$API/v1/streams?orphaned=false" $H | jq

# Streams below a MOS threshold
curl -fsS "$API/v1/streams?mos_below=3.5" $H | jq

# Aggregate counters
curl -fsS "$API/v1/stats" $H | jq

# Count failed calls (aggregated — REST exposes no per-message data)
curl -fsS "$API/v1/dialogs?state=Failed&limit=1000" $H \
  | jq '.total'

# For per-call response-code histograms, use the CLI NDJSON mode —
# sipnab -N --json emits one record per message (see Output Formats docs):
#   sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
#     | jq -r 'select(.is_request == false) | .status_code' \
#     | sort | uniq -c | sort -rn

# Prometheus metrics
curl -fsS "$API/metrics" $H | grep '^sipnab_'

# Error handling — server returns 503 (not 429) on rate-limit + conn-cap
http_code=$(curl -s -o /dev/null -w '%{http_code}' \
            "$API/v1/dialogs/no-such-call" $H)
case "$http_code" in
  200) echo "found" ;;
  401) echo "auth failed — check --api-key" ;;
  404) echo "dialog not found" ;;
  503) echo "rate-limited or connection cap reached" ;;
  *)   echo "unexpected $http_code" ;;
esac
```

> The per-message NDJSON records referenced above (`is_request`, `status_code`, `reason`, `cseq`, and so on) appear in [Output Formats](@/docs/output-formats.md).

---

### Python (sync, `requests`)

```python
"""sipnab REST client — sync version using requests."""
from __future__ import annotations

import os
import sys
from typing import Any

import requests

API = os.environ.get("SIPNAB_API", "http://localhost:8080")
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
            raise SipnabError("authentication failed")
        if r.status_code == 503:
            raise SipnabError("rate-limited or connection cap reached")
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
```

Run it:

```bash
SIPNAB_API_KEY=my-secret-token python3 sipnab_client.py
```

---

### Python (async, `httpx`)

For tailing dialogs in near-real-time without blocking:

```python
"""sipnab REST client — async, periodic polling."""
import asyncio
import os
from datetime import datetime, timezone

import httpx

API = os.environ.get("SIPNAB_API", "http://localhost:8080")
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
                    if d["state"] in ("Completed", "Failed", "Cancelled"):
                        print(f"{datetime.now(timezone.utc).isoformat()}  "
                              f"{d['state']:10s}  {d['call_id']}  "
                              f"{d.get('from')} → {d.get('to')}")
            except httpx.HTTPError as e:
                print(f"warning: {e}")
            await asyncio.sleep(poll_interval)


if __name__ == "__main__":
    asyncio.run(tail_dialogs())
```

---

### Node.js / TypeScript

```typescript
// sipnab-client.ts — runs on Node 18+ (built-in fetch)
const API = process.env.SIPNAB_API ?? "http://localhost:8080";
const KEY = process.env.SIPNAB_API_KEY;
if (!KEY) throw new Error("SIPNAB_API_KEY not set");

interface DialogSummary {
  call_id: string;
  state: string;
  method: string;
  from: string;
  to: string;
  duration_sec: number;
  msg_count: number;
}

interface DialogsPage {
  dialogs: DialogSummary[];
  total: number;
  limit: number;
  offset: number;
}

async function api<T>(
  path: string,
  params: Record<string, string | number> = {},
): Promise<T> {
  const url = new URL(`${API}${path}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, String(v));
  }
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${KEY}` },
  });
  if (r.status === 401) throw new Error("auth failed");
  if (r.status === 503) throw new Error("rate-limited or conn cap reached");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as T;
}

async function listDialogs(
  state: string | null = null,
  limit = 50,
): Promise<DialogSummary[]> {
  const all: DialogSummary[] = [];
  let offset = 0;
  for (;;) {
    const params: Record<string, string | number> = { limit, offset };
    if (state) params.state = state;
    const page = await api<DialogsPage>("/v1/dialogs", params);
    if (page.dialogs.length === 0) break;
    all.push(...page.dialogs);
    if (all.length >= page.total) break;
    offset += page.dialogs.length;
  }
  return all;
}

// REST API doesn't expose per-message data — see the note at the top of
// "Client Examples" for how to build per-call response-code histograms
// via the CLI or MCP. Here we just summarize what REST exposes:
interface FullDialog {
  call_id: string;
  state: string;
  msg_count: number;
  timing: { pdd_ms: number | null; setup_ms: number | null; retransmits: number };
  diagnosis: { one_way_audio: boolean; nat_mismatch: boolean; no_media: boolean };
}

// ── Demo ──────────────────────────────────────────────────────────
const failed = await listDialogs("Failed");
console.log(`${failed.length} failed dialogs`);

for (const d of failed.slice(0, 5)) {
  const full = await api<FullDialog>(`/v1/dialogs/${encodeURIComponent(d.call_id)}`);
  console.log(`  ${d.call_id}  state=${d.state}  ` +
              `pdd=${full.timing.pdd_ms ?? "—"}ms  ` +
              `nat_mismatch=${full.diagnosis.nat_mismatch}`);
}
```

Run:

```bash
SIPNAB_API_KEY=my-secret-token npx tsx sipnab-client.ts
```

---

### Rust (`reqwest`)

```rust
// Cargo.toml deps:
//   reqwest = { version = "0.12", features = ["json", "blocking"] }
//   serde   = { version = "1", features = ["derive"] }
//   anyhow  = "1"

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
struct DialogSummary {
    call_id: String,
    state: String,
    from: String,
    to: String,
    duration_sec: f64,
    msg_count: u32,
}

#[derive(Debug, Deserialize)]
struct DialogsPage {
    dialogs: Vec<DialogSummary>,
    total: usize,
    limit: usize,
    offset: usize,
}

struct Sipnab {
    base: String,
    client: Client,
}

impl Sipnab {
    fn new() -> Result<Self> {
        let base = env::var("SIPNAB_API")
            .unwrap_or_else(|_| "http://localhost:8080".into());
        let key = env::var("SIPNAB_API_KEY")?;
        let client = Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(reqwest::header::AUTHORIZATION,
                    format!("Bearer {key}").parse()?);
                h
            })
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self { base, client })
    }

    fn list_dialogs(&self, state: Option<&str>) -> Result<Vec<DialogSummary>> {
        let mut all = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut req = self.client
                .get(format!("{}/v1/dialogs", self.base))
                .query(&[("limit", "100"), ("offset", &offset.to_string())]);
            if let Some(s) = state {
                req = req.query(&[("state", s)]);
            }
            let resp = req.send()?;
            match resp.status().as_u16() {
                401 => return Err(anyhow!("auth failed")),
                503 => return Err(anyhow!("rate-limited or conn cap reached")),
                code if code >= 400 => return Err(anyhow!("HTTP {code}")),
                _ => {}
            }
            let page: DialogsPage = resp.json()?;
            if page.dialogs.is_empty() { break; }
            offset += page.dialogs.len();
            let total = page.total;
            all.extend(page.dialogs);
            if all.len() >= total { break; }
        }
        Ok(all)
    }

    /// Fetch one full dialog (aggregated; no per-message data).
    /// REST does not expose individual messages — for that, use the
    /// CLI `sipnab -N --json` mode or the MCP `get_dialog` tool.
    fn get_dialog(&self, call_id: &str) -> Result<serde_json::Value> {
        let cid = urlencoding::encode(call_id);
        let resp = self.client
            .get(format!("{}/v1/dialogs/{}", self.base, cid))
            .send()?;
        Ok(resp.json()?)
    }
}

fn main() -> Result<()> {
    let s = Sipnab::new()?;
    let failed = s.list_dialogs(Some("Failed"))?;
    println!("{} failed dialogs", failed.len());

    for d in failed.iter().take(5) {
        let full = s.get_dialog(&d.call_id)?;
        let pdd = full["timing"]["pdd_ms"].as_i64();
        let nat_mismatch = full["diagnosis"]["nat_mismatch"].as_bool().unwrap_or(false);
        println!("  {}  state={}  pdd={:?}ms  nat_mismatch={}",
                 d.call_id, d.state, pdd, nat_mismatch);
    }
    Ok(())
}
```

> The per-message `sipnab -N --json` records mentioned in `get_dialog`'s doc comment appear in [Output Formats](@/docs/output-formats.md).

---

### Go (`net/http` + `encoding/json`)

```go
// sipnab-client.go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "sort"
    "time"
)

type DialogSummary struct {
    CallID      string  `json:"call_id"`
    State       string  `json:"state"`
    From        string  `json:"from"`
    To          string  `json:"to"`
    DurationSec float64 `json:"duration_sec"`
    MsgCount    int     `json:"msg_count"`
}

type DialogTiming struct {
    PddMs      *int64 `json:"pdd_ms"`
    SetupMs    *int64 `json:"setup_ms"`
    Retransmits int   `json:"retransmits"`
}

type DialogDiagnosis struct {
    OneWayAudio  bool `json:"one_way_audio"`
    NatMismatch  bool `json:"nat_mismatch"`
    NoMedia      bool `json:"no_media"`
}

type FullDialog struct {
    CallID    string          `json:"call_id"`
    State     string          `json:"state"`
    Timing    DialogTiming    `json:"timing"`
    Diagnosis DialogDiagnosis `json:"diagnosis"`
}

type DialogsPage struct {
    Dialogs []DialogSummary `json:"dialogs"`
    Total   int             `json:"total"`
    Limit   int             `json:"limit"`
    Offset  int             `json:"offset"`
}

type Sipnab struct {
    Base   string
    Token  string
    Client *http.Client
}

func newSipnab() (*Sipnab, error) {
    base := os.Getenv("SIPNAB_API")
    if base == "" {
        base = "http://localhost:8080"
    }
    token := os.Getenv("SIPNAB_API_KEY")
    if token == "" {
        return nil, fmt.Errorf("SIPNAB_API_KEY not set")
    }
    return &Sipnab{
        Base:   base,
        Token:  token,
        Client: &http.Client{Timeout: 10 * time.Second},
    }, nil
}

func (s *Sipnab) get(path string, params url.Values, out any) error {
    u, _ := url.Parse(s.Base + path)
    u.RawQuery = params.Encode()
    req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
    req.Header.Set("Authorization", "Bearer "+s.Token)
    resp, err := s.Client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    switch resp.StatusCode {
    case 401:
        return fmt.Errorf("auth failed")
    case 503:
        return fmt.Errorf("rate-limited or conn cap reached")
    }
    if resp.StatusCode >= 400 {
        return fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    return json.NewDecoder(resp.Body).Decode(out)
}

func (s *Sipnab) ListDialogs(state string) ([]DialogSummary, error) {
    var all []DialogSummary
    offset := 0
    for {
        params := url.Values{"limit": {"100"}, "offset": {fmt.Sprint(offset)}}
        if state != "" {
            params.Set("state", state)
        }
        var page DialogsPage
        if err := s.get("/v1/dialogs", params, &page); err != nil {
            return nil, err
        }
        if len(page.Dialogs) == 0 {
            break
        }
        all = append(all, page.Dialogs...)
        offset += len(page.Dialogs)
        if len(all) >= page.Total {
            break
        }
    }
    return all, nil
}

// GetDialog fetches the full (aggregated) dialog. REST has no
// per-message detail — for that, use the CLI --json mode or the
// MCP get_dialog tool.
func (s *Sipnab) GetDialog(callID string) (*FullDialog, error) {
    var full FullDialog
    if err := s.get("/v1/dialogs/"+url.PathEscape(callID), nil, &full); err != nil {
        return nil, err
    }
    return &full, nil
}

func main() {
    s, err := newSipnab()
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    failed, err := s.ListDialogs("Failed")
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Printf("%d failed dialogs\n", len(failed))

    for i, d := range failed {
        if i >= 5 {
            break
        }
        full, err := s.GetDialog(d.CallID)
        if err != nil {
            continue
        }
        pdd := "—"
        if full.Timing.PddMs != nil {
            pdd = fmt.Sprintf("%dms", *full.Timing.PddMs)
        }
        fmt.Printf("  %s  state=%s  pdd=%s  nat_mismatch=%t\n",
            d.CallID, d.State, pdd, full.Diagnosis.NatMismatch)
    }
    // sort import no longer needed
    _ = sort.Strings
}
```

Run:

```bash
SIPNAB_API_KEY=my-secret-token go run sipnab-client.go
```

---

## Common Patterns

### Monitor failed calls in real-time (Python)

```python
import time
import requests

API = "http://127.0.0.1:8080"
KEY = "my-secret-token"
HEADERS = {"Authorization": f"Bearer {KEY}"}

seen = set()
while True:
    resp = requests.get(f"{API}/v1/dialogs", headers=HEADERS,
                        params={"state": "Failed"})
    for d in resp.json()["dialogs"]:
        cid = d["call_id"]
        if cid not in seen:
            seen.add(cid)
            print(f"FAILED: {cid} from={d.get('from')} to={d.get('to')}")
    time.sleep(5)
```

### Export all dialogs to CSV (bash)

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs?limit=1000" | \
  jq -r '.dialogs[] | [.call_id, .method, .state, .from, .to, .duration_sec] | @csv'
```

### Alert on poor MOS (bash)

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0" | \
  jq -r '.streams[] | "LOW MOS: SSRC=\(.ssrc) MOS=\(.mos) call=\(.associated_dialog)"'
```

### Grafana dashboard via Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sipnab
    bearer_token: your-api-key
    static_configs:
      - targets: ['127.0.0.1:8080']
    scrape_interval: 15s
```

> **Tip:** The metrics endpoint is lightweight and suitable for 5-15 second scrape intervals. The repo ships a sample Grafana dashboard JSON, included in the repository at [`contrib/grafana/sipnab-dashboard.json`](https://github.com/NormB/sipnab/blob/main/contrib/grafana/sipnab-dashboard.json).

### Paginate through all dialogs (Python)

```python
import requests

API = "http://127.0.0.1:8080"
HEADERS = {"Authorization": "Bearer my-secret-token"}

offset = 0
limit = 100
all_dialogs = []

while True:
    resp = requests.get(f"{API}/v1/dialogs",
                        headers=HEADERS,
                        params={"limit": limit, "offset": offset})
    data = resp.json()
    all_dialogs.extend(data["dialogs"])
    if offset + limit >= data["total"]:
        break
    offset += limit

print(f"Fetched {len(all_dialogs)} dialogs")
```
