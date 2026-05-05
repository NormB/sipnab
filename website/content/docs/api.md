+++
title = "REST API & Metrics"
weight = 7
description = "REST API endpoints, Prometheus metrics, and HEP protocol integration."
+++

sipnab includes an optional REST API and Prometheus metrics endpoint, enabled with the `api` feature flag. The API runs in an isolated child process with no access to capture file descriptors or key material.

> **Looking for AI-agent access?** sipnab also exposes the same dialog / RTP / diagnostic data as a Model Context Protocol server. See [MCP Server](@/docs/mcp.md) -- the MCP path uses the same in-memory stores as this REST API, so a running sipnab instance can serve both surfaces simultaneously.

## Getting Started

### Step 1: Build with API support

sipnab's REST API requires the `api` feature flag:

```bash
cargo build --release --features api
# or all features:
cargo build --release --features full
```

### Step 2: Choose an API key

You create the API key yourself -- there's no registration. Pick any string:

```bash
export SIPNAB_API_KEY="my-secret-token-change-this"
```

> **Security:** Use a strong random string in production. The key is sent as a Bearer token in every request. Using an environment variable avoids it appearing in `ps` output.

### Step 3: Start sipnab with the API

**Live capture:**

```bash
sudo sipnab --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

**Analyze a pcap file:**

```bash
sipnab -N -I capture.pcap --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

The process stays alive serving the API until you press Ctrl-C.

### Step 4: Query the API

```bash
curl -H "Authorization: Bearer $SIPNAB_API_KEY" http://127.0.0.1:8080/v1/dialogs
```

## Authentication

The REST API requires a bearer token passed via the `--api-key` flag or the `$SIPNAB_API_KEY` environment variable.

```bash
curl -H "Authorization: Bearer your-secret-key" http://127.0.0.1:8080/v1/dialogs
```

The metrics endpoint optionally requires a bearer token via `--metrics-auth`.

All endpoints except `/health` require authentication when an API key is configured. Missing or invalid keys return `401 Unauthorized`. Key comparison uses constant-time comparison to prevent timing side-channel attacks.

## API TLS

Secure the API endpoint with TLS:

```bash
sipnab -d eth0 --api 0.0.0.0:8443 --api-key "secret" \
  --api-tls-cert /etc/sipnab/cert.pem --api-tls-key /etc/sipnab/key.pem
```

## Connection Limits

The `--api-max-conn` flag (default: 100) limits concurrent API connections to prevent resource exhaustion. Requests are also rate-limited to 100 per second per source IP. Excess requests return `503 Service Unavailable`.

## Endpoint Reference

The base URL is whatever you pass to `--api` (e.g., `http://127.0.0.1:8080`). Data endpoints use a `/v1/` prefix. Utility endpoints (`/health`, `/metrics`) have no prefix.

### GET /health

Health check endpoint. Returns `"ok"` with no authentication required.

**curl:**

```bash
curl http://127.0.0.1:8080/health
```

**Python:**

```python
import requests

resp = requests.get("http://127.0.0.1:8080/health")
print(resp.text)  # "ok"
```

**Go:**

```go
resp, _ := http.Get("http://127.0.0.1:8080/health")
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
fmt.Println(string(body)) // "ok"
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/health");
console.log(await resp.text()); // "ok"
```

---

### GET /v1/dialogs

List all tracked SIP dialogs with optional filtering and pagination.

**Query parameters:**

| Parameter | Type   | Default | Description |
|-----------|--------|---------|-------------|
| `state`   | string | --      | Filter by dialog state (`Trying`, `Ringing`, `InCall`, `Completed`, `Failed`, `Cancelled`) |
| `from`    | string | --      | Filter by From user (regex pattern) |
| `limit`   | int    | 50      | Maximum results (capped at 1000) |
| `offset`  | int    | 0       | Pagination offset |

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10" | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/dialogs",
    headers={"Authorization": "Bearer my-secret-token"},
    params={"state": "Failed", "limit": 10},
)
data = resp.json()
for d in data["dialogs"]:
    print(f"{d['call_id']}: {d['state']} ({d['msg_count']} msgs)")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var result struct {
    Dialogs []map[string]interface{} `json:"dialogs"`
    Total   int                      `json:"total"`
}
json.NewDecoder(resp.Body).Decode(&result)
fmt.Printf("%d dialogs (%d total)\n", len(result.Dialogs), result.Total)
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch(
  "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10",
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const { dialogs, total } = await resp.json();
dialogs.forEach(d => console.log(`${d.call_id}: ${d.state}`));
```

**Response:**

```json
{
  "schema_version": 1,
  "total": 47,
  "offset": 0,
  "limit": 10,
  "dialogs": [
    {
      "call_id": "12013223@200.57.7.195",
      "from": "alice",
      "to": "bob",
      "state": "Failed",
      "method": "INVITE",
      "duration_sec": 0.0,
      "msg_count": 4,
      "timing": {
        "pdd_ms": 847,
        "setup_ms": null,
        "retransmits": 2
      },
      "created_at": "2026-04-13T10:30:00Z",
      "updated_at": "2026-04-13T10:30:03Z"
    }
  ]
}
```

---

### GET /v1/dialogs/{call_id}

Get full details for a single dialog by Call-ID, including associated RTP streams and media diagnosis.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@200.57.7.195" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@200.57.7.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}",
    headers={"Authorization": "Bearer my-secret-token"},
)
dialog = resp.json()
print(f"State: {dialog['state']}, Messages: {len(dialog.get('messages', []))}")
```

**Go:**

```go
callID := url.PathEscape("12013223@200.57.7.195")
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs/"+callID, nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var dialog map[string]interface{}
json.NewDecoder(resp.Body).Decode(&dialog)
fmt.Printf("State: %s\n", dialog["state"])
```

**JavaScript (Node.js):**

```javascript
const callId = encodeURIComponent("12013223@200.57.7.195");
const resp = await fetch(
  `http://127.0.0.1:8080/v1/dialogs/${callId}`,
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const dialog = await resp.json();
console.log(`State: ${dialog.state}`);
```

**Response:**

```json
{
  "schema_version": 1,
  "call_id": "12013223@200.57.7.195",
  "from": "alice",
  "to": "bob",
  "from_display": "Alice Smith",
  "to_display": "Bob Jones",
  "state": "Completed",
  "method": "INVITE",
  "msg_count": 8,
  "duration_sec": 45.2,
  "tags": [],
  "timing": {
    "pdd_ms": 847,
    "setup_ms": 2134,
    "ring_ms": 1287,
    "trying_delay_ms": 12,
    "teardown_ms": 45,
    "retransmits": 0
  },
  "sdp_timeline": [
    {
      "timestamp": "2026-04-13T10:30:00Z",
      "direction": "offer",
      "codecs": ["PCMU", "PCMA", "telephone-event"],
      "media_addr": "10.0.0.1",
      "media_port": 10000,
      "mode": "sendrecv"
    },
    {
      "timestamp": "2026-04-13T10:30:02Z",
      "direction": "answer",
      "codecs": ["PCMU", "telephone-event"],
      "media_addr": "10.0.0.2",
      "media_port": 20000,
      "mode": "sendrecv"
    }
  ],
  "refer_to": null,
  "siprec_metadata": null,
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false,
    "hints": []
  },
  "streams": [
    {
      "schema_version": 1,
      "ssrc": "0x1a2b3c4d",
      "codec": "PCMU",
      "payload_type": 0,
      "src": "10.0.0.1:10000",
      "dst": "10.0.0.2:20000",
      "packets": 4820,
      "octets": 771200,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@200.57.7.195",
      "first_seen": "2026-04-13T10:30:02Z",
      "last_seen": "2026-04-13T10:30:47Z",
      "quality_intervals": []
    }
  ]
}
```

**Additional dialog fields:**

- **`refer_to`** -- Present when a REFER transfer is detected. Contains the `Refer-To` URI extracted from the REFER request. The dialog state transitions to `Transferring` while the transfer is in progress.
- **`siprec_metadata`** -- Present when SIPREC recording metadata is detected. Parsed from `multipart/mixed` message bodies per RFC 7866. Contains the recording session XML metadata (participant info, session identifiers, media streams).
- **`stir_shaken`** -- When `--stir-shaken` validation is enabled, the `diagnosis.hints` array includes STIR/SHAKEN results. Tokens with an `iat` (issued-at) timestamp older than 60 seconds are rejected as `Expired` per RFC 8224 Section 12.

Returns `404` if the Call-ID is not found.

---

### GET /v1/dialogs/{call_id}/report

Get a structured call diagnosis report for a dialog in JSON format. Includes transaction timing, media quality, one-way audio detection, NAT mismatch analysis, and SDP timeline.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@200.57.7.195/report" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@200.57.7.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}/report",
    headers={"Authorization": "Bearer my-secret-token"},
)
report = resp.json()
print(f"Diagnosis: {report.get('diagnosis', {}).get('summary', 'N/A')}")
```

**Go:**

```go
callID := url.PathEscape("12013223@200.57.7.195")
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs/"+callID+"/report", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var report map[string]interface{}
json.NewDecoder(resp.Body).Decode(&report)
```

**JavaScript (Node.js):**

```javascript
const callId = encodeURIComponent("12013223@200.57.7.195");
const resp = await fetch(
  `http://127.0.0.1:8080/v1/dialogs/${callId}/report`,
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const report = await resp.json();
console.log(JSON.stringify(report, null, 2));
```

**Response:** Structured call report with diagnosis details. Returns `404` if the Call-ID is not found.

---

### GET /v1/streams

List all tracked RTP streams with quality metrics.

**Query parameters:**

| Parameter  | Type  | Default | Description |
|------------|-------|---------|-------------|
| `orphaned` | bool  | --      | Filter to orphaned streams (no associated dialog) |
| `mos_below`| float | --      | Filter streams with MOS below this threshold |
| `limit`    | int   | 50      | Maximum results (capped at 1000) |
| `offset`   | int   | 0       | Pagination offset |

**curl:**

```bash
# All streams
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/streams | jq .

# Streams with poor quality (MOS below 3.0)
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0" | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/streams",
    headers={"Authorization": "Bearer my-secret-token"},
    params={"mos_below": 3.0},
)
data = resp.json()
for s in data["streams"]:
    print(f"SSRC {s['ssrc']}: MOS={s['mos']:.1f}, loss={s['loss_pct']:.1f}%")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/streams?mos_below=3.0", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var result struct {
    Streams []map[string]interface{} `json:"streams"`
    Total   int                      `json:"total"`
}
json.NewDecoder(resp.Body).Decode(&result)
for _, s := range result.Streams {
    fmt.Printf("SSRC %s: MOS=%.1f\n", s["ssrc"], s["mos"])
}
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch(
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0",
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const { streams } = await resp.json();
streams.forEach(s =>
  console.log(`SSRC ${s.ssrc}: MOS=${s.mos.toFixed(1)}, loss=${s.loss_pct.toFixed(1)}%`)
);
```

**Response:**

```json
{
  "schema_version": 1,
  "total": 14,
  "offset": 0,
  "limit": 50,
  "streams": [
    {
      "ssrc": "0x1a2b3c4d",
      "codec": "PCMU",
      "src": "10.0.0.1:10000",
      "dst": "10.0.0.2:20000",
      "packets": 4820,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@200.57.7.195",
      "mos": 4.2
    }
  ]
}
```

---

### GET /v1/streams/{id}

Get a single RTP stream by SSRC hex string (e.g., `0x1a2b3c4d` or `1a2b3c4d`).

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/streams/0x1a2b3c4d | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/streams/0x1a2b3c4d",
    headers={"Authorization": "Bearer my-secret-token"},
)
stream = resp.json()
print(f"Codec: {stream['codec']}, Packets: {stream['packets']}")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/streams/0x1a2b3c4d", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var stream map[string]interface{}
json.NewDecoder(resp.Body).Decode(&stream)
fmt.Printf("Codec: %s, Packets: %.0f\n", stream["codec"], stream["packets"])
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/v1/streams/0x1a2b3c4d", {
  headers: { Authorization: "Bearer my-secret-token" },
});
const stream = await resp.json();
console.log(`Codec: ${stream.codec}, Packets: ${stream.packets}`);
```

**Response:** Full RTP stream JSON including codec, packet counts, jitter, loss, MOS estimate, and associated dialog. Returns `400` for invalid SSRC format, `404` if not found.

---

### GET /v1/stats

Aggregate statistics across all dialogs and streams, including PDD percentiles.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/stats | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/stats",
    headers={"Authorization": "Bearer my-secret-token"},
)
stats = resp.json()
d = stats["dialogs"]
print(f"Dialogs: {d['total']} total, {d['active']} active, {d['failed']} failed")
t = stats["timing"]
print(f"PDD: p50={t['pdd_p50_ms']}ms, p95={t['pdd_p95_ms']}ms")
```

**Go:**

```go
req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/v1/stats", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var stats map[string]interface{}
json.NewDecoder(resp.Body).Decode(&stats)
dialogs := stats["dialogs"].(map[string]interface{})
fmt.Printf("Total: %.0f, Active: %.0f\n", dialogs["total"], dialogs["active"])
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/v1/stats", {
  headers: { Authorization: "Bearer my-secret-token" },
});
const stats = await resp.json();
const { dialogs, timing } = stats;
console.log(`Dialogs: ${dialogs.total} total, ${dialogs.active} active`);
console.log(`PDD p50: ${timing.pdd_p50_ms}ms, p95: ${timing.pdd_p95_ms}ms`);
```

**Response:**

```json
{
  "schema_version": 1,
  "dialogs": {
    "total": 1247,
    "active": 23,
    "completed": 1180,
    "failed": 32,
    "cancelled": 12
  },
  "streams": {
    "total": 46,
    "orphaned": 3
  },
  "timing": {
    "pdd_p50_ms": 120,
    "pdd_p95_ms": 850,
    "pdd_p99_ms": 2100
  }
}
```

---

### GET /metrics

Prometheus-compatible metrics endpoint. Returns metrics in the OpenMetrics text format.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/metrics
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/metrics",
    headers={"Authorization": "Bearer my-secret-token"},
)
print(resp.text)  # Prometheus text format
```

**Go:**

```go
req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/metrics", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
fmt.Println(string(body))
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/metrics", {
  headers: { Authorization: "Bearer my-secret-token" },
});
console.log(await resp.text()); // Prometheus text format
```

**Response** (text/plain):

```
# HELP sipnab_dialogs_total Total dialogs by state
# TYPE sipnab_dialogs_total counter
sipnab_dialogs_total{state="completed"} 1180
sipnab_dialogs_total{state="failed"} 32
sipnab_dialogs_total{state="incall"} 23
# HELP sipnab_rtp_streams_total RTP streams by status
# TYPE sipnab_rtp_streams_total counter
sipnab_rtp_streams_total{status="established"} 43
sipnab_rtp_streams_total{status="orphaned"} 3
...
```

Metric names emitted by `src/output/prometheus.rs`:

| Metric | Type | Notes |
|---|---|---|
| `sipnab_dialogs_total{state}` | counter | Tracked dialogs grouped by `DialogState` (`Trying`, `Ringing`, `InCall`, `Completed`, `Cancelled`, `Failed`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`). The `--api` server emits state values lowercased; the standalone `--metrics` server emits them as-cased — pick the right form for your queries. |
| `sipnab_messages_total{method}` | counter | SIP messages by method (`INVITE`, `REGISTER`, …). |
| `sipnab_rtp_streams_active` | gauge | RTP streams currently in the `Established` state. |
| `sipnab_rtp_streams_total{status}` | counter | RTP streams by status (`established`, `orphaned`). |
| `sipnab_capture_packets_total` | counter | Total packets captured. |
| `sipnab_reassembly_timeouts_total` | counter | TCP/IP reassembly sessions that timed out. |
| `sipnab_pdd_seconds` | histogram | Post-dial delay distribution (buckets at 0.5/1/2/3/5/10s). Emits `sipnab_pdd_seconds_bucket{le}`, `_count`, `_sum`. |
| `sipnab_mos` | histogram | RTP MOS distribution (buckets at 1/2/2.5/3/3.5/4/4.5). |
| `sipnab_jitter_ms` | histogram | RTP jitter distribution (buckets at 5/10/20/50/100/200ms). |
| `sipnab_loss_percent` | histogram | RTP packet-loss distribution (buckets at 0.1/0.5/1/2/5/10%). |

The following metric *names* are declared in source (and will be formatted when the underlying maps have entries) but are not yet wired to the data plane in v0.3.x — they will appear empty in Prometheus until the upstream counters get populated: `sipnab_responses_total{code}`, `sipnab_security_alerts_total{type}`, `sipnab_diagnosis_total{kind}`. Track-via PR / dashboard authors: don't depend on these in alerts yet.

## Client Examples

End-to-end examples in five languages. Each one covers: bearer-token auth, listing dialogs filtered by state, fetching a single dialog with pagination, scraping `/metrics`, and error handling. Adapt to your environment.

> **Filter parameters:** the REST API accepts `state` (e.g. `Failed`, `Completed`, `InCall`) and `from` (regex on the From header) as query parameters on `/v1/dialogs`, plus `orphaned` and `mos_below` on `/v1/streams`. Full DSL filtering — anything more complex than a single state/from match — is **not** available over REST. For arbitrary DSL queries, use the [MCP server](@/docs/mcp.md)'s `list_dialogs` tool, which accepts a `filter` argument that runs through the same evaluator as `sipnab --filter`.

> **Status codes:** the REST API returns **503 Service Unavailable** when a request is rejected by the rate limiter or the connection cap (not 429). 401 on bad/missing token, 404 on unknown call_id.

> **Per-call response code:** dialog summaries (`/v1/dialogs`) and full dialogs (`/v1/dialogs/{id}` summary block) do not have a top-level `status_code` field — that's a per-message field, available inside `/v1/dialogs/{id}.messages[]` or in CLI `--json` per-message output. Examples below build per-call response-code histograms by walking the messages of each failed dialog.

### curl + jq one-liners

```bash
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

# Get one dialog with full SIP messages
curl -fsS "$API/v1/dialogs/abc123@host" $H | jq

# Get a Markdown call report
curl -fsS "$API/v1/dialogs/abc123@host/report" $H \
     -H 'Accept: text/markdown'

# Non-orphaned streams (orphaned=false)
curl -fsS "$API/v1/streams?orphaned=false" $H | jq

# Streams below a MOS threshold
curl -fsS "$API/v1/streams?mos_below=3.5" $H | jq

# Aggregate counters
curl -fsS "$API/v1/stats" $H | jq

# Per-call final-response histogram for failed dialogs (walk messages)
curl -fsS "$API/v1/dialogs?state=Failed&limit=1000" $H \
  | jq -r '.dialogs[].call_id' \
  | while read -r cid; do
      curl -fsS "$API/v1/dialogs/$(jq -rn --arg c "$cid" '$c|@uri')" $H \
        | jq -r '[.messages[] | select(.is_request == false) | .status_code] | last'
    done \
  | sort | uniq -c | sort -rn

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

    # Per-call final response code (walk each dialog's messages)
    from collections import Counter
    codes: Counter[int] = Counter()
    for d in failed:
        full = c.get_dialog(d["call_id"])
        responses = [m for m in full.get("messages", []) if not m.get("is_request")]
        if responses:
            codes[responses[-1].get("status_code")] += 1
    for code, n in codes.most_common():
        print(f"  {code}: {n}")
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

// Per-call final response code requires fetching the full dialog
interface SipMessage { is_request: boolean; status_code?: number; }
interface FullDialog { messages: SipMessage[]; }

async function finalStatusCode(call_id: string): Promise<number | undefined> {
  const d = await api<FullDialog>(`/v1/dialogs/${encodeURIComponent(call_id)}`);
  const responses = d.messages.filter((m) => !m.is_request);
  return responses.at(-1)?.status_code;
}

// ── Demo ──────────────────────────────────────────────────────────
const failed = await listDialogs("Failed");
console.log(`${failed.length} failed dialogs`);

const histogram = new Map<number | undefined, number>();
for (const d of failed) {
  const code = await finalStatusCode(d.call_id);
  histogram.set(code, (histogram.get(code) ?? 0) + 1);
}
for (const [code, n] of [...histogram].sort((a, b) => b[1] - a[1])) {
  console.log(`  ${code ?? "(none)"}: ${n}`);
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

    /// Fetch one full dialog and return the final response code, if any.
    fn final_status_code(&self, call_id: &str) -> Result<Option<u16>> {
        #[derive(Deserialize)]
        struct Msg { is_request: bool, status_code: Option<u16> }
        #[derive(Deserialize)]
        struct Full { messages: Vec<Msg> }
        let cid = urlencoding::encode(call_id);
        let resp = self.client
            .get(format!("{}/v1/dialogs/{}", self.base, cid))
            .send()?;
        let full: Full = resp.json()?;
        Ok(full.messages.iter()
            .filter(|m| !m.is_request)
            .last()
            .and_then(|m| m.status_code))
    }
}

fn main() -> Result<()> {
    let s = Sipnab::new()?;
    let failed = s.list_dialogs(Some("Failed"))?;
    println!("{} failed dialogs", failed.len());

    use std::collections::BTreeMap;
    let mut hist: BTreeMap<Option<u16>, usize> = BTreeMap::new();
    for d in &failed {
        let code = s.final_status_code(&d.call_id).unwrap_or(None);
        *hist.entry(code).or_default() += 1;
    }
    let mut sorted: Vec<_> = hist.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (code, n) in sorted {
        println!("  {:?}: {}", code, n);
    }
    Ok(())
}
```

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

type SipMessage struct {
    IsRequest  bool `json:"is_request"`
    StatusCode *int `json:"status_code"`
}

type FullDialog struct {
    Messages []SipMessage `json:"messages"`
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

// FinalStatusCode fetches the dialog and returns the last response code.
func (s *Sipnab) FinalStatusCode(callID string) (*int, error) {
    var full FullDialog
    if err := s.get("/v1/dialogs/"+url.PathEscape(callID), nil, &full); err != nil {
        return nil, err
    }
    var last *int
    for _, m := range full.Messages {
        if !m.IsRequest && m.StatusCode != nil {
            last = m.StatusCode
        }
    }
    return last, nil
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

    hist := map[int]int{}
    for _, d := range failed {
        code, err := s.FinalStatusCode(d.CallID)
        if err != nil || code == nil {
            continue
        }
        hist[*code]++
    }
    type kv struct{ k, v int }
    var sorted []kv
    for k, v := range hist {
        sorted = append(sorted, kv{k, v})
    }
    sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
    for _, e := range sorted {
        fmt.Printf("  %d: %d\n", e.k, e.v)
    }
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

> **Tip:** The metrics endpoint is lightweight and suitable for 5-15 second scrape intervals. A sample Grafana dashboard JSON is included in the repository at `contrib/grafana-dashboard.json`.

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

## HEP Protocol

sipnab supports HEP v2/v3 (Homer Encapsulation Protocol) for integration with Homer/SIPCAPTURE.

### Receiving HEP

```bash
sipnab -L 0.0.0.0:9060 -E
```

Restrict sources with `--hep-allow` and rate-limit with `--hep-rate-limit`:

```bash
sipnab -L 0.0.0.0:9060 -E --hep-allow 10.0.0.0/24 --hep-rate-limit 25000
```

### Sending HEP

Mirror captured traffic to a Homer collector:

```bash
sipnab -d eth0 -H 10.0.0.50:9060
```

## Security Model

- The API child process is isolated: no capture fd, no key material
- All network listeners bind to localhost by default
- Rate limiting on all listener endpoints (100 RPS per source IP)
- Bearer token authentication (required for API, optional for metrics)
- Constant-time key comparison prevents timing attacks
- TLS available for API endpoint
- Connection limits prevent resource exhaustion

> **Warning:** The API child process is isolated from the capture process. It has no access to capture file descriptors, TLS key material, or raw packet data. The API can only read dialog/stream metadata.

## Event Execution

sipnab can execute external commands on dialog state changes or quality drops. The command receives event data as JSON on stdin. Event execution works in **all modes** (TUI, CLI, and API) -- it is not specific to the API feature.

```bash
# Run a script when any dialog changes state
sipnab -d eth0 --on-dialog-exec "/usr/local/bin/sip-event.sh"

# Run a script when RTP quality drops below threshold
sipnab -d eth0 --on-quality-exec "/usr/local/bin/quality-alert.sh" \
  --quality-threshold 3.0

# Rate limit exec invocations (default: 10/sec)
sipnab -d eth0 --on-dialog-exec "logger" --exec-rate-limit 5
```

> **Warning:** Always use `--exec-rate-limit` in production to prevent response amplification. Under a SIP flood, an unthrottled exec handler could fork-bomb the system. The default limit of 10/sec is conservative -- adjust based on your use case.

## Fail2ban Integration

Generate fail2ban-compatible output for SIP security events:

```bash
sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab-fail2ban.log
```

Example fail2ban filter configuration:

```ini
# /etc/fail2ban/filter.d/sipnab.conf
[Definition]
failregex = ^.*SCANNER.*from=<HOST>.*$
            ^.*REG_FLOOD.*from=<HOST>.*$
ignoreregex =
```

```ini
# /etc/fail2ban/jail.d/sipnab.conf
[sipnab]
enabled = true
filter = sipnab
logpath = /var/log/sipnab-fail2ban.log
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-allports[name=sipnab, protocol=udp]
```

> **Tip:** Combine `--kill-scanner` with `--kill-ua "friendly-scanner|sipvicious"` to target specific scanner signatures. The `--kill-response` flag (default: 200) controls what SIP response code is sent back to detected scanners.

## Syslog Alerts

Send security alerts to syslog:

```bash
sipnab -d eth0 --kill-scanner --alert syslog --syslog
```

Alerts are sent with facility `LOG_LOCAL0` and severity based on event type (scanner=warning, fraud=alert). Use your syslog server's filtering to route sipnab events to dedicated log files or SIEM systems.
