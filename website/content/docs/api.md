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
# HELP sipnab_rtp_streams_total RTP streams by type
# TYPE sipnab_rtp_streams_total gauge
sipnab_rtp_streams_total{type="established"} 43
sipnab_rtp_streams_total{type="orphaned"} 3
...
```

Available metrics include:

- **sipnab_dialogs_total** -- Total number of tracked dialogs by state
- **sipnab_rtp_streams_total** -- Total RTP streams by type (established/orphaned)
- **sipnab_rtp_streams_active** -- Currently active RTP streams
- **sipnab_messages_total** -- SIP messages by method
- **sipnab_rtp_mos_histogram** -- MOS score distribution
- **sipnab_rtp_jitter_histogram** -- Jitter distribution
- **sipnab_rtp_loss_histogram** -- Packet loss distribution
- **sipnab_pdd_histogram** -- Post-dial delay distribution

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
