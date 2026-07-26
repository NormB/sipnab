+++
title = "REST API & Metrics"
weight = 11
description = "REST API endpoints and Prometheus metrics."
+++

sipnab includes an optional REST API and Prometheus metrics endpoint, enabled with the `api` feature flag. The API runs as a thread inside the sipnab process, reading the same in-memory dialog/stream stores as the capture pipeline (read-only — it never mutates capture state).

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

> **More client code and integrations:** ready-to-adapt clients in several languages live in [API Client Examples](@/docs/api-clients.md); HEP forwarding, event hooks, fail2ban, and syslog live in [Integrations](@/docs/integrations.md).

## Authentication

Credentials are always presented the same way — an `Authorization: Bearer`
header. Nothing else is accepted: not an `X-API-Key` header, not a query
parameter, not HTTP Basic (Basic applies only to the standalone metrics server,
below).

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/dialogs
```

There are **two kinds of credential**, and the server accepts either.

### Method 1 — static API key

A shared secret with **no expiry**. Simplest to set up; you revoke it by
restarting with a different key.

```bash
export SIPNAB_API_KEY="$(openssl rand -hex 32)"
sipnab --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

| Setting | Purpose |
|---|---|
| `--api-key <KEY>` / `$SIPNAB_API_KEY` | The static secret. Prefer the environment variable — argv is visible in `ps`. |

### Method 2 — signed bearer tokens

Self-describing HMAC tokens that carry their own expiry and id, so you get
expiry, rotation, and revocation **without restarting the server**. Prefer this
for CI, automation, and anything multi-client.

The token format is:

```
s2.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

where `payload` is compact JSON
`{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>"}` and the signature is
`HMAC-SHA256(signing_key, "s2." + base64url(payload))`. Verification is
stateless: the server recomputes the HMAC, compares it in constant time against
every configured signing key, then requires the audience to match, `exp > now`,
and that `id` is not revoked. Any malformed token is rejected (fail-closed).

**Audience binding.** `aud` names the surface the token was minted for, so a
token minted from `--api-signing-key` is rejected by the HTTP MCP endpoint and
vice versa — **even when both are configured with the same signing key**. The
version prefix is part of the signed input, so an `s2` token cannot be rewritten
as `s1` to shed its binding. The pre-`aud` `s1` format is **no longer
accepted** — it carried no audience, so honoring it would have left this
binding best-effort. An `s1` token now returns `401`; re-mint with
`--mint-token`. Note that **static** `--api-key` secrets carry no audience —
the binding applies to signed tokens only.

| Setting | Purpose |
|---|---|
| `--api-signing-key <KEY>` / `$SIPNAB_API_SIGNING_KEY` | HMAC signing key. **Repeatable** — the *first* key mints, *all* keys verify. |
| `--api-signing-key-file <FILE>` | Read one key from a file (contents trimmed). Prepended to any `--api-signing-key`, so it becomes the minting key. |
| `--api-token-ttl <SECS>` | Lifetime of a minted token. Default `3600`. |
| `--mint-token` | Sign a token with the first configured key, print it, and exit. Starts no capture and no server. |
| `--token-id <ID>` | The token's `id` (`jti`), used later for revocation. Defaults to a generated id. |
| `--api-revoked-file <FILE>` | Denylist of revoked token ids, one per line (blanks and `#` comments ignored). |

**Mint a token:**

```bash
KEY="$(openssl rand -hex 32)"

# 1-hour token (default TTL)
sipnab --mint-token --api-signing-key "$KEY"

# 24-hour token with an explicit id, so it can be revoked later
sipnab --mint-token --api-signing-key "$KEY" --api-token-ttl 86400 --token-id ci-runner-1
```

**Serve with that key, and honor a denylist:**

```bash
sipnab --api 127.0.0.1:8080 --api-signing-key "$KEY" \
  --api-revoked-file /etc/sipnab/revoked.txt
```

**Expiry** needs no server action — a token is rejected once `exp <= now`.

**Rotation** comes in two independent forms. Rotate *tokens* by minting a new
one before the old lapses and migrating clients; several tokens are valid at
once. Rotate *signing keys* by passing `--api-signing-key` more than once: add
the new key alongside the old, mint with the new one, migrate clients, then
drop the old key on the next restart.

**Revocation** kills a still-valid token before its `exp`:

```bash
echo "ci-runner-1" >> /etc/sipnab/revoked.txt
```

The file is re-read when its mtime changes, so the token stops working within
the next request — no restart.

### When authentication is required

**If you configure neither an API key nor a signing key, authentication is
disabled** and every endpoint is served without credentials. That is allowed
only on a loopback bind. On a non-loopback bind with no credentials configured,
**the server refuses to start** rather than exposing an open API:

```
REST API refuses to start: --api 0.0.0.0:8080 is non-loopback but no
--api-key / SIPNAB_API_KEY or --api-signing-key / SIPNAB_API_SIGNING_KEY was
supplied. Bind 127.0.0.1, or configure authentication.
```

Once credentials are configured, every endpoint **except `/health`** requires
them. `/health` is always unauthenticated. Missing, malformed, non-Bearer,
expired, or revoked credentials return `401 Unauthorized`. All comparisons are
constant-time, to prevent timing side channels.

Note that rate limiting is checked *before* authentication, so a client over
its per-IP budget receives `503 Service Unavailable` even when its credentials
are invalid.

### Metrics endpoints use two different schemes

This catches people out, so it is worth stating plainly:

| Endpoint | Scheme |
|---|---|
| `/metrics` **on the REST API** (`--api`) | The same Bearer credential as every other REST endpoint. |
| The **standalone** metrics server (`--metrics <ADDR>`) | HTTP Basic, via `--metrics-auth <user:pass>` or `--metrics-auth-file <FILE>`. |

The standalone server applies the same fail-closed rule: a non-loopback bind
with no `--metrics-auth` / `--metrics-auth-file` refuses to start.

## API TLS

Direct TLS termination on the API endpoint is **not yet implemented** —
supplying `--api-tls-cert`/`--api-tls-key` makes sipnab refuse to start
with an explanatory error. Terminate TLS in a reverse proxy (nginx,
Caddy, HAProxy) in front of a loopback-bound API instead:

```bash
sipnab -d eth0 --api 127.0.0.1:8080 --api-key "secret"
# then proxy https://host/ -> http://127.0.0.1:8080 in your reverse proxy
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
| `state`   | string | --      | Filter by dialog state (`Trying`, `Ringing`, `InCall`, `Completed`, `Failed`, `Cancelled`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`) |
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
      "call_id": "12013223@203.0.113.195",
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
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@203.0.113.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}",
    headers={"Authorization": "Bearer my-secret-token"},
)
dialog = resp.json()
# REST returns an aggregated dialog — `msg_count`, not the messages themselves.
print(f"State: {dialog['state']}, Messages: {dialog['msg_count']}")
```

**Go:**

```go
callID := url.PathEscape("12013223@203.0.113.195")
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
const callId = encodeURIComponent("12013223@203.0.113.195");
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
  "call_id": "12013223@203.0.113.195",
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
      "media_addr": "192.0.2.1",
      "media_port": 10000,
      "mode": "sendrecv"
    },
    {
      "timestamp": "2026-04-13T10:30:02Z",
      "direction": "answer",
      "codecs": ["PCMU", "telephone-event"],
      "media_addr": "192.0.2.2",
      "media_port": 20000,
      "mode": "sendrecv"
    }
  ],
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false,
    "hints": [
      "Asymmetric media may be due to comfort noise (42% CN frames)."
    ]
  },
  "streams": [
    {
      "schema_version": 1,
      "ssrc": "0x1a2b3c4d",
      "codec": "PCMU",
      "payload_type": 0,
      "src": "192.0.2.1:10000",
      "dst": "192.0.2.2:20000",
      "packets": 4820,
      "octets": 771200,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@203.0.113.195",
      "first_seen": "2026-04-13T10:30:02Z",
      "last_seen": "2026-04-13T10:30:47Z",
      "quality_intervals": []
    }
  ]
}
```

**Additional dialog fields:**

- **`diagnosis.hints`** -- Free-text diagnostic strings from the media analyzer: one-way audio, NAT mismatch (SDP `c=` address vs. actual RTP source), comfort-noise asymmetry (shown in the example above), codec / payload-type / ptime / duration asymmetry, and late media. Empty array when nothing was detected.
- **STIR/SHAKEN** -- When `--stir-shaken` validation is enabled (requires the `tls` build feature), the attestation level, orig/dest TNs, and verification status are written to the capture log. They are **not** part of the REST dialog JSON: there is no `stir_shaken` field, and the results do not appear in `diagnosis.hints`. Tokens whose `iat` (issued-at) claim is more than 60 seconds from the current time are marked `Expired` per RFC 8224 Section 4.4.

Returns `404` if the Call-ID is not found.

---

### GET /v1/dialogs/{call_id}/report

Get a structured call diagnosis report for a dialog in JSON format. Includes transaction timing, media quality, one-way audio detection, NAT mismatch analysis, and SDP timeline.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195/report" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@203.0.113.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}/report",
    headers={"Authorization": "Bearer my-secret-token"},
)
report = resp.json()
# `diagnosis` carries three booleans plus `hints` — there is no `summary` field.
hints = report["diagnosis"]["hints"]
print(f"Diagnosis: {'; '.join(hints) if hints else 'no issues detected'}")
```

**Go:**

```go
callID := url.PathEscape("12013223@203.0.113.195")
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
const callId = encodeURIComponent("12013223@203.0.113.195");
const resp = await fetch(
  `http://127.0.0.1:8080/v1/dialogs/${callId}/report`,
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const report = await resp.json();
console.log(JSON.stringify(report, null, 2));
```

**Response:**

In JSON format this endpoint returns **exactly the same document shape as
`GET /v1/dialogs/{call_id}`** — both serialize through the same internal
dialog projection (`generate_call_report(..., Json)` delegates to the one
dialog-to-JSON serializer). The text and Markdown report layouts are only
available via the MCP `get_dialog_report` tool and the CLI `--call-report`.

```json
{
  "schema_version": 1,
  "call_id": "12013223@203.0.113.195",
  "from": "alice",
  "to": "bob",
  "state": "Completed",
  "method": "INVITE",
  "msg_count": 8,
  "duration_sec": 45.2,
  "timing": {
    "pdd_ms": 847,
    "setup_ms": 2134,
    "ring_ms": 1287,
    "trying_delay_ms": 12,
    "teardown_ms": 45,
    "retransmits": 0
  },
  "sdp_timeline": [],
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false,
    "hints": []
  },
  "streams": []
}
```

For a call with negotiated media, `sdp_timeline[]` and `streams[]` carry the
same objects shown in the `GET /v1/dialogs/{call_id}` example above. Optional
fields (`from`, `to`, `from_display`, `to_display`, `tags`, per-timing values)
are omitted — not `null` — when absent.

Returns `404` if the Call-ID is not found.

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
      "src": "192.0.2.1:10000",
      "dst": "192.0.2.2:20000",
      "packets": 4820,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@203.0.113.195",
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

Prometheus-compatible metrics endpoint. Returns metrics in the Prometheus text exposition format (`text/plain; version=0.0.4`).

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
| `sipnab_kill_responses_sent_total{mode}` | counter | Scanner-kill responses sent, by source mode: `raw` (source-spoofed via a raw socket) or `ephemeral` (sipnab's own port). Alert on unexpected `ephemeral` to catch a silent spoof fallback. |
| `sipnab_capture_queue_depth_packets` | gauge | Packets currently queued between the capture reader and the processing thread (standalone `--metrics` server). |
| `sipnab_capture_backpressure_blocks_total` | counter | Times the capture reader blocked on a full queue (standalone `--metrics` server). |
| `sipnab_pdd_seconds` | histogram | Post-dial delay distribution (buckets at 0.5/1/2/3/5/10s). Emits `sipnab_pdd_seconds_bucket{le}`, `_count`, `_sum`. |
| `sipnab_mos` | histogram | RTP MOS distribution (buckets at 1/2/2.5/3/3.5/4/4.5). |
| `sipnab_jitter_ms` | histogram | RTP jitter distribution (buckets at 5/10/20/50/100/200ms). |
| `sipnab_loss_percent` | histogram | RTP packet-loss distribution (buckets at 0.1/0.5/1/2/5/10%). |

The following metric *names* are declared in source (and will be formatted when the underlying maps have entries) but are not yet wired to the data plane as of 0.5.44 — they will appear empty in Prometheus until the upstream counters get populated: `sipnab_responses_total{code}`, `sipnab_security_alerts_total{type}`, `sipnab_diagnosis_total{kind}`, `sipnab_capture_packets_total`, `sipnab_reassembly_timeouts_total`. Track-via PR / dashboard authors: don't depend on these in alerts yet.

## Security Model

- The API thread only reads dialog/stream metadata: no capture fd access, no key material exposure
- All network listeners bind to localhost by default
- Rate limiting on all listener endpoints (100 RPS per source IP)
- Bearer token authentication required on every REST endpoint except `/health` — `/metrics` on the `--api` server sits on the same guarded router and takes the same credential (the *standalone* `--metrics` server is the one that uses HTTP Basic instead)
- Constant-time key comparison prevents timing attacks
- TLS not terminated in-process; run behind a reverse proxy (see [API TLS](#api-tls))
- Connection limits prevent resource exhaustion

> **Note:** The API runs as a thread in the sipnab process, sharing the in-memory dialog/stream stores read-only. It never touches capture file descriptors or TLS key material, and exposes only dialog/stream metadata — but it is not a separate OS process; treat the API bind address and key accordingly.
