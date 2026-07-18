# REST API & Metrics

sipnab includes an optional REST API and Prometheus metrics endpoint, enabled with the `api` feature flag. The API runs as a thread inside the sipnab process, reading the same in-memory dialog/stream stores as the capture pipeline — read-only; it never mutates capture state.

The same dialog / RTP / diagnostic data is also exposed to AI agents over the Model Context Protocol; see [MCP Server](mcp.md). The MCP path uses the same in-memory stores as this REST API, so one running sipnab instance can serve both surfaces simultaneously.

All API flags are catalogued in [CLI Reference](cli-reference.md#network-listeners).

## Getting started

Build with API support (`api` feature flag), then start sipnab with an `--api` bind address and a key:

```bash
cargo build --release --features api   # or --features full

export SIPNAB_API_KEY="my-secret-token-change-this"

# Live capture
sudo sipnab --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"

# Analyze a pcap (process stays alive serving the API until Ctrl-C)
sipnab -N -I capture.pcap --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

Query it:

```bash
curl -H "Authorization: Bearer $SIPNAB_API_KEY" http://127.0.0.1:8080/v1/dialogs
```

## Authentication

The REST API authenticates with a bearer token passed as `Authorization: Bearer <token>`:

```bash
curl -H "Authorization: Bearer your-secret-key" http://127.0.0.1:8080/v1/dialogs
```

The token is either a static secret (`--api-key` / `$SIPNAB_API_KEY`) or an HMAC-signed self-describing token that carries its own expiry and id (enabling expiry, rotation, and revocation without restart). All endpoints **except `/health`** require authentication when a key is configured; missing or invalid credentials return `401 Unauthorized`. Comparison is constant-time to prevent timing side channels. On a non-loopback bind a token is required — the server refuses to start otherwise.

For the full token lifecycle — minting (`--mint-token`), TTLs, signing-key rotation, and revocation denylists — see [Bearer-token authentication](auth.md).

The REST API's `/metrics` endpoint is guarded by the same bearer token as every other endpoint. The *standalone* metrics server (`--metrics <ADDR>`) is separate: it uses HTTP Basic auth via `--metrics-auth <user:pass>`.

## API TLS

Direct TLS termination on the API endpoint is **not yet implemented** — supplying `--api-tls-cert` / `--api-tls-key` makes sipnab refuse to start with an explanatory error. Terminate TLS in a reverse proxy (nginx, Caddy, HAProxy) in front of a loopback-bound API instead:

```bash
sipnab -d eth0 --api 127.0.0.1:8080 --api-key "secret"
# then proxy https://host/ -> http://127.0.0.1:8080 in your reverse proxy
```

## Bind address & connection limits

The base URL is whatever you pass to `--api` (e.g., `http://127.0.0.1:8080`). All network listeners bind to loopback by default; bind a routable address (e.g. `0.0.0.0:8080`) only behind a token and a reverse proxy. Data endpoints use a `/v1/` prefix; utility endpoints (`/health`, `/metrics`) have no prefix.

`--api-max-conn` (default `100`) caps concurrent API connections to prevent resource exhaustion. Requests are additionally rate-limited to 100 per second per source IP. Requests rejected by the rate limiter or connection cap return **`503 Service Unavailable`** (not 429).

## Endpoint reference

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check, returns `"ok"` |
| `GET /v1/dialogs` | bearer | List tracked SIP dialogs (filter + paginate) |
| `GET /v1/dialogs/{call_id}` | bearer | Full dialog detail incl. streams + diagnosis |
| `GET /v1/dialogs/{call_id}/report` | bearer | Structured call-diagnosis report (JSON) |
| `GET /v1/streams` | bearer | List tracked RTP streams (filter + paginate) |
| `GET /v1/streams/{id}` | bearer | Single RTP stream by SSRC |
| `GET /v1/stats` | bearer | Aggregate dialog/stream/timing counters |
| `GET /metrics` | bearer | Prometheus text exposition |

### GET /health

Health check. Returns `"ok"`, no authentication required.

```bash
curl http://127.0.0.1:8080/health
```

### GET /v1/dialogs

List all tracked SIP dialogs with optional filtering and pagination.

**Query parameters:**

| Parameter | Type   | Default | Description |
|-----------|--------|---------|-------------|
| `state`   | string | --      | Filter by dialog state (`Trying`, `Ringing`, `InCall`, `Completed`, `Failed`, `Cancelled`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`) |
| `from`    | string | --      | Filter by From user (regex pattern) |
| `limit`   | int    | 50      | Maximum results (capped at 1000) |
| `offset`  | int    | 0       | Pagination offset |

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10" | jq .
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

The REST API accepts only `state` and `from` on `/v1/dialogs` (plus `orphaned` / `mos_below` on `/v1/streams`). Full DSL filtering — anything more complex than a single state/from match — is **not** available over REST; use the [MCP server](mcp.md)'s `list_dialogs` tool, which accepts a `filter` argument that runs through the same evaluator as `sipnab --filter`.

### GET /v1/dialogs/{call_id}

Full details for a single dialog by Call-ID, including associated RTP streams and media diagnosis.

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195" | jq .
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

**Notes on fields:**

- `diagnosis.hints` — free-text strings from the media analyzer: one-way audio, NAT mismatch (SDP `c=` address vs. actual RTP source), comfort-noise asymmetry, codec / payload-type / ptime / duration asymmetry, and late media. Empty array when nothing was detected.
- **STIR/SHAKEN** — when `--stir-shaken` validation is enabled (requires the `tls` build feature), the attestation level, orig/dest TNs, and verification status are written to the capture log. They are **not** part of the REST dialog JSON (there is no `stir_shaken` field, and they do not appear in `diagnosis.hints`). Tokens whose `iat` claim is more than 60 seconds from now are marked `Expired` per RFC 8224 §4.4.
- **Per-message data is not on REST.** Each dialog is aggregated into a summary (`call_id`, `state`, `from`, `to`, `duration_sec`, `msg_count`, `timing`, `diagnosis`, `sdp_timeline`, `streams`); individual SIP messages and per-response status codes are not exposed. For per-message records (`is_request`, `status_code`, `reason`, `cseq`, …) use the CLI `sipnab -N --json` mode — see [Output Formats](output-formats.md) — or the MCP `get_dialog` tool.

Returns `404` if the Call-ID is not found.

### GET /v1/dialogs/{call_id}/report

Structured call-diagnosis report for a dialog, in JSON. In JSON this endpoint returns **exactly the same document shape as `GET /v1/dialogs/{call_id}`** — both serialize through the same internal dialog projection. The text and Markdown report layouts are only available via the MCP `get_dialog_report` tool and the CLI `--call-report`.

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195/report" | jq .
```

For a call with negotiated media, `sdp_timeline[]` and `streams[]` carry the same objects shown in the `GET /v1/dialogs/{call_id}` example above. Optional fields (`from`, `to`, `from_display`, `to_display`, `tags`, per-timing values) are omitted — not `null` — when absent. Returns `404` if the Call-ID is not found.

### GET /v1/streams

List all tracked RTP streams with quality metrics.

**Query parameters:**

| Parameter  | Type  | Default | Description |
|------------|-------|---------|-------------|
| `orphaned` | bool  | --      | Filter to orphaned streams (no associated dialog) |
| `mos_below`| float | --      | Filter streams with MOS below this threshold |
| `limit`    | int   | 50      | Maximum results (capped at 1000) |
| `offset`   | int   | 0       | Pagination offset |

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0" | jq .
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

### GET /v1/streams/{id}

Single RTP stream by SSRC hex string (e.g., `0x1a2b3c4d` or `1a2b3c4d`).

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/streams/0x1a2b3c4d | jq .
```

Returns the full RTP stream JSON (codec, packet counts, jitter, loss, MOS estimate, associated dialog). Returns `400` for an invalid SSRC format, `404` if not found.

### GET /v1/stats

Aggregate statistics across all dialogs and streams, including PDD percentiles.

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/stats | jq .
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

### GET /metrics

Prometheus-compatible metrics in the text exposition format (`text/plain; version=0.0.4`).

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/metrics | grep '^sipnab_'
```

**Sample output:**

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

**Metric families (emitted by `src/output/prometheus.rs`):**

| Metric | Type | Notes |
|---|---|---|
| `sipnab_dialogs_total{state}` | counter | Tracked dialogs by `DialogState` (`Trying`, `Ringing`, `InCall`, `Completed`, `Cancelled`, `Failed`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`). The `--api` server emits state values **lowercased**; the standalone `--metrics` server emits them **as-cased** — pick the right form for your queries. |
| `sipnab_messages_total{method}` | counter | SIP messages by method (`INVITE`, `REGISTER`, …). |
| `sipnab_rtp_streams_active` | gauge | RTP streams currently in the `Established` state. |
| `sipnab_rtp_streams_total{status}` | counter | RTP streams by status (`established`, `orphaned`). |
| `sipnab_kill_responses_sent_total{mode}` | counter | Scanner-kill responses sent, by source mode: `raw` (source-spoofed via a raw socket) or `ephemeral` (sipnab's own port). Alert on unexpected `ephemeral` to catch a silent spoof fallback. |
| `sipnab_capture_queue_depth_packets` | gauge | Packets queued between the capture reader and the processing thread (standalone `--metrics` server). |
| `sipnab_capture_backpressure_blocks_total` | counter | Times the capture reader blocked on a full queue (standalone `--metrics` server). |
| `sipnab_pdd_seconds` | histogram | Post-dial-delay distribution (buckets at 0.5/1/2/3/5/10s). Emits `_bucket{le}`, `_count`, `_sum`. |
| `sipnab_mos` | histogram | RTP MOS distribution (buckets at 1/2/2.5/3/3.5/4/4.5). |
| `sipnab_jitter_ms` | histogram | RTP jitter distribution (buckets at 5/10/20/50/100/200ms). |
| `sipnab_loss_percent` | histogram | RTP packet-loss distribution (buckets at 0.1/0.5/1/2/5/10%). |

The following metric *names* are declared in source (and formatted when the underlying maps have entries) but are **not yet wired to the data plane** — they appear empty in Prometheus until their upstream counters get populated: `sipnab_responses_total{code}`, `sipnab_security_alerts_total{type}`, `sipnab_diagnosis_total{kind}`, `sipnab_capture_packets_total`, `sipnab_reassembly_timeouts_total`. Do not depend on these in alerts yet.

## Status codes

| Code | When |
|------|------|
| `200` | Success |
| `400` | Malformed request (e.g. invalid SSRC on `/v1/streams/{id}`) |
| `401` | Missing/invalid/expired/revoked bearer token |
| `404` | Unknown `call_id` or stream id |
| `503` | Rejected by the rate limiter or the connection cap (**not** 429) |

## Recipes (curl + jq)

```bash
API="http://127.0.0.1:8080"; KEY="my-secret-token"
H="-H 'Authorization: Bearer $KEY'"

# Health check (no auth)
curl -fsS $API/health

# Failed dialogs / dialogs from a user (from= is a regex)
curl -fsS "$API/v1/dialogs?state=Failed&limit=20" $H | jq
curl -fsS "$API/v1/dialogs?from=alice&limit=20"   $H | jq

# One aggregated dialog, and its JSON call report
curl -fsS "$API/v1/dialogs/abc123@host"        $H | jq
curl -fsS "$API/v1/dialogs/abc123@host/report" $H | jq

# Streams: non-orphaned, or below a MOS threshold
curl -fsS "$API/v1/streams?orphaned=false" $H | jq
curl -fsS "$API/v1/streams?mos_below=3.5"  $H | jq

# Aggregate counters
curl -fsS "$API/v1/stats" $H | jq

# Export all dialogs to CSV
curl -fsS "$API/v1/dialogs?limit=1000" $H \
  | jq -r '.dialogs[] | [.call_id, .method, .state, .from, .to, .duration_sec] | @csv'

# Alert on poor MOS
curl -fsS "$API/v1/streams?mos_below=3.0" $H \
  | jq -r '.streams[] | "LOW MOS: SSRC=\(.ssrc) MOS=\(.mos) call=\(.associated_dialog)"'
```

For per-call response-code histograms (not exposed over REST), use the CLI NDJSON mode — `sipnab -N --json` emits one record per message; see [Output Formats](output-formats.md).

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sipnab
    bearer_token: your-api-key
    static_configs:
      - targets: ['127.0.0.1:8080']
    scrape_interval: 15s
```

The metrics endpoint is lightweight and suitable for 5–15 second scrape intervals. A sample Grafana dashboard JSON ships in the repo at `contrib/grafana-dashboard.json`.

## Client examples

Full end-to-end clients (bearer auth, pagination, `/metrics` scraping, error handling) in Python (sync + async), Node/TypeScript, Rust, and Go are on the website: <https://sipnab.com/docs/api/>.

## Security model

- The API thread only reads dialog/stream metadata: no capture fd access, no key material exposure.
- All network listeners bind to loopback by default.
- Rate limiting on all listener endpoints (100 RPS per source IP) plus a concurrent-connection cap (`--api-max-conn`).
- Bearer-token authentication (required for the API; the standalone `--metrics` server uses HTTP Basic auth).
- Constant-time key comparison prevents timing attacks.
- TLS is not terminated in-process — run behind a reverse proxy (see [API TLS](#api-tls)).

The API runs as a *thread* in the sipnab process, sharing the in-memory stores read-only. It never touches capture file descriptors or TLS key material and exposes only dialog/stream metadata — but it is not a separate OS process, so treat the API bind address and key accordingly.
