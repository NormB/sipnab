+++
title = "REST API"
description = "sipnab REST API reference: 8 endpoints with authentication, rate limiting, and Prometheus metrics."
weight = 7

[extra]
weight = 7
+++

sipnab provides a read-only REST API for querying active SIP dialogs and RTP streams. Requires the `api` feature flag at build time and the `--api` flag at runtime.

```bash
# Start sipnab with REST API on port 8080
sipnab --api :8080 --api-key "your-secret-key" -d eth0
```

## Overview

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/v1/dialogs` | Yes | List dialogs (paginated, filterable) |
| GET | `/v1/dialogs/:call_id` | Yes | Get single dialog with full detail |
| GET | `/v1/dialogs/:call_id/report` | Yes | Get call diagnosis report |
| GET | `/v1/streams` | Yes | List RTP streams (paginated, filterable) |
| GET | `/v1/streams/:id` | Yes | Get single RTP stream by SSRC |
| GET | `/v1/stats` | Yes | Aggregate statistics |
| GET | `/metrics` | Yes | Prometheus exposition format |

All responses include a `schema_version` field (currently `1`) for forward compatibility.

## Authentication

If `--api-key` is provided (or the `SIPNAB_API_KEY` env var is set), all endpoints except `/health` require a Bearer token in the `Authorization` header.

```bash
curl -H "Authorization: Bearer your-secret-key" http://localhost:8080/v1/dialogs
```

Missing or invalid keys return `401 Unauthorized`. Token comparison uses constant-time equality to prevent timing side-channel attacks.

If no API key is configured, all endpoints are accessible without authentication. The API binds to localhost by default (defense-in-depth).

## Rate Limiting

Requests are rate-limited to **100 per second per source IP**. Excess requests return `503 Service Unavailable`. The rate limiter uses a sliding one-second window.

Source IP is determined from the direct connection address only. `X-Forwarded-For` and `X-Real-IP` headers are not trusted (they are attacker-controlled).

Maximum concurrent connections is controlled by `--api-max-conn` (default 100). When exceeded, new connections return `503 Service Unavailable`.

## Endpoints

### GET /health

Health check. Always returns `200 OK` with body `ok`. No authentication required.

```bash
curl http://localhost:8080/health
# ok
```

### GET /v1/dialogs

List dialogs with optional filtering and pagination.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `offset` | integer | `0` | Pagination offset |
| `limit` | integer | `50` | Max results (capped at 1000) |
| `state` | string | -- | Filter by dialog state: `Trying`, `Ringing`, `InCall`, `Completed`, `Failed`, `Cancelled` |
| `from` | string | -- | Filter by From user (regex) |

**Response:**

```json
{
  "schema_version": 1,
  "total": 1523,
  "offset": 0,
  "limit": 50,
  "dialogs": [
    {
      "call_id": "abc123@192.168.1.10",
      "method": "INVITE",
      "from_user": "1001",
      "to_user": "1002",
      "state": "InCall",
      "msg_count": 6,
      "first_seen": "2025-01-15T10:30:00Z",
      "last_seen": "2025-01-15T10:30:45Z"
    }
  ]
}
```

**Example:**

```bash
# List failed dialogs
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/dialogs?state=Failed&limit=10"

# Filter by From user
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/dialogs?from=1001"
```

### GET /v1/dialogs/:call\_id

Get a single dialog with full detail, including all SIP messages, associated RTP streams, and media diagnosis.

Returns the same JSON format as `sipnab -N --json --call-report`.

Returns `404` if the Call-ID is not found.

```bash
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/dialogs/abc123@192.168.1.10"
```

### GET /v1/dialogs/:call\_id/report

Get a structured call diagnosis report in JSON format. Includes SIP transaction timing, RTP quality metrics, media diagnosis, and VoIP troubleshooting information.

Returns `404` if the Call-ID is not found.

```bash
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/dialogs/abc123@192.168.1.10/report"
```

**Response:**

```json
{
  "call_id": "abc123@192.168.1.10",
  "state": "Completed",
  "timing": {
    "pdd_ms": 245,
    "setup_time_ms": 1200,
    "duration_ms": 45000
  },
  "rtp": {
    "streams": 2,
    "quality": {
      "mos": 4.2,
      "jitter_ms": 3.5,
      "loss_pct": 0.1
    }
  },
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false
  }
}
```

### GET /v1/streams

List RTP streams with optional filtering and pagination.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `offset` | integer | `0` | Pagination offset |
| `limit` | integer | `50` | Max results (capped at 1000) |
| `orphaned` | boolean | -- | Filter by orphaned status. `true` = only orphaned, `false` = only associated |
| `mos_below` | float | -- | Filter streams with MOS below this threshold |

**Example:**

```bash
# Find low-quality streams
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/streams?mos_below=3.0"

# List orphaned streams (no associated SIP dialog)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/streams?orphaned=true"
```

### GET /v1/streams/:id

Get a single RTP stream by SSRC hex string. The `:id` parameter is the SSRC in hex format, with optional `0x` prefix.

Returns `400` if the SSRC is not valid hex. Returns `404` if the stream is not found.

```bash
# Both formats work
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/streams/0x12345678"

curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/v1/streams/12345678"
```

### GET /v1/stats

Aggregate statistics across all tracked dialogs and streams.

**Response:**

```json
{
  "schema_version": 1,
  "dialogs": {
    "total": 15230,
    "active": 42,
    "completed": 14500,
    "failed": 688,
    "cancelled": 0
  },
  "streams": {
    "total": 28400,
    "orphaned": 12
  },
  "timing": {
    "pdd_p50_ms": 180,
    "pdd_p95_ms": 1200,
    "pdd_p99_ms": 3500
  }
}
```

### GET /metrics

Prometheus exposition format metrics. Compatible with Prometheus, Grafana Agent, Victoria Metrics, and any OpenMetrics scraper.

All metric names are prefixed with `sipnab_`.

**Available Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sipnab_dialogs_total` | counter | `state` | Total SIP dialogs by state |
| `sipnab_messages_total` | counter | `method` | Total SIP messages by method |
| `sipnab_responses_total` | counter | `code` | Total SIP responses by code class (2xx, 4xx, ...) |
| `sipnab_rtp_streams_active` | gauge | -- | Currently active RTP streams |
| `sipnab_rtp_streams_total` | counter | `status` | Total RTP streams by status |
| `sipnab_capture_packets_total` | counter | -- | Total captured packets |
| `sipnab_security_alerts_total` | counter | `type` | Security alerts by type |
| `sipnab_pdd_seconds` | histogram | -- | Post-dial delay distribution |
| `sipnab_mos_score` | histogram | -- | MOS score distribution |
| `sipnab_jitter_ms` | histogram | -- | Jitter distribution |
| `sipnab_loss_pct` | histogram | -- | Packet loss distribution |
| `sipnab_reassembly_timeouts_total` | counter | -- | TCP reassembly timeouts |
| `sipnab_diagnosis_total` | counter | `type` | Media diagnosis events (one_way_audio, nat_mismatch, ...) |

**Example:**

```bash
curl -H "Authorization: Bearer $KEY" http://localhost:8080/metrics
```

**Prometheus Configuration:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sipnab
    scheme: http
    bearer_token: your-secret-key
    static_configs:
      - targets: ['localhost:8080']
```

You can also enable a separate metrics-only endpoint with `--metrics` and `--metrics-auth`, independent of the REST API.

## TLS

The API supports TLS via `--api-tls-cert` and `--api-tls-key` flags. For production deployments, a TLS-terminating reverse proxy (nginx, HAProxy, Caddy) is recommended over direct TLS.

Binding to a non-loopback address without TLS produces a warning at startup.

## Process Isolation

The API server runs in an isolated child process. It has no access to packet capture file descriptors or TLS key material. It communicates with the main process through shared read-only stores (DialogStore and StreamStore), protected by read-write locks.
