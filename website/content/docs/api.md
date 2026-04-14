+++
title = "REST API & Metrics"
weight = 7
description = "REST API endpoints, Prometheus metrics, and HEP protocol integration."
+++

sipnab includes an optional REST API and Prometheus metrics endpoint, enabled with the `api` feature flag. The API runs in an isolated child process with no access to capture file descriptors or key material.

## Enabling the API

Build with the `api` feature:

```bash
cargo build --release --features api
# or
cargo build --release --features full
```

Start with API and metrics endpoints:

```bash
sipnab -d eth0 --api 127.0.0.1:8080 --api-key "your-secret-key" \
  --metrics 127.0.0.1:9090 --metrics-auth "your-metrics-token"
```

## Authentication

The REST API requires a bearer token passed via the `--api-key` flag or the `$SIPNAB_API_KEY` environment variable.

```bash
curl -H "Authorization: Bearer your-secret-key" http://127.0.0.1:8080/api/v1/dialogs
```

The metrics endpoint optionally requires a bearer token via `--metrics-auth`.

> **Tip:** Set the API key via environment variable to avoid it appearing in process listings:
> ```bash
> export SIPNAB_API_KEY="your-secret-key"
> sipnab -d eth0 --api 127.0.0.1:8080
> ```

## API TLS

Secure the API endpoint with TLS:

```bash
sipnab -d eth0 --api 0.0.0.0:8443 --api-key "secret" \
  --api-tls-cert /etc/sipnab/cert.pem --api-tls-key /etc/sipnab/key.pem
```

## Connection Limits

The `--api-max-conn` flag (default: 100) limits concurrent API connections to prevent resource exhaustion.

## REST API Endpoints

### GET /api/v1/dialogs

List all tracked dialogs with optional filtering and pagination.

```bash
# List all dialogs
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/api/v1/dialogs | jq .

# Filter by state with pagination
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/api/v1/dialogs?state=Failed&limit=10&offset=0"

# Filter by From user
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/api/v1/dialogs?from=1001"
```

**Response:**

```json
{
  "dialogs": [
    {
      "call_id": "3c9a82f1e7b4@10.0.0.1",
      "method": "INVITE",
      "state": "InCall",
      "from_user": "alice",
      "to_user": "bob",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "message_count": 12,
      "timing": {
        "pdd_ms": 847,
        "setup_ms": 2134
      }
    }
  ],
  "total": 47,
  "offset": 0,
  "limit": 20
}
```

### GET /api/v1/dialogs/:call_id

Get details for a specific dialog by Call-ID.

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/api/v1/dialogs/3c9a82f1e7b4@10.0.0.1" | jq .
```

### GET /api/v1/streams

List all tracked RTP streams with quality metrics.

```bash
# All streams
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/api/v1/streams | jq .

# Streams with poor quality
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/api/v1/streams?mos_below=3.0"
```

**Response:**

```json
{
  "streams": [
    {
      "ssrc": "0x1a2b3c4d",
      "src": "10.0.0.1:10000",
      "dst": "10.0.0.2:20000",
      "codec": "PCMU",
      "packets": 4820,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "mos": 4.2,
      "call_id": "3c9a82f1e7b4@10.0.0.1"
    }
  ],
  "total": 14
}
```

### GET /api/v1/stats

Get aggregate statistics for the current capture session.

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/api/v1/stats | jq .
```

**Response:**

```json
{
  "dialogs_total": 1247,
  "dialogs_active": 23,
  "streams_total": 46,
  "packets_captured": 892341,
  "alerts_total": 3,
  "uptime_seconds": 3600
}
```

### GET /api/v1/alerts

List security alerts (scanner detections, fraud, registration floods).

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/api/v1/alerts | jq .
```

> **Warning:** The API child process is isolated from the capture process. It has no access to capture file descriptors, TLS key material, or raw packet data. This is a security design choice -- the API can only read dialog/stream metadata.

## Prometheus Metrics

When `--metrics` is specified, sipnab exposes a Prometheus-compatible `/metrics` endpoint.

Available metrics include:

- **sipnab_dialogs_total** -- Total number of tracked dialogs
- **sipnab_dialogs_active** -- Currently active dialogs
- **sipnab_rtp_streams_total** -- Total RTP streams tracked
- **sipnab_rtp_mos_histogram** -- MOS score distribution
- **sipnab_packets_captured_total** -- Total packets captured
- **sipnab_security_alerts_total** -- Security alerts by type

### Grafana Integration

A sample Grafana dashboard JSON is included in the repository at `contrib/grafana-dashboard.json`.

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sipnab'
    scheme: http
    bearer_token: 'your-metrics-token'
    static_configs:
      - targets: ['127.0.0.1:9090']
    scrape_interval: 15s
```

> **Tip:** The metrics endpoint is lightweight and suitable for 5-15 second scrape intervals. For high-traffic SIP servers, the histogram metrics provide percentile-based MOS distribution without storing individual values.

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
- Rate limiting on all listener endpoints
- Bearer token authentication (required for API, optional for metrics)
- TLS available for API endpoint

## Event Execution

sipnab can execute external commands on dialog state changes or quality drops. The command receives event data as JSON on stdin.

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
