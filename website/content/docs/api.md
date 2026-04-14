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

## API TLS

Secure the API endpoint with TLS:

```bash
sipnab -d eth0 --api 0.0.0.0:8443 --api-key "secret" \
  --api-tls-cert /etc/sipnab/cert.pem --api-tls-key /etc/sipnab/key.pem
```

## Connection Limits

The `--api-max-conn` flag (default: 100) limits concurrent API connections to prevent resource exhaustion.

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

sipnab can execute external commands on dialog state changes or quality drops:

```bash
# Run a script when any dialog changes state
sipnab -d eth0 --on-dialog-exec "/usr/local/bin/sip-event.sh"

# Run a script when RTP quality drops below threshold
sipnab -d eth0 --on-quality-exec "/usr/local/bin/quality-alert.sh" \
  --quality-threshold 3.0

# Rate limit exec invocations (default: 10/sec)
sipnab -d eth0 --on-dialog-exec "logger" --exec-rate-limit 5
```

## Fail2ban Integration

Generate fail2ban-compatible output for SIP security events:

```bash
sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab-fail2ban.log
```

Configure fail2ban to watch the log file for scanner and flood events.

## Syslog Alerts

Send security alerts to syslog:

```bash
sipnab -d eth0 --kill-scanner --alert syslog --syslog
```
