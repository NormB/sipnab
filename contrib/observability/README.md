# Observability Test Stack

A Docker Compose stack for exercising sipnab's metrics and traces.
Runs against a sipnab process on the same host (default) or against
sipnab on a remote host reachable over the network. The same compose
file works in both topologies — only the `SIPNAB_HOST` env var changes.

## Stack

| Service          | Image                                            | Purpose                                              |
| ---------------- | ------------------------------------------------ | ---------------------------------------------------- |
| `prometheus`     | `prom/prometheus:v3.1.0`                         | Scrapes sipnab `/metrics`, evaluates alert rules     |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.117.0`   | OTLP receiver (Phase 9.2 traces target)              |
| `tempo`          | `grafana/tempo:2.7.0`                            | Trace backend, fed by the collector                  |
| `grafana`        | `grafana/grafana:11.4.0`                         | UI; Prometheus + Tempo provisioned as datasources    |

The existing `contrib/grafana/sipnab-dashboard.json` is the *user-importable*
dashboard. A provisioning-ready copy lives at
`grafana/dashboards/sipnab-overview.json` and is regenerated with `jq`:

```bash
jq 'del(.__inputs, .__requires, .templating) |
    walk(if type == "object" and .uid == "${DS_PROMETHEUS}"
         then .uid = "prometheus" else . end)' \
   ../grafana/sipnab-dashboard.json > grafana/dashboards/sipnab-overview.json
```

## Running it

```bash
cp .env.example .env
docker compose up -d
```

Then run sipnab locally with metrics exposed:

```bash
sipnab -N -L 0.0.0.0:9060 --metrics 0.0.0.0:9100
```

Open <http://localhost:3000> (admin/admin), navigate to the *sipnab*
folder, open the *sipnab Overview* dashboard.

## Co-located vs. remote sipnab

The compose file is identical in both topologies. The only difference is
how Prometheus reaches sipnab — controlled by `SIPNAB_HOST` in `.env`.

| Topology                                         | `.env`                                   | Effect                                                       |
| ------------------------------------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| sipnab on the same host as the compose stack     | `SIPNAB_HOST=host-gateway` *(default)*   | Containers reach sipnab via Docker's host-gateway alias      |
| sipnab on a different host (e.g. capture server) | `SIPNAB_HOST=<sipnab-host-or-ip>`        | Prometheus scrapes `<host>:9100` over the network            |

`prometheus.yml`'s scrape target is the literal hostname `sipnab`, resolved
inside each container by the compose-injected `extra_hosts` entry.

## Validating the stack

```bash
# Prometheus is up, scrape targets healthy.
curl -s localhost:9090/-/healthy
curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job:.labels.job, health}'

# Sipnab metrics flowing.
curl -s 'localhost:9090/api/v1/query?query=up{job="sipnab"}'

# OTLP receiver is up (returns 405 on GET — that means it's listening).
curl -i localhost:4318/v1/traces

# Tempo is reachable from inside the network (via grafana's datasource proxy).
# Tempo's :3200 is intentionally not host-exposed.
curl -sf 'localhost:3000/api/datasources/proxy/uid/tempo/ready'
```

## Retention

Defaults: Prometheus 30 days, Tempo 7 days. Override via `.env`
(`PROM_RETENTION=90d`, etc.). Volumes are named (`prometheus-data`,
`tempo-data`, `grafana-data`) so a `docker compose down` *without* `-v`
preserves history across restarts.

## Remote-sipnab deployment

For a topology where sipnab runs on a separate capture host fed by HEP
mirrors from upstream SIP/RTP services:

1. Run `sipnab --hep-listen 0.0.0.0:9060 --api 0.0.0.0:9100 -N` on the
   capture host (the included `sipnab-hep.service` is a sample systemd
   unit — adjust user, paths, and capability set for your environment).
2. Run this compose stack on a separate host with `SIPNAB_HOST=<capture-host>`
   in `.env`.
3. Configure your SIP server to mirror HEP v3 to `<capture-host>:9060`
   (OpenSIPS: `proto_hep` + `siptrace`; rtpengine: `homer = <host>:9060`;
   Kamailio/FreeSWITCH have similar `siptrace`/`homer` modules).

### Runtime dependencies on the capture host

A `--features full` (or `--features audio`) sipnab binary dynamically
links `libasound.so.2` and refuses to start if it's missing — even in
HEP-listener mode, where audio playback is never invoked. A
`--features native` (or any build that includes the `native` feature)
also links `libpcap.so.0.8`. On Debian/Ubuntu hosts:

```bash
apt-get install -y libpcap0.8 libasound2
```

If you don't need TUI audio playback on the capture host (typical for
a server that only runs `--hep-listen --api` or `--mcp`), build without
the `audio` feature to drop the libasound dependency:

```bash
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

### Cross-glibc compatibility

If you build on a newer Debian/Ubuntu (e.g. Debian 13 / glibc 2.41) and
deploy to an older one (Debian 12 / glibc 2.36), the binary will fail
with `version 'GLIBC_2.39' not found`. Build inside a container
matching the target's glibc — for example, `rust:1-bookworm` for
Debian 12 deploys.
