# Add sipnab's metrics to Prometheus

Your SIP proxy's statistics say what the proxy did: calls routed,
transactions, memory. sipnab's say what the calls themselves looked like on the wire: how
many completed and failed, post-dial delay, and the quality of their audio. In
the same Prometheus, the two sit side by side on one dashboard.

This guide adds sipnab to the Prometheus and Grafana from
[Add Prometheus and Grafana to your voice stack](prometheus.md), and
imports the dashboard that ships with sipnab. Every series sipnab publishes,
and what it means, is in [Prometheus metrics](prometheus-metrics.md). The proxy
is OpenSIPS, from its packages or built from source, or Kamailio, as that
guide's [With Kamailio](prometheus.md#with-kamailio) section sets it up. sipnab
reads the calls off the wire, so every step is the same for each.

## Tested on

Every command on this page ran as written, in order, on 2026-09-26, with
sipnab 0.5.192 from its release package, on the Debian 13 (kernel 6.12.63) and
Ubuntu 24.04.5 (kernel 6.8.0) machines that
[the Prometheus guide](prometheus.md) had set up. The examples use
`192.0.2.10` as the machine's address.

## 1. Install sipnab

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_amd64.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_amd64.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_amd64.deb
sipnab --version
```

## 2. Run sipnab with its metrics on a free port

sipnab's package runs it under systemd as the `sipnab` user, with its metrics
on `127.0.0.1:9090`. That is Prometheus's own port, so move sipnab's to
`127.0.0.1:9091` in a drop-in.

The call counts need only the SIP, which sipnab captures by default. The media
series (MOS, jitter, loss) need the audio too: sipnab 0.5.192 and earlier
capture it only when a capture filter names its ports, as the
[rtpengine guide](rtpengine-sipnab.md#2-let-sipnab-see-the-media) does, and
later versions capture it by default.

```bash
# Run all of these, in order.
sudo mkdir -p /etc/systemd/system/sipnab.service.d
sudo tee /etc/systemd/system/sipnab.service.d/metrics.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/sipnab -N -d any --no-cli-print --syslog --metrics 127.0.0.1:9091
EOF
sudo systemctl daemon-reload
sudo systemctl enable sipnab
sudo systemctl restart sipnab
systemctl is-active sipnab
until curl -fs -o /dev/null 127.0.0.1:9091/metrics; do sleep 1; done
curl -s 127.0.0.1:9091/metrics | awk '/^sipnab_/ && n++ < 3'
```

The empty `ExecStart=` line clears the package's command before the next line
sets this one. If another guide's drop-in also sets `ExecStart`, systemd uses
only the last one it reads, so put all the flags in one drop-in.

## 3. Scrape sipnab

Add sipnab to Prometheus's targets, and restart Prometheus so that it reads
the change. The `until` line waits for Prometheus to scrape sipnab once:

```bash
# Run all of these, in order.
cd /opt/monitoring
cat >> prometheus.yml <<'EOF'
  - job_name: sipnab
    static_configs:
      - targets: ["127.0.0.1:9091"]
EOF
docker compose restart prometheus
targets() { curl -s localhost:9090/api/v1/targets | python3 -c 'import sys,json; [print(t["labels"]["job"], t["health"]) for t in json.load(sys.stdin)["data"]["activeTargets"]]'; }
until targets 2>/dev/null | grep -q '^sipnab up$'; do sleep 2; done
targets
```

It prints the proxy's target, `opensips up` or `kamailio up`, and `sipnab up`.

## 4. Import sipnab's dashboard

The dashboard ships in sipnab's repository as [`contrib/grafana/sipnab-dashboard.json`](https://github.com/NormB/sipnab/blob/main/contrib/grafana/sipnab-dashboard.json).
It asks, on import, which Prometheus data source to use. Import it through
Grafana's API, answering with the data source the Prometheus guide provisioned:

```bash
# Run all of these, in order.
cd /opt/monitoring
V=$(sipnab --version | head -1 | awk '{print $2}')
curl -fsSL "https://raw.githubusercontent.com/NormB/sipnab/v$V/contrib/grafana/sipnab-dashboard.json" -o sipnab-dashboard.json
python3 -c 'import json; d=json.load(open("sipnab-dashboard.json")); print(json.dumps({"dashboard": d, "overwrite": True, "inputs": [{"name": "DS_PROMETHEUS", "type": "datasource", "pluginId": "prometheus", "value": "prometheus"}]}))' > import.json
curl -fs -u "admin:$(sed -n 's/^GF_PASS=//p' .env)" -H 'Content-Type: application/json' \
  -d @import.json localhost:3000/api/dashboards/import | python3 -c 'import sys,json; print(json.load(sys.stdin)["importedUrl"])'
rm import.json
```

The last line prints the dashboard's path. Open it under
`http://192.0.2.10:3000`: the dashboard is **sipnab Overview**.

## 5. Place a call and watch sipnab count it

Place a test call as in
[step 5 of the Prometheus guide](prometheus.md#5-place-a-test-call-and-watch-the-counter),
then ask Prometheus how many calls sipnab saw complete:

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -m 1 -d 1000 -timeout 20s
sleep 8
curl -s localhost:9090/api/v1/query --data-urlencode 'query=sum(sipnab_dialogs_total{state="completed"})' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["result"][0]["value"][1])'
```

It prints 1: sipnab saw the call from its `INVITE` to its `BYE`. The proxy
counted the same call in its own series: OpenSIPS's
`opensips_processed_dialogs`, or Kamailio's `kamailio_core_rcv_requests_invite`.

## With OpenSIPS and Kamailio on one machine

With Kamailio on 5062, as
[OpenSIPS and Kamailio on one machine](kamailio.md#opensips-and-kamailio-on-one-machine)
sets it up, sipnab's default capture of ports 5060-5061 misses Kamailio's
calls. Add `--portrange 5060-5062` to the drop-in in step 2:

```bash
# Run all of these, in order.
sudo sed -i 's|--metrics 127.0.0.1:9091$|--metrics 127.0.0.1:9091 --portrange 5060-5062|' /etc/systemd/system/sipnab.service.d/metrics.conf
grep '^ExecStart=/' /etc/systemd/system/sipnab.service.d/metrics.conf
sudo systemctl daemon-reload
sudo systemctl restart sipnab
```

Step 3 then prints three targets, `opensips`, `kamailio` and `sipnab`, all
`up`, and a call through either proxy adds one to sipnab's count.

## When something does not work

- **`systemctl is-active sipnab` does not say `active`.** Read `journalctl -u
  sipnab`. `Failed to bind metrics server on 127.0.0.1:9090: Address already in
  use` means something else, here Prometheus, holds the port, and systemd keeps
  restarting sipnab. Check the drop-in's `--metrics` port.
- **The `sipnab` target is `down`.** Check `curl 127.0.0.1:9091/metrics` on
  the machine, then the target in `/opt/monitoring/prometheus.yml`.
