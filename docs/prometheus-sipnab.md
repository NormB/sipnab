# Add sipnab's metrics to Prometheus

Your SIP proxy's statistics say what the proxy did: calls routed,
transactions, memory. sipnab's say what the calls themselves looked like on the
wire:

- how many completed and failed,
- post-dial delay,
- the quality of their audio.

In the same Prometheus, the two sit side by side on one dashboard.

This guide adds sipnab to the Prometheus and Grafana from
[Add Prometheus and Grafana to your voice stack](prometheus.md). It also
imports the dashboard that ships with sipnab. Every series sipnab publishes,
and what it means, is in [Prometheus metrics](prometheus-metrics.md).

The proxy is one of these:

- OpenSIPS, from its packages or built from source;
- Kamailio, as that guide's [With Kamailio](prometheus.md#with-kamailio)
  section sets it up.

sipnab reads the calls off the wire, so every step is the same for each.

## Before you start

- **The stack from
  [Add Prometheus and Grafana to your voice stack](prometheus.md),** with its
  test call counted. The steps here reuse its SIPp files in `~/sipp` and its
  `/opt/monitoring` directory.
- **root on the machine that runs sipnab.** The steps use `sudo`.
- **On the other system, Prometheus,** the Scrape sipnab step adds a `sipnab`
  job to `prometheus.yml` and restarts Prometheus. Grafana gains one
  dashboard.
- **With Prometheus on another machine,** the firewall between the two opens
  sipnab's metrics port to Prometheus's address.
  [Scrape sipnab from another machine](#scrape-sipnab-from-another-machine)
  has the steps.
- **On the SIP proxy, the phones and the carriers,** nothing changes.

## Tested on

Every block on this page ran as written, in order, on 2026-09-28, with
sipnab 0.5.194 from its release package. It ran on clean x86_64 virtual
machines with 2 cores and 3 GB of memory:

- Debian 13 (kernel 6.12.63)
- Ubuntu 24.04.5 (kernel 6.8.0)

On each, it ran with OpenSIPS, from source and from the packages, with
Kamailio, and with both on one machine.

On Debian 13, causing each fault under
[When something does not work](#when-something-does-not-work) produced what
it describes.

On 2026-11-03 the steps ran again with sipnab 0.5.232 built from source, on
Ubuntu 24.04.5 (aarch64, kernel 6.8.12), with Prometheus 3.15.0 and Grafana
13.2.2 started as [Start Prometheus and Grafana](prometheus.md#start-prometheus-and-grafana)
says. That run differed from the steps in two ways:

- sipnab ran from the command line, capturing the loopback interface, rather
  than under the package's systemd unit.
- No SIP server ran. `tcpreplay` replayed [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
  which holds one completed call, onto the loopback interface. The
  query in [Place a call and watch sipnab count it](#place-a-call-and-watch-sipnab-count-it)
  printed `1`, and the imported dashboard was **sipnab Overview**, with 7
  panels.

[Scrape sipnab from another machine](#scrape-sipnab-from-another-machine)
ran the same day against the same Prometheus, with sipnab and Prometheus on
one host and `server_name` set, because the certificate named
`capture01.example.net`.

The examples use `192.0.2.10` as the machine's address.

## Install sipnab

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
A=$(dpkg --print-architecture)
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_${A}.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_${A}.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_${A}.deb
sipnab --version
```

## Run sipnab with its metrics on a free port

sipnab's package runs it under systemd as the `sipnab` user, with its metrics
on `127.0.0.1:9090`. That is Prometheus's own port. So move sipnab's to
`127.0.0.1:9091` in a drop-in.

The call counts need only the SIP, which sipnab captures by default. The media
series (MOS, jitter, loss) need the audio too:

- sipnab 0.5.192 and earlier capture it only when a capture filter names its
  ports, as the [rtpengine guide](rtpengine-sipnab.md#let-sipnab-see-the-media)
  does.
- Later versions capture it by default.

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
sets this one. Another guide's drop-in may also set `ExecStart`. Then systemd
uses only the last one it reads. So put all the flags in one drop-in.

## Scrape sipnab

Add sipnab to Prometheus's targets. Restart Prometheus so that it reads
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

## Import sipnab's dashboard

The dashboard ships in sipnab's repository as [`contrib/grafana/sipnab-dashboard.json`](https://github.com/NormB/sipnab/blob/main/contrib/grafana/sipnab-dashboard.json).
It asks, on import, which Prometheus data source to use. Import it through
Grafana's API. Answer with the data source the Prometheus guide provisioned:

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

## Place a call and watch sipnab count it

Place a test call as in
[the Place a test call and watch the counter step of the Prometheus guide](prometheus.md#place-a-test-call-and-watch-the-counter).
Then ask Prometheus how many calls sipnab saw complete:

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
counted the same call in its own series:

- OpenSIPS's `opensips_processed_dialogs`,
- or Kamailio's `kamailio_core_rcv_requests_invite`.

## Scrape sipnab from another machine

The steps above keep sipnab's metrics on `127.0.0.1`. When Prometheus runs on
another machine, open the port to it with a password, and serve it over HTTPS
so the password does not cross the network in the clear. sipnab refuses a
non-loopback `--metrics` bind that has no credential.

What changes on each side:

- **sipnab:** a credential file, a certificate and its key, and three flags.
- **Prometheus:** a job with `scheme: https`, the CA that issued sipnab's
  certificate, and the password.
- **The firewall** between them: the metrics port, open to Prometheus's
  address only.

On the sipnab machine, write the credential as `user:password`, and give
sipnab a certificate that names the host Prometheus connects to. sipnab drops
its privileges after it opens the capture, so the service user must be able
to read both files. Other users must not read the key:

```bash
# Run all of these, in order.
P=$(openssl rand -hex 12)
sudo sh -c "umask 077; printf 'prometheus:%s\n' '$P' > /etc/sipnab/metrics.auth"
sudo chown sipnab: /etc/sipnab/metrics.auth /etc/sipnab/metrics.key
sudo chmod 600 /etc/sipnab/metrics.key
```

`/etc/sipnab/metrics.pem` is the certificate chain, the server's certificate
first, with `DNS:capture01.example.net` in its subject alternative names.
Then change the drop-in's `--metrics` flag:

```text
--metrics 0.0.0.0:9091 --metrics-auth-file /etc/sipnab/metrics.auth \
  --metrics-tls-cert /etc/sipnab/metrics.pem --metrics-tls-key /etc/sipnab/metrics.key
```

On the Prometheus machine, put the CA certificate and the password where the
container reads them, and add the job:

```yaml
  - job_name: sipnab-tls
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/scrape/sipnab-ca.pem
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/scrape/sipnab-metrics.password
    static_configs:
      - targets: ['capture01.example.net:9091']
```

The password file holds the password alone, with no `prometheus:` and no
newline. When Prometheus reaches sipnab by an address the certificate does
not name, add `server_name: capture01.example.net` under `tls_config`.

**Verify.** The targets check from [Scrape sipnab](#scrape-sipnab) prints
`sipnab-tls up`.

**When it does not work.** Prometheus's targets page, or `lastError` in
`/api/v1/targets`, says why:

| `lastError` | Cause and fix |
|---|---|
| `server returned HTTP status 401 Unauthorized` | The password file does not match `metrics.auth`. Write the password alone, with no newline. |
| `tls: failed to verify certificate: x509: certificate is valid for capture01.example.net, not <name>` | Prometheus connects by a name the certificate does not hold. Use that name in `targets`, or set `server_name`. |
| `connection refused` | sipnab is not listening there: check the drop-in's `--metrics` address and `systemctl is-active sipnab`. |

sipnab itself stops at startup, naming the file, when:

- it cannot read the credential file, for example
  `metrics auth: --metrics-auth-file '/etc/sipnab/metrics.auth': Permission denied (os error 13)`.
  A root run reads it before it drops privileges, so this means the user
  sipnab starts as cannot read it: under the packaged unit, `sipnab`. Make
  the file the service user's, as above.
- other users can read the key, or the key does not match the certificate.
  [Metrics TLS](prometheus-metrics.md#metrics-tls) lists every refusal.

## With OpenSIPS and Kamailio on one machine

With Kamailio on 5062, as
[OpenSIPS and Kamailio on one machine](kamailio.md#opensips-and-kamailio-on-one-machine)
sets it up, sipnab's default capture of ports 5060-5061 misses Kamailio's
calls. Add `--portrange 5060-5062` to the drop-in in the Run sipnab with its
metrics on a free port step:

```bash
# Run all of these, in order.
sudo sed -i 's|--metrics 127.0.0.1:9091$|--metrics 127.0.0.1:9091 --portrange 5060-5062|' /etc/systemd/system/sipnab.service.d/metrics.conf
grep '^ExecStart=/' /etc/systemd/system/sipnab.service.d/metrics.conf
sudo systemctl daemon-reload
sudo systemctl restart sipnab
```

The Scrape sipnab step then prints three targets, `opensips`, `kamailio` and
`sipnab`, all `up`. A call through either proxy adds one to sipnab's count.

## Check that it worked

After a test call, ask sipnab's endpoint and then Prometheus:

```bash
# Run all of these, in order.
curl -s 127.0.0.1:9091/metrics | grep -c '^sipnab_'
curl -s localhost:9090/api/v1/query --data-urlencode 'query=sum(sipnab_dialogs_total{state="completed"})' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["result"][0]["value"][1])'
```

- The first line counts the series sipnab serves. Zero, or no answer, means
  that the endpoint is not up on that port.
- The second prints how many calls sipnab saw complete, as Prometheus stored
  it. It is 1 after the first test call.
- Started with `SIPNAB_LOG=info` in its environment, sipnab also logs
  `Prometheus metrics server listening on 127.0.0.1:9091` once the endpoint
  is up.

## When something does not work

- **`systemctl is-active sipnab` does not say `active`.** Read `journalctl -u
  sipnab`.
  - `Failed to bind metrics server on 127.0.0.1:9090: Address already in
    use` means something else, here Prometheus, holds the port. systemd then
    keeps restarting sipnab.
  - Check the drop-in's `--metrics` port.
- **The `sipnab` target is `down`.** Check `curl 127.0.0.1:9091/metrics` on
  the machine. Then check the target in `/opt/monitoring/prometheus.yml`.
