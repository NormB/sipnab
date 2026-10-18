# Prometheus metrics

sipnab exposes Prometheus-compatible metrics. Either of two feature flags
enables them:

- the `api` feature flag, served on the REST API's port;
- the `metrics` feature, a standalone server on `--metrics`.

Both emit the same families.

This is a different surface from the [REST API](rest-api.md).

- The REST API returns what sipnab SAW: dialogs, streams, messages.
- These are numbers ABOUT sipnab: what it captured, what it lost, and what it
  could not read.

They also authenticate differently. See
[Authentication](rest-api.md#authentication).

It is also different from HEP, the Homer Encapsulation Protocol:

- HEP carries SIP messages. sipnab receives them with
  [`--hep-listen`](cli-reference.md#network-listeners) or forwards them with
  `--hep-send`, and Homer stores the signaling itself.
- Prometheus carries no SIP. A scrape says how many packets sipnab dropped,
  not which calls they belonged to.

A deployment can use both.

### Scrape the metrics of a capture file

With `--api`, sipnab keeps serving after it has read a file, until you stop
it. On a loopback address with no API key, `/metrics` needs no token. Start
it:

```bash
sipnab -N -I tests/pcap-samples/sip-sdp-example.pcap --api 127.0.0.1:19392 --no-cli-print
```

From a second terminal, read it:

```bash
curl -s http://127.0.0.1:19392/metrics
```

The scrape begins:

```text
# HELP sipnab_dialogs_total Total SIP dialogs by state
# TYPE sipnab_dialogs_total counter
sipnab_dialogs_total{state="completed"} 1

# HELP sipnab_messages_total SIP messages in tracked dialogs, labeled by the method that opened each dialog
# TYPE sipnab_messages_total counter
sipnab_messages_total{method="INVITE"} 7

# HELP sipnab_responses_total Total SIP responses by code class
# TYPE sipnab_responses_total counter
sipnab_responses_total{code="1xx"} 2
sipnab_responses_total{code="2xx"} 2
sipnab_responses_total{code="3xx"} 0
sipnab_responses_total{code="4xx"} 0
sipnab_responses_total{code="5xx"} 0
sipnab_responses_total{code="6xx"} 0
…
```

Stop sipnab with Ctrl-C when you have finished. The standalone `--metrics` server
exits with the run, so on a file run it is reachable only while sipnab reads
the file.


### GET /metrics

Prometheus-compatible metrics endpoint. It returns metrics in the Prometheus
text exposition format (`text/plain; version=0.0.4`).

The Python, Go and JavaScript examples are the core of the `metrics` programs in
[`clients/`](../clients/). CI compiles and runs those programs against a sipnab
replaying a committed capture. Those programs read:

- the base URL from `SIPNAB_URL`, default `http://127.0.0.1:8080`;
- the token from `SIPNAB_API_KEY`, default `my-secret-token`.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/metrics
```

**Python:**

<!-- snippet: clients/python/metrics.py#metrics -->
```python
req = Request(
    f"{BASE}/metrics",
    headers={"Authorization": f"Bearer {TOKEN}"},
)
with urlopen(req, timeout=10) as resp:
    print(resp.read().decode(), end="")  # Prometheus text format
```

**Go:**

<!-- snippet: clients/go/metrics/main.go#metrics -->
```go
req, err := http.NewRequest(http.MethodGet, baseURL+"/metrics", nil)
if err != nil {
	return err
}
req.Header.Set("Authorization", "Bearer "+token)
resp, err := http.DefaultClient.Do(req)
if err != nil {
	return err
}
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK {
	return fmt.Errorf("GET /metrics: %s", resp.Status)
}
body, err := io.ReadAll(resp.Body)
if err != nil {
	return err
}
fmt.Print(string(body)) // Prometheus text format
```

**JavaScript (Node.js):**

<!-- snippet: clients/javascript/metrics.mjs#metrics -->
```javascript
const resp = await fetch(`${base}/metrics`, {
  headers: { Authorization: `Bearer ${token}` },
});
if (!resp.ok) throw new Error(`GET /metrics: ${resp.status} ${resp.statusText}`);
process.stdout.write(await resp.text()); // Prometheus text format
```

**Response** (text/plain): the same text as the scrape above.

The metric families:

| Metric | Type | Notes |
|---|---|---|
| `sipnab_dialogs_total{state}` | counter | Tracked dialogs grouped by `DialogState` (`Trying`, `Ringing`, `InCall`, `Completed`, `Canceled`, `Failed`, `Redirected`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`). State values are lowercase: `state="completed"`. |
| `sipnab_dialogs_active` | gauge | Dialogs in one of six active states: `Trying`, `Ringing`, `InCall`, `Transferring`, `Pending`, `Active`. `Pending` and `Active` are SUBSCRIBE dialogs, which carry no media, so **this is not a count of calls**: a host serving presence traffic reports a non-zero value with no call up. For calls, use `sipnab_calls_active`. |
| `sipnab_calls_active` | gauge | Calls that are up right now: dialogs in `InCall`, and nothing else. A dialog enters `InCall` on the 200 OK to its INVITE and leaves on the BYE. Compare it against a carrier's simultaneous-call limit. Never greater than `sipnab_dialogs_active`; the difference is calls still in setup plus subscriptions. |
| `sipnab_messages_total{method}` | counter | SIP messages in the tracked dialogs, labeled by the method that opened each dialog. Every message of an INVITE dialog, its responses, `ACK` and `BYE` included, counts under `method="INVITE"`. |
| `sipnab_responses_total{code}` | counter | SIP responses in the tracked dialogs, grouped by class: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `6xx`. Every class appears on every scrape, at `0` where the capture saw none. |
| `sipnab_rtp_streams_active` | gauge | RTP streams a dialog claims, however long ago their last packet arrived: the same population as `sipnab_rtp_streams_total{status="established"}`. A call whose media stopped five minutes ago still counts until sipnab drops its dialog. |
| `sipnab_rtp_streams_total{status}` | counter | RTP streams by status: `orphaned` when no dialog claims the stream, `established` when one does. No age threshold applies: a stream unclaimed for two seconds counts as `orphaned`. |
| `sipnab_kill_responses_sent_total{mode}` | counter | Scanner-kill responses sent, by source mode: `raw` (source-spoofed via a raw socket) or `ephemeral` (sipnab's own port). Alert on unexpected `ephemeral` to catch a silent spoof fallback. |
| `sipnab_capture_packets_total` | counter | Packets the capture handed to the processing pipeline since the process started, counted before parsing. A frame sipnab cannot parse still counts, so read it with `sipnab_capture_undecoded_fraction`. One process-wide total covering every input (`-I` files, live devices, HEP) and every worker of the parallel pipeline. A line that stops climbing means packets stopped arriving. |
| `sipnab_reassembly_timeouts_total` | counter | IP fragments whose datagram never completed, plus TCP streams that went idle, dropped once older than the 30-second reassembly TTL. Entries evicted because the reassembly table was full are not counted here. |
| `sipnab_capture_kernel_dropped_packets_total` | counter | Packets the kernel discarded because the capture ring buffer was full when they arrived (`ps_drop`). Non-zero means the analysis is incomplete: dialogs may be missing messages, and RTP loss figures overstate what was on the wire. The remedy is a larger `-B`/`--buffer`, a narrower BPF filter, or a smaller `--snaplen`. Always zero for a `-I` file replay, which has no ring. |
| `sipnab_capture_interface_dropped_packets_total` | counter | Packets the interface or its driver discarded before libpcap saw them (`ps_ifdrop`). A larger `-B` does not recover these; look at the NIC, the driver, or the mirror. Alert on it separately from the kernel drops, because the remedies differ. |
| `sipnab_capture_invalid_timestamps_total` | counter | Packets whose pcap timestamp did not parse, which sipnab stamped with the wall clock instead. sipnab loses no packet, but every timing figure from the run reads a substituted clock: post-dial delay, [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html) jitter, MOS and call duration. |
| `sipnab_capture_undecodable_frames_total{reason}` | counter | Frames that reached the parser and produced no packet, grouped by reason. Labels are `unsupported_link_type_<dlt>`, `not_ip_ethertype_0x<hhhh>`, `no_transport_ip_protocol_<n>`, `truncated_frame`, `decode_error`, the `_unrecorded` variants of the EtherType and protocol labels (the decoder did not report the number), and `reason_not_retained` for frames past the tally's slot limit, so that `sum()` over the family equals the true total. `unsupported_link_type_0` is a `DLT_NULL` file, which `editcap -T ether` converts. Absent on a capture that decoded cleanly, so alert on `sipnab_capture_undecoded_fraction` instead. Both servers emit it. |
| `sipnab_capture_snapped_frames_total` | counter | Frames the capture's own `--snaplen` cut short (`caplen < origlen`). The frames arrived and most decoded; what is missing is payload. Raise `--snaplen` if you need RTP payload, audio export, or a faithful `-O` re-emit. |
| `sipnab_nat_unanswered_requests` | gauge | STUN and TURN transactions that went out and never drew a reply. A refusal counts as answered. An endpoint that cannot learn its reflexive address advertises its private address in SDP, and the call then has one-way or no audio while signaling looks healthy. A common cause is a security appliance (web filter, secure web gateway, firewall or IPS) dropping UDP it does not recognize. A gauge: a late answer lowers it. |
| `sipnab_nat_lapsed_turn_allocations` | gauge | TURN allocations still carrying traffic past the lifetime the server last granted, with no Refresh seen in between. A relay tears an allocation down when its lifetime lapses, and the relayed media stops mid-call with no SIP message to explain it. A capture that started late or lost a packet can miss a Refresh the client sent. A deliberate release (a Refresh with `LIFETIME` 0) is never counted. A gauge: a Refresh seen later lowers it. |
| `sipnab_nat_lapsed_turn_allocation_streams` | gauge | Media streams observed crossing a TURN allocation that had already lapsed: the number of calls a lapse affected. Counted by distinct SSRC inside the ChannelData frames on the allocation's channels, so RTCP does not inflate it. A gauge: a Refresh seen later lowers it. |
| `sipnab_nat_ice_role_conflicts` | gauge | Candidate pairs where both ICE agents claimed the same role, or where one answered `487 Role Conflict` ([RFC 8445 section 7.3.1.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.1)). ICE usually resolves a conflict itself, at the cost of repeated checks; a steady rate points at two endpoints configured with the same role, or a B2BUA relaying one side's role attribute to the other. Where no pair between the two was ever nominated, the conflict is a candidate cause of media that never started. A gauge: a later nomination on the same pair lowers it. |
| `sipnab_capture_undecoded_fraction` | gauge | Share of captured frames sipnab could not decode, `0` to `1`, on every scrape. It separates "this capture holds no SIP" from "sipnab could not read this capture", which otherwise both show `sipnab_messages_total` at zero. At `1`, nothing else in the scrape describes traffic sipnab read. A small non-zero value is normal on Ethernet, where ARP and other non-IP traffic is undecodable. |
| `sipnab_capture_quality_degraded` | gauge | `1` when any of the three loss counters (kernel drops, interface drops, invalid timestamps) is above zero, `0` otherwise. Undecodable frames are not included; use `sipnab_capture_undecoded_fraction` with a threshold for those. `0` means nothing surfaced as wrong. Loss upstream of the capture point, such as an oversubscribed SPAN port, a tap mirroring one direction, or a filter that excluded the traffic, does not appear in any of the three counters. |
| `sipnab_capture_queue_depth_packets` | gauge | Packets currently queued between the capture reader and the processing thread. |
| `sipnab_capture_backpressure_blocks_total` | counter | Times the capture reader blocked on a full queue. |
| `sipnab_capture_sources` | gauge | Capture sources held in the source table: input files, the device, HEP senders, traced processes. Both servers fill it. |
| `sipnab_capture_sources_max` | gauge | The source table's limit, `[limits] max_capture_sources` / `--max-capture-sources`. |
| `sipnab_capture_sources_refused_total` | counter | Packets whose new capture source the full table refused. They are still analyzed, but carry no `frame` pointer for `--show-frame`. Nonzero means raise `max_capture_sources`. |
| `sipnab_hep_senders` | gauge | Senders the `--hep-listen` listener is tracking, each keyed by the capture id it claims and the address it sent from. Present only on a run with a HEP listener. A total only, with no series per sender: to see which sender stopped, use [`GET /v1/hep/senders`](rest-api.md#get-v1hepsenders) (full scope), the MCP `hep_senders` tool, or `--hep-senders`. Both servers fill it. |
| `sipnab_hep_datagrams_received_total` | counter | HEP packets the listener received, admitted or refused. With the refused family below, `received - sum(refused)` is what reached the capture. |
| `sipnab_hep_datagrams_refused_total{reason}` | counter | HEP packets the listener refused, by reason: `allowlist`, `rate_limit_global`, `rate_limit_per_peer`, `peer_tracking_full`, `malformed`, `auth_missing`, `auth_mismatch`, and the five `hmac_*` reasons (`hmac_bad_format`, `hmac_unsupported_version`, `hmac_timestamp_out_of_window`, `hmac_bad_mac`, `hmac_replay`). Every reason appears on every scrape of a run with a listener, at `0` where the listener refused none. A climbing `auth_mismatch` or `hmac_bad_mac` is a sender with the wrong key; `hmac_timestamp_out_of_window` is a sender with a drifting clock. Both servers fill it. |
| `sipnab_hep_export_packets_total` | counter | Packets the `--hep-send` exporter delivered as far as its transport can tell. Over TCP and TLS, the exporter wrote it to the connection. **Over UDP, the exporter handed it to the kernel**, and the series climbs whether or not a collector is listening; check the collector's own `sipnab_hep_senders` or its roster for delivery. Present only on a run that exports. |
| `sipnab_hep_export_failures_total{kind}` | counter | Delivery **attempts** that failed, by the step that failed: `connect` (the collector refused, or the sender could not reach it within `--hep-send-timeout`), `tls_handshake` (it connected and the certificate was not one the sender accepts, or the session broke), `write` (an established connection or the socket refused the packet, or the collector closed the connection). A failed attempt loses nothing: the packet stays queued and the sender retries with backoff, so read losses off `sipnab_hep_export_dropped_total`. Every kind appears, at `0` where nothing failed. A climbing `tls_handshake` after a collector rebuild is a certificate the sender does not trust. Present only on a run that exports. |
| `sipnab_hep_export_queued_total` | counter | Packets the capture handed to the exporter's queue. Every one ends up sent, dropped, or still queued: `queued = packets + dropped + queue_depth`. Present only on a run that exports. |
| `sipnab_hep_export_replayed_total` | counter | Packets delivered after waiting out a collector outage in the queue, in capture order. Present only on a run that exports. |
| `sipnab_hep_export_reconnects_total` | counter | Times the collector became reachable again after an outage, a collector down at startup included. Present only on a run that exports. |
| `sipnab_hep_export_dropped_total{reason}` | counter | Packets discarded undelivered, by why: `queue_full` (the queue was at `--hep-send-queue` while the collector was unreachable, and this was the oldest packet in it), `stopped` (still queued when a signal stopped the run; sipnab flushes nothing at a stop), `unsent_at_exit` (the input ended and the collector stayed unreachable for the grace period). Every reason appears, at `0` where sipnab dropped nothing, so an alert on `queue_full` reads zero rather than no-data. Present only on a run that exports. |
| `sipnab_hep_export_queue_depth` | gauge | Packets queued for the collector now, neither sent nor dropped. Near zero while the collector keeps up; it climbs through an outage and falls as the queue replays. Present only on a run that exports. |
| `sipnab_diagnosis_total{type}` | counter | Tracked dialogs whose media diagnosis raises each finding. A dialog with two findings counts under both. Three groups of labels: `one_way_audio`, `nat_mismatch` and `no_media` appear on every scrape, at `0` where nothing raises them. `private_media_address` (the SDP `c=` line offered an address the far end cannot route back to) and `private_media_address_confirmed` (the subset where STUN evidence shows nothing rewrote that address) appear once a dialog raises them. `dead_air` and `clipping` measure the decoded audio, so they appear only on a run started with `--retain-audio`; their absence means the run kept no samples, not that the calls were fine. Both servers run the diagnosis during the scrape, so scrape cost grows with the number of tracked dialogs (capped by `-l`/`--limit`). |
| `sipnab_security_alerts_total{type}` | counter | Security alerts by the detector that fired: `scanner`, `fraud`, `digest`, `reg_flood`. Only types that have fired appear, so the family is absent before the first alert. At most 128 distinct names; any beyond that count under `type="other"`, so the total stays right. |
| `sipnab_mcp_tool_calls_total{tool,outcome}` | counter | MCP tool calls, by the tool asked for and how the call ended: `ok`, `tool_error` (the tool answered with an error), or `refused` (the rate limit, the concurrency limit, a scope check, unknown arguments, or a name no tool answers to). A name no tool answers to still counts. At most 256 distinct tool names; any beyond that count under `tool="other"`. Absent until the first tool call. It always agrees with the `mcp_audit` log lines. |
| `sipnab_mcp_tool_duration_seconds{tool}` | histogram | How long each MCP tool takes to answer, in seconds, measured from the same instant as the audit line's `elapsed_ms`. Fixed boundaries at 1/5/10/25/50/100/250/500ms and 1/2.5/5/10s. Emits `_bucket{tool,le}`, `_count{tool}`, `_sum{tool}`. |
| `sipnab_mcp_tool_response_bytes_total{tool}` | counter | Text content bytes each MCP tool has returned: the payload an agent reads, without the JSON-RPC envelope and its escaping. Divide by `sipnab_mcp_tool_duration_seconds_count{tool}` for the average answer size, and see `--mcp-max-rows` and `--mcp-max-body-bytes` to bound it. A refused call returns no content and does not move this counter. |
| `sipnab_pdd_seconds` | histogram | Post-dial delay distribution. Boundaries at 0.5/1/2/3/5s, then `[diagnosis] post_dial_delay_secs` and twice it (11s and 22s at the default), so a query reproduces the finding sipnab raises. Emits `sipnab_pdd_seconds_bucket{le}`, `_count`, `_sum`. |
| `sipnab_mos` | histogram | RTP MOS distribution. Half-steps up the 1-5 scale, plus `[quality] mos_warn` and `mos_bad` (4 and 3 at the shipped settings). |
| `sipnab_jitter_ms` | histogram | RTP jitter distribution. A ladder at 5/10/20ms, plus `[quality] jitter_warn_ms` and `jitter_bad_ms` and multiples above them (30/50/100/200ms at the shipped settings). |
| `sipnab_loss_percent` | histogram | RTP packet-loss distribution. A ladder at 0.1/0.5%, plus `[quality] loss_warn_pct` and `loss_bad_pct` and multiples above them (1/2/5/10/20% at the shipped settings). |

Two shapes of counter share that table. An alert rule has to know which one it
reads.

These count events since the process started and only ever climb:

- `sipnab_capture_packets_total`
- `sipnab_reassembly_timeouts_total`
- `sipnab_kill_responses_sent_total`
- `sipnab_capture_backpressure_blocks_total`
- `sipnab_capture_sources_refused_total`
- `sipnab_capture_undecodable_frames_total`
- `sipnab_capture_snapped_frames_total`
- the two MCP counters:
  - `sipnab_mcp_tool_calls_total`
  - `sipnab_mcp_tool_response_bytes_total`
- the three capture-quality counters:
  - `sipnab_capture_kernel_dropped_packets_total`
  - `sipnab_capture_interface_dropped_packets_total`
  - `sipnab_capture_invalid_timestamps_total`

So `rate()` and `increase()` over them mean what they say.

The rest describe what sipnab tracks right now: dialogs, messages, responses,
streams, diagnosis findings, and the four NAT gauges. Every one of them falls
as well as rises:

- dialogs and streams age out of their stores,
- a late STUN answer clears an unanswered request,
- a TURN Refresh unsays a lapsed allocation.

Alert on the current value or on a ratio there, never on `increase()`.

`sipnab_security_alerts_total{type}` carries only the types that have fired,
and is absent from the scrape until the first alert. An absent series means
no alert of that type has fired since the process started.


### Choose a scrape target

sipnab serves the same metrics on two ports. Scrape whichever one the run
already has:

- `/metrics` on the REST API's port, when the run has `--api`. It takes the
  API's bearer token.
- The standalone metrics server, when the run has `--metrics`. It takes
  `--metrics-auth-file` credentials, and can serve HTTPS (see
  [Metrics TLS](#metrics-tls)).

Both publish the same series with the same values, so a rule or dashboard
built against one works against the other. Every series in the table above is
on both.

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

A scrape interval of 5 to 15 seconds suits the endpoint. Scrape cost grows
with the number of tracked dialogs (see `sipnab_diagnosis_total`).

## Metrics TLS

Give sipnab a certificate and its private key. Then the standalone metrics
server (`--metrics`) serves HTTPS instead of plain HTTP on its port:

```bash
sudo sipnab -N -d eth0 --metrics 0.0.0.0:9090 \
  --metrics-auth-file /etc/sipnab/metrics.auth \
  --metrics-tls-cert /etc/sipnab/metrics.pem --metrics-tls-key /etc/sipnab/metrics.key
```

Check it with curl, trusting the CA that issued the certificate. The
credential file holds `user:pass`. That is what `curl -u` takes:

```bash
curl --cacert /etc/sipnab/ca.pem -u "$(cat /etc/sipnab/metrics.auth)" https://capture01.example.net:9090/metrics
```

- `--metrics-tls-cert` is a PEM certificate chain, the server's own
  certificate first.
- `--metrics-tls-key` is its PEM private key
  (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`).
- The port speaks HTTPS only. A plain-HTTP request to it fails the TLS
  handshake and is not served.
- TLS 1.2 and TLS 1.3 only.
- No client certificates.
  - Scrapers authenticate with `--metrics-auth` or `--metrics-auth-file`, as
    over plain HTTP.
  - The credential now crosses the network encrypted.
- `[metrics] tls_cert` and `[metrics] tls_key` in
  [`sipnab.toml`](config-reference.md#metrics) set the same files. Each flag
  replaces its own key.

sipnab checks both files at startup. It refuses to start, naming the file, in
each of these cases:

- you give only one of the pair;
- it cannot read either file;
- the certificate file holds no certificate, or the key file no private key;
- any other user on the host can read the key file. `chmod 600` it.
  Group-readable stays allowed.
- the key does not belong to the certificate.

A non-loopback bind still needs `--metrics-auth` or `--metrics-auth-file`.
Without TLS, sipnab also warns that the credential crosses the network
unencrypted. With TLS, it does not.

Each read and each write on a scrape connection times out after 5 seconds, as
on plain HTTP. That includes the TLS handshake's. The `--metrics-max-conn`
limit counts HTTPS connections the same way. sipnab closes a connection over
that limit without a reply, because a plain-text `503` would be unreadable
inside TLS.

sipnab reads the certificate once, at startup. To pick up a renewed
certificate, restart sipnab.

The Prometheus job for an HTTPS endpoint names the scheme, the CA, and the
Basic credential:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sipnab
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/sipnab-ca.pem
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/sipnab-metrics.password
    static_configs:
      - targets: ['capture01.example.net:9090']
```

The certificate must name the host Prometheus connects to, here
`capture01.example.net`, in its subject alternative names.

A sample Grafana dashboard JSON ships in the repo at [`contrib/grafana/sipnab-dashboard.json`](https://github.com/NormB/sipnab/blob/main/contrib/grafana/sipnab-dashboard.json).
