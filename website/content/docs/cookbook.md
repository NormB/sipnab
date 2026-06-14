+++
title = "Cookbook"
weight = 10
description = "Step-by-step recipes for every major sipnab feature: triage, filtering, HEP, TLS decryption, MCP, observability, security, audio export."
+++

Recipe-style walkthroughs for the things people actually want to do. Each recipe states the problem, gives exact commands, tells you what to look for in the output, and flags common pitfalls.

If you're new, start with **Recipe 1**. If you have a specific symptom, jump to the matching one.

## 1. Triage a pcap fast

**Problem:** Someone handed you a `capture.pcap` and asked "is anything wrong?"

**Commands:**

```bash
# 1. Interactive: open the call list, scan visually
sipnab -I capture.pcap

# 2. Headless overview: dialog count, methods, average PDD
sipnab -N -I capture.pcap

# 3. One-flag diagnostic sweep — surfaces every likely-bad call
sipnab -N -I capture.pcap --problems

# 4. Same in JSON for piping
sipnab -N -I capture.pcap --problems --json
```

**What to look for:**

- `--problems` matches `state == 'Failed' OR one_way == true OR rtp.loss > 2.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 32.0 OR rtp.orphaned == true OR codec_asymmetry == true OR ptime_asymmetry == true OR payload_asymmetry == true OR duration_asymmetry == true OR late_media == true`. If it's empty, the capture is probably clean.
- The end-of-capture summary distinguishes RTP packets from RTP streams: `852 packets captured, 10 SIP messages, 839 RTP packets across 2 streams`. A capture with media but no SIP usually means the SIP signaling happened off-pcap (different VLAN, different host, different port).

**Pitfalls:**

- The TUI requires a tty. If you're SSH'd in without `-t`, force `-N` mode.
- For large pcaps (>1 GB), prefer `-N` first; the TUI loads everything into memory.

---

## 2. Live capture, narrow to a single user

**Problem:** A user reports their calls are flaky. Capture only their traffic in real time.

**Commands:**

```bash
# Capture on eth0, only this user's calls (matches From or To)
sudo sipnab -d eth0 --filter "from.user == '1001' OR to.user == '1001'"

# Same, with a CLI summary line per dialog (not the TUI)
sudo sipnab -N -d eth0 --filter "from.user == '1001' OR to.user == '1001'" --json
```

**What to look for:**

- The TUI's call list updates as new dialogs appear. Press `Tab` to switch to the RTP stream view; press `Enter` on a stream to see jitter/loss/MOS history.
- In CLI mode, each completed dialog is one line of JSON. Pipe to `jq` or `tee` to a log.

**Pitfalls:**

- Live capture needs `CAP_NET_RAW` (Linux) or root. `setcap cap_net_raw,cap_net_admin=eip $(which sipnab)` lets you skip `sudo` after the first run.
- The filter DSL evaluates against complete dialog records — once the dialog state machine has enough information (typically after the first response, or earlier for fields that only depend on the request). For per-header regex filtering on individual messages, use the older `--from`, `--to`, `--contact`, `--ua` flags listed in `sipnab --help`.

---

## 3. Find every failed call, grouped by response code

**Problem:** "We had a spike in failures around 14:00. What was it?"

**Commands:**

`sipnab -N --json` emits per-message records (one JSON line per SIP message), not per-dialog summaries. The `status_code` field is on response messages; combined with `--filter` (which evaluates against the dialog so all messages from matched dialogs flow through), you get a histogram of every response code seen during failed dialogs:

```bash
# Every failed call's response messages (Call-ID + status_code + reason)
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq 'select(.is_request == false) | {call_id, status_code, reason}'

# Histogram of response codes seen in failed dialogs
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r 'select(.is_request == false) | .status_code' \
  | sort | uniq -c | sort -rn

# Detailed report for one failure (Markdown, paste into a ticket)
sipnab -I capture.pcap --call-report 'abc123@host' --markdown > failure-report.md
```

**What to look for:**

- A 401/407 spike usually means a credential-rotation push hit the wrong realm.
- A 408 spike on outbound is upstream timeout — check rtpengine / SBC.
- A 488 spike (Not Acceptable Here) usually means a codec mismatch — combine with Recipe 11.

**Pitfalls:**

- The histogram counts *all* response codes seen in messages of failed dialogs (so a single failed call with `100 Trying → 488` contributes both 100 and 488). For just the final response per call, use `--call-report <id>` per dialog.
- The dialog summary returned by the REST API (`/v1/dialogs`) has no `status_code` field; that's a per-message field only available in CLI `--json` output or via `/v1/dialogs/{id}` (which includes the full message list).

---

## 4. Diagnose a one-way audio complaint

**Problem:** A user said "I can hear them but they can't hear me." There's a Call-ID in the ticket.

**Commands:**

```bash
# 1. Confirm the diagnosis engine flagged it
sipnab -N -I capture.pcap --filter "call_id == 'abc123@host'" --json \
  | jq '{call_id, state, diagnosis: .diagnosis}'

# 2. Get the call report — surfaces NAT mismatch, SDP offer/answer, media path
sipnab -I capture.pcap --call-report 'abc123@host' --markdown

# 3. Inspect the actual RTP streams for that call (TUI)
sipnab -I capture.pcap
#   → press '/' to filter, type 'abc123', Enter
#   → Tab to switch to RTP streams view
#   → Enter on each stream to see packet count, jitter, loss
```

**What to look for:**

- `diagnosis.one_way_audio: true` confirms the engine saw RTP in only one direction for ≥6s after call establishment.
- `diagnosis.nat_mismatch: true` is the usual root cause — the Contact header / Via address differs from the SDP `c=` line. Common when the upstream SBC isn't rewriting Contact.
- In the TUI's RTP stream view, look for one stream with packets and one with `0 packets received` — that's the silenced direction.

**Pitfalls:**

- If both streams show packets but the user still reports silence, the issue is downstream of sipnab (codec mismatch, jitter buffer underflow, bad headset). Use Recipe 11 for codec asymmetry checks.

---

## 5. Five Filter-DSL queries that pay rent

The filter DSL has 30 fields and 7 operators. These five cover most operational triage:

```bash
# A. Slow setup — anything over 3 seconds INVITE→200 OK
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json

# B. REGISTER failures
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND state == 'Failed'" --json

# C. Short calls — under 10s, completed (likely UX or cancellation problem)
sipnab -N -I capture.pcap --filter "duration < 10.0 AND state == 'Completed'" --json

# D. Heavy retransmits — packet loss on the SIP path
sipnab -N -I capture.pcap --filter "retransmits > 5" --json

# E. Specific User-Agent (regex)
sipnab -N -I capture.pcap --filter "ua =~ '(?i)friendly.*scanner|sipvicious'" --json
```

For per-call asymmetry checks (different codec on each leg, late media, etc.), see Recipe 11.

**Pitfalls:**

- String comparisons are case-sensitive. State names must match exactly (`'Completed'`, not `'completed'`). Use `=~ '(?i)...'` if you want case-insensitive.
- Boolean fields only support `==` and `!=` — `one_way > true` is a parse error.

---

## 6. Wire HEP from your SIP stack to a central sipnab

**Problem:** You want one sipnab box collecting traffic mirrors from multiple SIP servers.

### 6a. Set up the listener

```bash
# Build sipnab with HEP support
cargo build --release --no-default-features \
    --features native,hep,api,mcp,mcp-http

# Run as a daemon. UDP :9060 receives HEP, TCP :9100 serves REST + Prometheus
sipnab -N --hep-listen 0.0.0.0:9060 --api 0.0.0.0:9100 --no-priv-drop --syslog
```

A ready-to-deploy systemd unit lives at `contrib/observability/sipnab-hep.service` — see [Remote-sipnab deployment](/docs/install/) in the install guide.

### 6b. Configure the SIP server to mirror

**OpenSIPS:**

```cfg
loadmodule "proto_hep.so"
modparam("proto_hep", "hep_id", "[hep_central]udp:capture.example.com:9060;version=3")

loadmodule "siptrace.so"
modparam("siptrace", "trace_id", "[hep_central]uri=hep:hep_central")

route {
    sip_trace("hep_central", "d", "sip");
    ...
}
```

Reload with `opensipsctl restart` (or `systemctl reload opensips` for graceful reload).

**rtpengine:**

```ini
# /etc/rtpengine/rtpengine.conf
homer = capture.example.com:9060
homer-protocol = udp
homer-id = 1
```

Restart with `systemctl restart rtpengine`.

**Kamailio:**

```cfg
loadmodule "siptrace.so"
modparam("siptrace", "duplicate_uri", "sip:capture.example.com:9060")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "hep_version", 3)

route {
    sip_trace();
    ...
}
```

**FreeSWITCH (mod_sofia):**

```xml
<!-- conf/sip_profiles/external.xml -->
<param name="capture-server" value="udp:capture.example.com:9060;hep=3"/>
<param name="sip-capture" value="yes"/>
```

### 6c. Verify packets are arriving

```bash
# On the sipnab host, tcpdump the HEP socket
sudo tcpdump -i eth0 -n udp port 9060

# Confirm dialogs are being created from the HEP feed
curl -s http://localhost:9100/v1/stats | jq

# Watch dialogs accumulate live
watch -n 1 'curl -s http://localhost:9100/v1/dialogs?limit=5 | jq ".dialogs[] | {call_id, state}"'
```

**Pitfalls:**

- HEP is UDP — silently drops if the listener can't keep up. The `--hep-rate-limit 50000` default lets you tune.
- The default HEP listener accepts from any source. Add `--hep-allow 10.0.0.0/24` (repeatable) to lock it down to your SIP-server subnet.
- If your central host is reachable by hostname only, set `--mcp-allowed-host` for the MCP transport too (see Recipe 8).

---

## 7. Decrypt SIP/TLS via SSLKEYLOGFILE

**Problem:** TLS-encrypted SIP captures are unreadable without keys.

### 7a. Live decryption (UA produces keys, sipnab follows)

```bash
# 0. Build sipnab with the tls feature (or use --features full)
cargo build --release --features tls,hep,api

# 1. On the SIP user agent, set SSLKEYLOGFILE in its environment
SSLKEYLOGFILE=/tmp/sipua.keylog /opt/myua/bin/start

# 2. Start sipnab watching the keylog file (live updates)
sudo sipnab -N -d eth0 \
            --keylog /tmp/sipua.keylog --keylog-watch
```

### 7b. Offline decryption (capture once, decrypt later)

```bash
# Capture the encrypted pcap normally
sudo sipnab -N -d eth0 -O encrypted.pcap

# Later, decrypt using the keylog the UA wrote during the call
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog
```

### 7c. Export decrypted pcap for Wireshark

```bash
# Default mode: write decrypted plaintext payloads to the output pcap
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog \
       -O decrypted.pcap --pcap-export-mode decrypted

# encrypted+dsb mode: keep encrypted bytes + add a Decryption Secrets
# Block so Wireshark itself can decrypt
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog \
       -O wireshark-friendly.pcap --pcap-export-mode encrypted+dsb
```

Accepted values for `--pcap-export-mode`: `decrypted` (default), `encrypted+dsb`, `raw`.

### 7d. SRTP via DTLS-SRTP keylog

```bash
sipnab -I capture.pcap --dtls-keylog /tmp/dtls.keylog
```

**Pitfalls:**

- `tls` is a **build-time** feature, not a runtime flag. There is no `sipnab --features tls` invocation; pass `--features` to `cargo build` and use the resulting binary. `sipnab --version` only prints the version string and a commit hash — it does *not* enumerate compiled-in features. To verify support, `sipnab --help | grep -E '\-\-keylog|\-\-tls-key'` — if the flags appear, `tls` was compiled in.
- The keylog format is the standard NSS `SSLKEYLOGFILE` (one line per session). Same format Firefox/Chrome/curl produce.
- TLS 1.3 + ECDH ephemeral handshakes are fully supported via the `ring` backend.

---

## 8. Run sipnab as an MCP server

**Problem:** You want an AI agent (Claude Code, Claude Desktop, anything MCP-capable) to query a capture without you typing CLI flags.

### 8a. Stdio (local agent)

```bash
# One-shot, agent reads a pcap
sipnab --mcp -I capture.pcap --quiet

# Live capture
sudo sipnab --mcp -d eth0 --quiet
```

**Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-I", "/path/to/capture.pcap", "--quiet"]
    }
  }
}
```

**Claude Code** (in your project directory):

```bash
claude mcp add sipnab -- sipnab --mcp -I "$PWD/capture.pcap" --quiet
```

### 8b. HTTP (remote agent, single user)

```bash
# Generate a token
mkdir -p /etc/sipnab && chmod 0755 /etc/sipnab
openssl rand -hex 32 > /etc/sipnab/mcp-token
chmod 0600 /etc/sipnab/mcp-token

# Run sipnab listening on a private network interface
sipnab --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp-token \
       --mcp-allowed-host capture.example.com \
       --hep-listen 0.0.0.0:9060 --quiet
```

The agent connects to `http://capture.example.com:8731/mcp` with `Authorization: Bearer <token>`.

### 8c. Test the JSON-RPC handshake from a shell

```bash
TOKEN=$(cat /etc/sipnab/mcp-token)

# Initialize (pretend to be an MCP client)
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2025-06-18",
                    "capabilities":{},
                    "clientInfo":{"name":"curl","version":"0"}}}'

# List the 11 read-only tools
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# Call find_problems and get JSON of problematic dialogs
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
          "params":{"name":"find_problems",
                    "arguments":{"kinds":["one-way","nat-issues"]}}}'
```

**Pitfalls:**

- Stdout is the JSON-RPC wire in stdio mode. Use `--quiet` and don't combine with `--json`/`--report`/etc. — sipnab refuses to start.
- Non-loopback bind without a token: refused at startup. Loopback bind needs no token.
- `--mcp-allowed-host` is required when the client connects via the actual hostname (rmcp's default Host allowlist is just `localhost`/`127.0.0.1`/`::1`).

---

## 9. Prometheus + Grafana end-to-end

**Problem:** You want a dashboard tracking call rate, response codes, and PDD over time.

### 9a. Use the bundled stack

```bash
git clone https://github.com/NormB/sipnab.git
cd sipnab/contrib/observability
cp .env.example .env

# If sipnab runs on a different host, point at it:
# echo 'SIPNAB_HOST=192.0.2.10' >> .env       # or capture.example.com

docker compose up -d
```

This boots Prometheus (`:9090`), Grafana (`:3000`, admin/admin), an OTel Collector (`:4317`/`:4318`), and Tempo. The included Grafana dashboard provisions automatically — log in and look for the `sipnab` folder.

### 9b. Run sipnab so Prometheus can scrape it

```bash
# Standalone metrics endpoint
sipnab -N -d eth0 --metrics 0.0.0.0:9100 --json

# Or as part of the REST API (single port for both)
sipnab -N -d eth0 --api 0.0.0.0:9100
```

### 9c. Verify the scrape

```bash
# From the Prometheus host
curl -s http://localhost:9090/api/v1/query?query=up{job=\"sipnab\"} | jq

# Spot-check a metric value
curl -s 'http://localhost:9090/api/v1/query?query=rate(sipnab_messages_total[1m])' | jq
```

### 9d. Useful PromQL queries

```promql
# Call rate (per method)
rate(sipnab_messages_total[5m])

# Active dialogs (in-progress)
sum(sipnab_dialogs_total{state=~"trying|ringing|incall"})

# Setup time p95
histogram_quantile(0.95, rate(sipnab_pdd_seconds_bucket[5m]))

# RTP MOS p10 (worst 10%)
histogram_quantile(0.1, rate(sipnab_mos_bucket[5m]))
```

**Pitfalls:**

- The dashboard ships with the metric names sipnab actually emits. If you wrote a custom panel using older docs, double-check against [the metrics list in the API page](@/docs/api.md).
- Some metrics (`sipnab_responses_total`, `sipnab_security_alerts_total`) are declared but not yet wired — they'll stay empty until upstream populates them. Don't put alerts on them today.

---

## 10. Detect SIP scanners and auto-block via fail2ban

**Problem:** Your honeypot or edge box is getting probed by `friendly-scanner`, `sipvicious`, etc.

### 10a. Detect + log

```bash
sudo sipnab -N -d eth0 \
            --kill-scanner \
            --alert syslog \
            --json
```

`--kill-scanner` actively responds 403 to known scanner User-Agents (uses the isolated kill-child process). `--alert syslog` writes alerts to `LOCAL0` so you can pick them up from `/var/log/syslog`.

### 10b. Wire to fail2ban

`--fail2ban` is a boolean flag — it switches sipnab's stdout to fail2ban-friendly log lines. Pipe to a file (or run under systemd and capture the unit's stdout).

```bash
# Run sipnab with fail2ban-format output, write to a logfile
sudo sipnab -N -d eth0 --kill-scanner --fail2ban \
     >> /var/log/sipnab/fail2ban.log 2>&1
```

Sample log line shape (from `src/output/fail2ban.rs`):

```
2026-05-05 12:34:56 sipnab[12345]: scanner_detected src=203.0.113.42 ua=friendly-scanner method=OPTIONS
2026-05-05 12:34:57 sipnab[12345]: reg_flood src=203.0.113.42 count=37
```

`/etc/fail2ban/filter.d/sipnab.conf`:

```ini
[Definition]
failregex = ^.*sipnab\[\d+\]: scanner_detected src=<HOST>.*$
            ^.*sipnab\[\d+\]: reg_flood src=<HOST>.*$
ignoreregex =
```

`/etc/fail2ban/jail.d/sipnab.local`:

```ini
[sipnab]
enabled = true
filter = sipnab
logpath = /var/log/sipnab/fail2ban.log
findtime = 600
maxretry = 1
bantime = 86400
action = iptables-allports
```

### 10c. Custom alert handler

For exec hooks instead of syslog/fail2ban:

```bash
sudo sipnab -N -d eth0 --kill-scanner \
            --alert-exec '/usr/local/bin/notify-slack.sh "%type%" "%source_ip%" "%detail%"'
```

The hook is rate-limited (`--exec-rate-limit 10` default) and runs in a sandboxed process.

**Pitfalls:**

- The kill-child process needs `CAP_NET_RAW` to forge SIP responses. Run sipnab as root or with capabilities — privilege drop happens after the kill-child is spawned.
- `--kill-ua "<regex>"` adds a custom User-Agent pattern beyond the built-in scanner list.

---

## 11. Per-call asymmetry diagnosis

**Problem:** A call sounds bad in one direction. The codec/ptime might differ between legs.

The asymmetry signals (Phase 8.7) live on sipnab's internal `MediaDiagnosis` struct and are exposed through the filter DSL — not the dialog JSON output's `diagnosis` block. `--filter` accepts the alias name directly (`codec-asym`) and falls back to the raw DSL expression if it isn't an alias. Both forms are equivalent.

```bash
# All five asymmetry checks at once via the 'problems' alias (CLI flag)
sipnab -N -I capture.pcap --problems --json

# Targeted, one signal at a time — alias name or raw DSL, both work
sipnab -N -I capture.pcap --filter codec-asym    --json
sipnab -N -I capture.pcap --filter ptime-asym    --json
sipnab -N -I capture.pcap --filter payload-asym  --json
sipnab -N -I capture.pcap --filter duration-asym --json
sipnab -N -I capture.pcap --filter late-media    --json

# Equivalent raw-DSL forms
sipnab -N -I capture.pcap --filter "codec_asymmetry == true"  --json
sipnab -N -I capture.pcap --filter "ptime_asymmetry == true"  --json

# Multiple signals OR'd require raw DSL (alias names cover only one signal each)
sipnab -N -I capture.pcap \
       --filter "codec_asymmetry == true OR ptime_asymmetry == true OR late_media == true" \
       --json

# From an MCP client, multiple alias names go through find_problems:
#   tools/call find_problems {"kinds": ["codec-asym", "ptime-asym", "late-media"]}
# See the MCP docs for the full client-side syntax.
```

**What to look for:**

- `codec_asymmetry: true` on a call from PSTN to internal: usually a transcoding policy that fired in one direction only.
- `ptime_asymmetry: true` between two SIP UAs: one is using `ptime=20`, the other `ptime=30`. Some downstream jitter buffers can't handle the mismatch.
- `payload_asymmetry: true`: same codec, but each side picked a different dynamic payload type number. Causes audio cut-out on RFC-strict implementations.
- `late_media: true`: media starts noticeably after the answering 200 OK. Usually means an SBC is doing late-attach NAT — first real RTP arrives only after media-binding.

**Pitfalls:**

- `sipnab -N --filter '<expr>' --json` emits **per-message** records for every message of every matching dialog. Pipe through `jq -s 'unique_by(.call_id)'` if you want one record per affected call.
- The `diagnosis` block in CLI `--json` output and in the REST API today only exposes `one_way_audio`, `nat_mismatch`, `no_media`, and free-form `hints`. The five asymmetry booleans are filterable via the DSL but aren't in the JSON shape — if you need them in your output, generate a `--call-report` per dialog (which does include them) or use the MCP `find_problems` tool.

---

## 12. Generate a call report (text / Markdown / JSON)

**Problem:** A support ticket needs full call details attached.

In `-N` (non-interactive) mode, sipnab normally prints each captured SIP message to stdout and then emits the report. Pass `--no-cli-print` to suppress the per-message dump so only the report reaches stdout. (`-N` is required: without it sipnab tries to start the TUI and the report output never reaches stdout.)

```bash
# Markdown — paste into a ticket or markdown editor
sipnab -N -I capture.pcap --call-report 'abc123@host' --markdown --no-cli-print > ticket.md

# Plain text (default report format)
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print > ticket.txt

# JSON
sipnab -N -I capture.pcap --call-report 'abc123@host' --json --no-cli-print > ticket.json
```

The report covers: SIP message timeline, SDP offers/answers, RTP stream stats per direction, computed timing (PDD, setup time, retransmits), and the diagnosis engine's findings.

**Tip:** combine with Recipe 3's filter to bulk-generate reports for every failed call. The CLI `--filter` outputs per-message records, so deduplicate to call_ids first:

```bash
mkdir -p /tmp/reports
# First pass: enumerate matching calls (no --no-cli-print here — we want the
# per-message JSON so jq can extract call_id).
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json 2>/dev/null \
  | jq -r '.call_id' | sort -u \
  | while read cid; do
      # Second pass per call: --no-cli-print so only the report is written.
      sipnab -N -I capture.pcap --call-report "$cid" --markdown --no-cli-print \
        > "/tmp/reports/$(echo "$cid" | tr '/' '_').md"
    done
```

> **Compatibility note:** `--no-cli-print` was added in v0.3.2. On older binaries strip the leading per-message text by piping through `sed -n '/^# Call Report:/,$p'` (markdown) or `awk '/^{$/{found=1} found'` (JSON).

---

## 13. Export RTP audio as WAV

**Problem:** A call sounds bad. You want the actual audio to listen to or share.

### From the TUI

```bash
sipnab -I capture.pcap
#   → select the call in the call list (Up/Down)
#   → press 'r' or Tab to switch to the RTP stream view
#   → highlight a stream
#   → F2 to open the Save dialog
#   → cycle the format (Left/Right) until you reach "WAV — Decoded G.711 audio per RTP stream"
#   → Enter to save
```

A timestamped `.wav` lands at the path you choose. The Save dialog also exposes PCAP, PCAP-NG, TXT, JSON, NDJSON, CSV, HTML, Markdown, RTP JSON, and SIPp XML formats — WAV is the format you want for audio.

### Live audio playback (TUI)

If you've built with the `audio` feature (in default), `P` in the RTP stream view plays the highlighted stream through your local audio device.

**Pitfalls:**

- Supported codecs for WAV decode and playback: G.711 µ-law (PT 0), G.711 A-law (PT 8), Opus (dynamic PT). Other codecs (G.729, AMR, etc.) aren't decoded today.
- A failed audio device (headless servers, Tegra without ALSA) no longer crashes the TUI — it disables playback gracefully and surfaces a message suggesting F2 → WAV as an offline alternative.
- A CLI batch audio-export flag does **not** exist today. The library functions (`rtp::audio_export::export_stream_to_wav`, `export_dialog_to_wav`) are available if you want to build it; until then, scripted batch export means driving the TUI under `expect`/`tmux` or writing a small Rust binary that links the library.

---

## 14. Browser pcap analysis (no install)

**Problem:** You don't want to install anything. The pcap is on your laptop. You want to look at it.

Open </analyze/> in any modern browser. Drag-and-drop a pcap or `.pcapng` file. Everything runs locally via WebAssembly — the pcap never leaves your machine.

The analyze page supports `.pcap`, `.pcapng`, `.cap` (NetMon), and gives you the same call list, ladder diagram, RTP stream view, search, and filter DSL as the native TUI. Keyboard shortcuts match the TUI (`?` opens the help popup).

**Pitfalls:**

- WASM has no network access — live capture is native-only.
- Very large pcaps (>200 MB) may strain browser memory. Use the native `sipnab -N` for those.
