# Cookbook — common workflows

Copy-paste recipes for the tasks sipnab is usually reached for. Live
capture needs root or `CAP_NET_RAW`; reading pcap files does not.

## Triage

```bash
# 1. Watch SIP interactively on an interface (TUI, sngrep-style)
sudo sipnab -d eth0

# 2. Show only problem calls from a pcap (failures, one-way audio,
#    slow setup, high loss/jitter/MOS issues)
sipnab -N -I capture.pcap --problems

# 3. Deep-dive one call: ladder, timing, SDP, RTP quality, diagnosis
sipnab -N -I capture.pcap --call-report 'abc123@10.0.0.1'

# 4. The same as a Markdown report for a ticket
sipnab -N -I capture.pcap --call-report 'abc123@10.0.0.1' --markdown > call.md

# 5. Post-capture aggregate summary only (no per-message noise)
sipnab -N -I capture.pcap --report --no-cli-print
```

## Filtering

```bash
# 6. Calls from/to specific users (regex)
sudo sipnab -N -d eth0 --from '^1001@' --to '^18005551212'

# 7. Filter DSL: INVITE dialogs that ended with bad audio quality
sipnab -N -I capture.pcap --filter "method == 'INVITE' and rtp.mos < 3.5"

# 8. Diagnostic aliases via the same flag (see docs/filter-dsl.md)
sipnab -N -I capture.pcap --filter codec-asym
sipnab -N -I capture.pcap --filter late-media

# 9. Slow call setup (long post-dial delay)
sipnab -N -I capture.pcap --slow-setup
```

## Data pipelines

```bash
# 10. NDJSON to jq: count failures by status code
sipnab -N -I capture.pcap --json \
  | jq -s 'map(select(.status_code >= 400)) | group_by(.status_code)
           | map({code: .[0].status_code, n: length})'

# 11. Every Call-ID seen on the wire (feed back into --call-report)
sipnab -N -I capture.pcap --json | jq -r '.call_id // empty' | sort -u
```

More in [output-formats.md](./output-formats.md).

## Recording

```bash
# 12. Capture SIP+RTP to rotating pcapng files (50 MiB chunks)
sudo sipnab -N -d eth0 -O /var/capture/sip.pcapng --pcapng --split filesize:50

# 13. Decrypt SIPS/SRTP with a TLS key log and export decryptable pcapng
sudo sipnab -N -d eth0 --keylog /tmp/sslkeys.log --keylog-watch \
     -O decrypted.pcapng --pcapng
```

## Security

```bash
# 14. Detect SIP scanners and answer them (rate-limited)
sudo sipnab -N -d eth0 --kill-scanner --alert syslog

# 15. Emit fail2ban-compatible lines for scanner/flood sources
sudo sipnab -N -d eth0 --fail2ban
```

## Event hooks

```bash
# 16. Run a command on every dialog state change (details arrive as
#     SIPNAB_* env vars + SIPNAB_JSON payload — never shell-interpolated)
sudo sipnab -N -d eth0 --on-dialog-exec '/usr/local/bin/call-logger'

# 17. Alert when RTP quality drops
sudo sipnab -N -d eth0 --on-quality-exec '/usr/local/bin/page-noc'
```

## HEP

```bash
# 18. Receive HEP from Kamailio/OpenSIPS/Asterisk and analyze live
sipnab -N -L 0.0.0.0:9060 --hep-parse

# 19. Mirror captured traffic to Homer
sudo sipnab -N -d eth0 -H homer.example.net:9060
```
