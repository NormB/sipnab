# Cookbook — common workflows

Copy-paste recipes for the tasks sipnab is usually reached for. Live
capture needs root or `CAP_NET_RAW` — run `sudo sipnab --setup-caps` once
and drop the `sudo` from every recipe below (see
[install.md](install.md#live-capture-permissions)); reading pcap files
needs no privileges. Every flag used here is detailed in
[cli-reference.md](cli-reference.md).

> The documentation site carries a longer cookbook — fourteen worked
> recipes including Prometheus/Grafana, fail2ban, WAV export and
> browser-based analysis: <https://www.sipnab.com/docs/cookbook/>.

## Triage a capture fast

```bash
# 1. Watch SIP interactively on an interface (TUI, sngrep-style)
sudo sipnab -d eth0

# 2. Show only problem calls from a pcap. The --problems flag is a narrow
#    sweep: retransmits, or a Failed dialog. For the broad diagnostic set
#    (one-way audio, loss/jitter, NAT, asymmetry, late media) use the
#    same-named DSL alias via --filter problems.
sipnab -N -I capture.pcap --problems
sipnab -N -I capture.pcap --filter problems

# 3. Deep-dive one call: ladder, timing, SDP, RTP quality, diagnosis
sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1'

# 4. The same as a Markdown report for a ticket
sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1' --markdown > call.md

# 5. Post-capture aggregate summary only (no per-message noise)
sipnab -N -I capture.pcap --report --no-cli-print
```

## Narrow a capture to the calls you care about

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

## Feed NDJSON into jq and other tools

```bash
# 10. NDJSON to jq: count failures by status code
sipnab -N -I capture.pcap --json \
  | jq -s 'map(select(.status_code >= 400)) | group_by(.status_code)
           | map({code: .[0].status_code, n: length})'

# 11. Every Call-ID seen on the wire (feed back into --call-report)
sipnab -N -I capture.pcap --json | jq -r '.call_id // empty' | sort -u
```

More in [output-formats.md](./output-formats.md).

## Record traffic to disk, encrypted or not

```bash
# 12. Capture SIP+RTP to rotating pcapng files (50 MiB chunks)
sudo sipnab -N -d eth0 -O /var/capture/sip.pcapng --pcapng --split filesize:50

# 13. Decrypt SIPS signaling with a TLS key log and export decryptable
#     pcapng. --keylog is the SIP/TLS NSS keylog -- signaling only; it
#     does not decrypt media. SRTP needs media keys instead:
#     --dtls-keylog (DTLS-SRTP handshakes) or --srtp-keys (AES-CM
#     master keys; SDES a=crypto keys are also learned from SDP).
sudo sipnab -N -d eth0 --keylog /tmp/sslkeys.log --keylog-watch \
     -O decrypted.pcapng --pcapng
sipnab -N -I capture.pcap --dtls-keylog /tmp/dtls.keylog
sipnab -N -I capture.pcap --srtp-keys /tmp/srtp-keys.txt
```

## Detect scanners and block abuse

```bash
# 14. Detect SIP scanners and answer them (rate-limited)
sudo sipnab -N -d eth0 --kill-scanner --alert syslog

# 15. Emit fail2ban-compatible lines for scanner/flood sources
sudo sipnab -N -d eth0 --fail2ban
```

## Run a command when a call or its quality changes

```bash
# 16. Run a command on every dialog state change (details arrive as
#     SIPNAB_* env vars + SIPNAB_JSON payload — never shell-interpolated)
sudo sipnab -N -d eth0 --on-dialog-exec '/usr/local/bin/call-logger'

# 17. Alert when RTP quality drops
sudo sipnab -N -d eth0 --on-quality-exec '/usr/local/bin/page-noc'
```

## Exchange HEP with Kamailio, OpenSIPS or Homer

```bash
# 18. Receive HEP from Kamailio/OpenSIPS/Asterisk and analyze live.
#     -L/--hep-listen decodes HEP on its own; --hep-parse is only for
#     unwrapping HEP that arrives inside ordinary UDP capture.
sipnab -N -L 0.0.0.0:9060

# 19. Mirror captured traffic to Homer
sudo sipnab -N -d eth0 -H homer.example.net:9060
```

## Next steps

- [keybindings.md](keybindings.md) — the interactive TUI these captures feed
- [filter-dsl.md](filter-dsl.md) — the full filter language behind `--filter`
- [mcp.md](mcp.md) — drive the same analysis from an AI agent
