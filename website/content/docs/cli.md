+++
title = "CLI Reference"
weight = 2
description = "Complete flag reference for sipnab, organized by functional group."
+++

> **Quick start:** `sipnab -I capture.pcap` to analyze a file, or `sudo sipnab` for live capture on the default interface. Add `-N` for non-interactive output.

Complete flag reference for sipnab. Flags are organized by functional group.

CLI flags always override config file values. Boolean flags default to `off` (false) unless otherwise noted.

## Common Recipes

Real-world examples to get productive fast. Each recipe combines flags that work well together.

### Debug a failed call

```bash
# Find all failed calls in a pcap
sipnab -N -I capture.pcap --filter "state == 'Failed'"

# Show just the call flow for a specific Call-ID
sipnab -I capture.pcap --call-report "abc123@host"

# Get a Markdown-formatted report for a ticket
sipnab -I capture.pcap --call-report "abc123@host" --markdown > report.md
```

### Monitor live SIP quality

```bash
# Watch for poor quality calls in real-time
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0 OR one_way == true"

# Export problems as NDJSON for your monitoring pipeline
sudo sipnab -N -d eth0 --problems --json | tee /var/log/sipnab/problems.ndjson

# Alert when quality drops below threshold
sudo sipnab -d eth0 --on-quality-exec "/usr/local/bin/pagerduty-alert.sh" \
  --quality-threshold 3.0 --exec-rate-limit 5
```

### Measure post-dial delay across calls

```bash
# Find calls with slow setup (PDD > 3 seconds)
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json

# Use the built-in alias for quick PDD checks
sipnab -N -I capture.pcap --slow-setup --report
```

### Security monitoring

```bash
# Detect SIP scanners and log for fail2ban
sudo sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab/scanners.log

# Find digest authentication leaks
sipnab -N -I capture.pcap --digest-leak

# Full security sweep: scanners + fraud + registration floods
sudo sipnab -N -d eth0 --kill-scanner --fraud-detect --reg-flood \
  --alert syslog --alert json --syslog
```

### Export for Wireshark analysis

```bash
# Generate a Wireshark display filter for a specific user
sipnab -I capture.pcap --wireshark

# Generate a tshark command filtered by caller
sipnab -I capture.pcap --tshark-filter "from.user == '1001'"
```

### Export call audio as WAV

Audio export is a TUI workflow — see [Keybindings](@/docs/keybindings.md).

### Pipe through jq for custom analysis

```bash
# Count failures by response code
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r '.status_code' | sort | uniq -c | sort -rn

# Find all unique User-Agents
sipnab -N -I capture.pcap --json \
  | jq -r '.user_agent // empty' | sort -u
```

### Bound, split, and multi-interface captures

```bash
# Capture first 1000 packets, then generate a report
sipnab -N -d eth0 -n 1000 --report

# Split capture files at 50 MiB and write as pcapng
sipnab -d eth0 -O /var/captures/sip.pcapng --pcapng --split filesize:50

# Monitor all interfaces with delta timestamps
sipnab -d any --multi-device --delta-time
```

> **Tip:** The `-N` flag is required for any output flag (`--json`, `--report`, `--fail2ban`, etc.). Think of it as "non-interactive mode" -- it disables the TUI and writes to stdout instead.

---

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE>` | auto-detect | Network interface to capture on. Auto-detects the default interface if no `-I` file or `-L` HEP listener is specified |
| `-I`, `--input` | `<FILE>` | -- | Read packets from a pcap file instead of live capture |
| `-O`, `--output` | `<FILE>` | -- | Write captured packets to a pcap file |
| `-B`, `--buffer` | `<MIB>` | OS default | Kernel capture buffer size in MiB |
| `--buffer-budget` | `<MIB>` | `64` | Memory budget for the in-flight capture→processing queue (grows under load up to this, capped; shrinks when idle). Overrides `[capture] buffer_budget_mb` |
| `--snaplen` | `<BYTES>` | OS default | Snapshot length for packet capture (bytes) |
| `--portrange` | `<RANGE>` | `5060-5061` | SIP port range to capture |
| `--multi-device` | -- | off | Capture on all available interfaces |
| `--no-rtp` | -- | off | Disable RTP capture and analysis |
| `--bpf-file` | `<FILE>` | -- | Read BPF filter from a file |
| `-n`, `--count` | `<N>` | -- | Stop after capturing N packets |
| `--duration` | `<DURATION>` | -- | Stop after duration (e.g., `30s`, `5m`, `1h`) |
| `--autostop` | `<CONDITION>` | -- | Autostop condition (e.g., `filesize:100`, `duration:60`) |
| `--split` | `<CONDITION>` | -- | Split output files (e.g., `filesize:50` for 50 MiB chunks) |
| `--replay` | -- | off | Replay packets from a pcap file at original timing |
| `--pcapng` | -- | off | Use pcapng format for output files |
| `--strip-secrets` | `<OUTPUT>` | -- | With `-I <input>`, write a copy of the input pcapng to `<OUTPUT>` with all Decryption Secrets Blocks removed (the `editcap --discard-all-secrets` analog), then exit. The input is never modified; the output is written atomically |
| `<BPF_FILTER>...` | positional | -- | BPF display filter expression (trailing positional args) |

## Mode

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-N`, `--no-tui` | -- | off | Non-interactive mode (no TUI). Required for batch/output flags |
| `-c`, `--calls-only` | -- | off | Show only SIP dialogs (calls), not standalone messages |
| `-t`, `--telephone-event` | -- | off | Capture and display telephone-event (DTMF) RTP payloads |
| `-q`, `--quiet` | -- | off | Suppress informational output; only show results |

## Matching

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-i`, `--ignore-case` | -- | off | Case-insensitive matching for header filters and patterns |
| `-v`, `--invert` | -- | off | Invert the match: show messages that do NOT match |
| `-w`, `--word` | -- | off | Match whole words only |
| `--single-line` | -- | off | Treat multi-line SIP headers as a single line for matching |
| `--from` | `<PATTERN>` | -- | Filter by SIP From header (regex pattern) |
| `--to` | `<PATTERN>` | -- | Filter by SIP To header (regex pattern) |
| `--contact` | `<PATTERN>` | -- | Filter by SIP Contact header (regex pattern) |
| `--ua` | `<PATTERN>` | -- | Filter by User-Agent header (regex pattern) |
| `--filter` | `<EXPR>` | -- | Advanced filter DSL expression (see [Filter DSL](@/docs/filter-dsl.md)) |

## Diagnostic Aliases

Shortcut flags that expand to predefined filter DSL expressions. See [Filter DSL](@/docs/filter-dsl.md) for the exact expansion of each alias.

| Flag | Description |
|------|-------------|
| `--problems` | Show calls matching any diagnostic signal: failed state, one-way audio, RTP loss > 2%, jitter > 50 ms, NAT mismatch, more than 3 retransmits, PDD > 32 s, orphaned RTP, codec/ptime/payload/duration asymmetry, or late media. See [Named Aliases](@/docs/filter-dsl.md#named-aliases) for the exact expansion |
| `--slow-setup` | Show calls with post-dial delay > 3 seconds |
| `--short-calls` | Show completed calls shorter than 5 seconds |
| `--one-way` | Show calls with potential one-way audio issues |
| `--nat-issues` | Show calls with Contact/Via NAT mismatch |

## Output

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--json` | -- | off | Output as NDJSON (one JSON object per line). Requires `-N` |
| `--json-pretty` | -- | off | Output as pretty-printed JSON. Requires `-N` |
| `--report` | -- | off | Generate summary report after capture completes. Requires `-N` |
| `--call-report` | `<CALL-ID>` | -- | Generate a detailed report for a specific Call-ID. Implies non-interactive |
| `--markdown` | -- | off | Format report output as Markdown |
| `--hexdump` | -- | off | Include hex dump of SIP payloads. Requires `-N` |
| `--no-cli-print` | -- | off | Suppress per-message CLI output (use with `--report` / `--call-report` so only the post-capture summary reaches stdout) |
| `--delta-time` | -- | off | Show delta time between consecutive messages |
| `-A`, `--after` | `<N>` | -- | Show N messages after each match (like `grep -A`) |
| `--show-empty` | -- | off | Show messages with empty bodies |
| `--line-buffer` | -- | off | Flush output after each line (useful for piping) |
| `--color` | `<WHEN>` | `auto` | Color output mode: `auto`, `always`, `never` |
| `--from-to-mode` | `<MODE>` | `default` | Default TUI From/To column display: `default` (user else host:port), `host-port`, `user`, `user-host-port`. Cycle at runtime with `u` |
| `--payload-limit` | `<BYTES>` | -- | Maximum payload bytes to display |
| `-T`, `--text-dump` | -- | off | Dump raw SIP message text |
| `--wireshark` | -- | off | Launch Wireshark with a display filter for the current capture |
| `--tshark-filter` | `<EXPR>` | -- | Generate a tshark-compatible display filter string |
| `--fail2ban` | -- | off | Output in fail2ban-compatible format for SIP security events. Requires `-N` |
| `--group-by` | `<FIELD>` | -- | Group output by field (e.g., `call-id`, `from`, `method`) |

## Name Resolution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--resolve` | -- | off | Start with name resolution enabled (manual mappings + hosts file) |
| `--reverse-dns` | -- | off | Also resolve via reverse DNS (PTR); implies `--resolve` |
| `--names` | `<FILE>` | -- | Preload an `/etc/hosts`-format mapping file (repeatable) |

## Dialog

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-l`, `--limit` | `<N>` | `100000` | Maximum number of dialogs to track simultaneously |
| `-R`, `--rotate` | -- | **on** | Evict the oldest dialog at `--limit` capacity (LRU). On by default; the flag is kept for back-compat |
| `--no-rotate` | -- | off | Disable rotation: drop *new* dialogs at capacity instead of evicting the oldest |
| `--dialog-track` | `<METHOD>` | -- | Dialog tracking method: `call-id` or `branch` |
| `--no-dialog` | -- | off | Disable dialog tracking entirely (message-only mode) |
| `--tag` | `<TAG>` | -- | Filter dialogs by tag value |

## RTP

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--rtp-interval` | `<SECS>` | `1` | RTP statistics reporting interval in seconds |
| `--max-streams` | `<N>` | `50000` | Maximum number of RTP streams to track simultaneously |
| `--quality-threshold` | `<MOS>` | `3.0` | MOS quality threshold for alerts (1.0-5.0 scale) |

## Security

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--kill-scanner` | -- | off | Detect and report SIP scanning activity |
| `--kill-ua` | `<PATTERN>` | -- | Detect scanners by User-Agent pattern (regex) |
| `--kill-response` | `<CODE>` | `200` | SIP response code for scanner kill reports (100-699) |
| `--fraud-detect` | -- | off | Enable fraud detection heuristics |
| `--reg-flood` | -- | off | Detect registration flood attacks |
| `--digest-leak` | -- | off | Detect digest credential leaks in SIP messages |
| `--alert` | `<CHANNEL>` | -- | Alert channels (repeatable): `syslog`, `json`, `exec` |
| `--alert-exec` | `<CMD>` | -- | Execute this command when an alert fires |
| `--alert-json` | -- | off | Emit each security alert as a structured JSON line on stderr (in addition to the human `[ALERT]` line) |
| `--stir-shaken` | -- | off | Validate STIR/SHAKEN identity headers |

## Event Execution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--on-dialog-exec` | `<CMD>` | -- | Execute command when a dialog state changes |
| `--on-quality-exec` | `<CMD>` | -- | Execute command when RTP quality drops below threshold |
| `--exec-rate-limit` | `<N>` | `10` | Maximum exec invocations per second |

## Network Listeners

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--metrics` | `<ADDR>` | -- | Prometheus metrics endpoint (e.g., `0.0.0.0:9090`). Feature: `api` |
| `--metrics-auth` | `<USER:PASS>` | -- | HTTP Basic auth credentials (`user:pass`) required by the metrics endpoint; requests must send `Authorization: Basic <base64>` |
| `--api` | `<ADDR>` | -- | REST API endpoint (e.g., `0.0.0.0:8080`). Feature: `api` |
| `--api-key` | `<KEY>` | -- | API key for REST API authentication. Also reads `$SIPNAB_API_KEY` |
| `--api-tls-cert` | `<FILE>` | -- | TLS certificate file for API endpoint |
| `--api-tls-key` | `<FILE>` | -- | TLS private key file for API endpoint |
| `--api-max-conn` | `<N>` | `100` | Maximum concurrent API connections |
| `--api-signing-key` | `<HEX>` | -- | HMAC signing key (hex) for revocable API tokens |
| `--api-signing-key-file` | `<FILE>` | -- | Read the API HMAC signing key from a file |
| `--api-revoked-file` | `<FILE>` | -- | File listing revoked API token IDs (one per line) |
| `--api-token-ttl` | `<SECS>` | -- | Lifetime for minted API tokens |
| `-L`, `--hep-listen` | `<ADDR>` | -- | Listen for HEP (Homer Encapsulation Protocol) packets. Feature: `hep` |
| `-H`, `--hep-send` | `<ADDR>` | -- | Send captured packets via HEP to a remote collector. Feature: `hep` |
| `-E`, `--hep-parse` | -- | off | Parse incoming HEP packets (enable HEP decoding). Feature: `hep` |
| `--hep-allow` | `<ADDR>` | -- | Allowed source addresses for HEP input (repeatable) |
| `--hep-rate-limit` | `<N>` | `50000` | Maximum HEP packets per second |
| `--syslog` | -- | off | Send alerts to syslog |

## MCP Server

Run sipnab as a Model Context Protocol server so an AI agent can drive
it. See [MCP Server](@/docs/mcp.md) for the full guide.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--mcp` | -- | off | Run sipnab as an MCP server (implies `--no-tui`). Feature: `mcp` |
| `--mcp-transport` | `<TRANSPORT>` | `stdio` | Transport: `stdio` (default) or `http` (requires `mcp-http` feature) |
| `--mcp-bind` | `<ADDR>` | -- (`127.0.0.1:8731` applied at runtime when `--mcp-transport http` is set without an explicit bind) | Bind address for the HTTP MCP transport |
| `--mcp-token` | `<TOKEN>` | -- | Bearer token for HTTP MCP. Required for non-loopback binds. Also reads `$SIPNAB_MCP_TOKEN` |
| `--mcp-token-file` | `<FILE>` | -- | Read MCP bearer token from a file (preferred over env in systemd units) |
| `--mcp-allowed-host` | `<HOST>` | -- | Additional Host header values the HTTP MCP server will accept (repeatable). rmcp's DNS-rebind protection defaults to allowing only `localhost`, `127.0.0.1`, and `::1`; add the public hostname or bind IP clients actually use. `*` disables host checking entirely (not recommended; pair the resulting open binding with a network-level allowlist) |
| `--mcp-signing-key` | `<HEX>` | -- | HMAC signing key (hex) for revocable MCP tokens |
| `--mcp-signing-key-file` | `<FILE>` | -- | Read the MCP HMAC signing key from a file |
| `--mcp-revoked-file` | `<FILE>` | -- | File listing revoked MCP token IDs (one per line) |
| `--mcp-token-ttl` | `<SECS>` | -- | Lifetime for minted MCP tokens |
| `--mint-token` | -- | off | Mint a signed bearer token (using the API/MCP signing key) and exit |
| `--token-id` | `<ID>` | -- | Token ID to embed when minting with `--mint-token` |

## TLS / Decryption

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-k`, `--tls-key` | `<FILE>` | -- | TLS private key file for SIP-TLS decryption. Feature: `tls` |
| `--keylog` | `<FILE>` | -- | TLS key log file (NSS `SSLKEYLOGFILE` format). Feature: `tls` |
| `--keylog-watch` | -- | off | Watch key log file for new entries (live decryption). Feature: `tls` |
| `--dtls-keylog` | `<FILE>` | -- | DTLS key log file for SRTP key extraction. Feature: `tls` |
| `--srtp-keys` | `<FILE>` | -- | SRTP master keys file for RTP decryption. Feature: `tls` |
| `--pcap-export-mode` | `<MODE>` | `decrypted` | Pcap export mode for encrypted traffic: `decrypted` (plaintext payloads, no DSB), `raw` (original encrypted bytes, no DSB), `encrypted+dsb` (original encrypted bytes + Decryption Secrets Block so Wireshark can decrypt) |
| `--allow-coredump` | -- | off | Allow core dumps (do not call `prctl` to disable them) |

## Privilege

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--user` | `<USER>` | -- | Drop privileges to this user after opening capture devices |
| `--no-priv-drop` | -- | off | Do not drop privileges after opening capture devices |
| `--chroot` | `<DIR>` | -- | Chroot to this directory after initialization |
| `--setup-caps` | -- | off | Grant the binary `CAP_NET_RAW`/`CAP_NET_ADMIN` via setcap (one-time, needs sudo) and exit |

## Resource Limits

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--max-reassembly` | `<N>` | `10000` | Maximum concurrent TCP/TLS reassembly sessions |
| `--cores` | `<N>` | `1` | CPU cores for offline pcap reconstruction (`-I`). 1 = single-threaded; >1 shards by host pair for multi-core throughput (dialog+RTP reconstruction, `--report`/`--json`) |

## Config

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-f`, `--config` | `<FILE>` | -- | Path to configuration file (must exist) |
| `-F`, `--no-config` | -- | off | Skip loading any configuration file |
| `-D`, `--dump-config` | -- | off | Dump effective configuration and exit |

## Validation Rules

- Output flags (`--json`, `--json-pretty`, `--report`, `--hexdump`, `--fail2ban`) require `-N` / `--no-tui` mode, unless `--call-report` is also specified.
- `--kill-response` accepts values 100-699 only.
- Feature-gated flags (`tls`, `hep`, `api`, `mcp`, `mcp-http`, `audio`, `tui`) produce startup errors when the required feature is not compiled in.
- `--mcp` is incompatible with stdout-writing flags (`--json`, `--json-pretty`, `--report`, `--call-report`, `--hexdump`, `--wireshark`, `--tshark-filter`) when using stdio transport — sipnab refuses to start. Combine `--mcp` with `--quiet` to suppress text-mode capture output.
- HTTP MCP transport (`--mcp --mcp-transport http`) on a non-loopback `--mcp-bind` requires `--mcp-token` / `--mcp-token-file` / `SIPNAB_MCP_TOKEN`; loopback binds need no token.
