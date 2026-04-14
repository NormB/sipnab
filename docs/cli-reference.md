# CLI Reference

Complete flag reference for sipnab. Flags are organized by functional group.

CLI flags always override config file values. Boolean flags default to `off` (false) unless otherwise noted.

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE>` | -- | Network interface to capture on |
| `-I`, `--input` | `<FILE>` | -- | Read packets from a pcap file instead of live capture |
| `-O`, `--output` | `<FILE>` | -- | Write captured packets to a pcap file |
| `-B`, `--buffer` | `<MIB>` | OS default | Kernel capture buffer size in MiB |
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
| `--filter` | `<EXPR>` | -- | Advanced filter DSL expression (see [filter-dsl.md](filter-dsl.md)) |

## Diagnostic Aliases

Shortcut flags that expand to predefined filter DSL expressions. See [filter-dsl.md](filter-dsl.md) for the exact expansion of each alias.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--problems` | -- | off | Show calls with retransmits, timeouts, errors, quality issues, or NAT mismatch |
| `--slow-setup` | -- | off | Show calls with post-dial delay > 3 seconds |
| `--short-calls` | -- | off | Show completed calls shorter than 5 seconds |
| `--one-way` | -- | off | Show calls with potential one-way audio issues |
| `--nat-issues` | -- | off | Show calls with Contact/Via NAT mismatch |

## Output

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--json` | -- | off | Output as NDJSON (one JSON object per line). Requires `-N` |
| `--json-pretty` | -- | off | Output as pretty-printed JSON. Requires `-N` |
| `--report` | -- | off | Generate summary report after capture completes. Requires `-N` |
| `--call-report` | `<CALL-ID>` | -- | Generate a detailed report for a specific Call-ID. Implies non-interactive |
| `--markdown` | -- | off | Format report output as Markdown |
| `--hexdump` | -- | off | Include hex dump of SIP payloads. Requires `-N` |
| `--delta-time` | -- | off | Show delta time between consecutive messages |
| `-A`, `--after` | `<N>` | -- | Show N messages after each match (like `grep -A`) |
| `--show-empty` | -- | off | Show messages with empty bodies |
| `--line-buffer` | -- | off | Flush output after each line (useful for piping) |
| `--color` | `<WHEN>` | `auto` | Color output mode: `auto`, `always`, `never` |
| `--payload-limit` | `<BYTES>` | -- | Maximum payload bytes to display |
| `-T`, `--text-dump` | -- | off | Dump raw SIP message text (like sipgrep `-T`) |
| `--wireshark` | -- | off | Launch Wireshark with a display filter for the current capture |
| `--tshark-filter` | `<EXPR>` | -- | Generate a tshark-compatible display filter string |
| `--fail2ban` | -- | off | Output in fail2ban-compatible format for SIP security events. Requires `-N` |
| `--group-by` | `<FIELD>` | -- | Group output by field (e.g., `call-id`, `from`, `method`) |

## Dialog

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-l`, `--limit` | `<N>` | `100000` | Maximum number of dialogs to track simultaneously |
| `-R`, `--rotate` | -- | off | Rotate dialog storage when limit is reached (discard oldest) |
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
| `--metrics-auth` | `<TOKEN>` | -- | Bearer token for metrics endpoint authentication |
| `--api` | `<ADDR>` | -- | REST API endpoint (e.g., `0.0.0.0:8080`). Feature: `api` |
| `--api-key` | `<KEY>` | -- | API key for REST API authentication. Also reads `$SIPNAB_API_KEY` |
| `--api-tls-cert` | `<FILE>` | -- | TLS certificate file for API endpoint |
| `--api-tls-key` | `<FILE>` | -- | TLS private key file for API endpoint |
| `--api-max-conn` | `<N>` | `100` | Maximum concurrent API connections |
| `-L`, `--hep-listen` | `<ADDR>` | -- | Listen for HEP (Homer Encapsulation Protocol) packets. Feature: `hep` |
| `-H`, `--hep-send` | `<ADDR>` | -- | Send captured packets via HEP to a remote collector. Feature: `hep` |
| `-E`, `--hep-parse` | -- | off | Parse incoming HEP packets (enable HEP decoding). Feature: `hep` |
| `--hep-allow` | `<ADDR>` | -- | Allowed source addresses for HEP input (repeatable) |
| `--hep-rate-limit` | `<N>` | `50000` | Maximum HEP packets per second |
| `--syslog` | -- | off | Send alerts to syslog |

## TLS / Decryption

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-k`, `--tls-key` | `<FILE>` | -- | TLS private key file for SIP-TLS decryption. Feature: `tls` |
| `--keylog` | `<FILE>` | -- | TLS key log file (NSS `SSLKEYLOGFILE` format). Feature: `tls` |
| `--keylog-watch` | -- | off | Watch key log file for new entries (live decryption). Feature: `tls` |
| `--dtls-keylog` | `<FILE>` | -- | DTLS key log file for SRTP key extraction. Feature: `tls` |
| `--srtp-keys` | `<FILE>` | -- | SRTP master keys file for RTP decryption. Feature: `tls` |
| `--pcap-export-mode` | `<MODE>` | `decrypted` | Pcap export mode for encrypted traffic |
| `--allow-coredump` | -- | off | Allow core dumps (do not call `prctl` to disable them) |

## Privilege

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--user` | `<USER>` | -- | Drop privileges to this user after opening capture devices |
| `--no-priv-drop` | -- | off | Do not drop privileges after opening capture devices |
| `--chroot` | `<DIR>` | -- | Chroot to this directory after initialization |

## Resource Limits

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--max-reassembly` | `<N>` | `10000` | Maximum concurrent TCP/TLS reassembly sessions |

## Config

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-f`, `--config` | `<FILE>` | -- | Path to configuration file (must exist) |
| `-F`, `--no-config` | -- | off | Skip loading any configuration file |
| `-D`, `--dump-config` | -- | off | Dump effective configuration and exit |

## Validation Rules

- Output flags (`--json`, `--json-pretty`, `--report`, `--hexdump`, `--fail2ban`) require `-N` / `--no-tui` mode, unless `--call-report` is also specified.
- `--kill-response` accepts values 100-699 only.
- Feature-gated flags (`tls`, `hep`, `api`) produce startup errors when the required feature is not compiled in.

## Examples

```bash
# Capture on eth0
sipnab -d eth0

# Read from pcap file
sipnab -I capture.pcap

# Non-interactive JSON output
sipnab -N --json -I capture.pcap

# Show problematic calls
sipnab --problems

# Detect SIP scanners
sipnab --kill-scanner -d eth0

# Filter by From/To headers
sipnab --from alice --to bob

# BPF display filter
sipnab 'host 10.0.0.1 and port 5060'

# Advanced filter DSL
sipnab --filter "method == 'INVITE' AND rtp.mos < 3.0"

# Generate detailed report for a call
sipnab -I capture.pcap --call-report "abc123@host" --markdown

# Capture with HEP mirror
sipnab -d eth0 -H 10.0.0.50:9060

# Live TLS decryption
sipnab -d eth0 --keylog /tmp/sslkeys.log --keylog-watch
```
