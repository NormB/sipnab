# CLI Reference

Complete flag reference for sipnab. Flags are grouped by function.

## Capture

| Flag | Description | Default |
|------|-------------|---------|
| `-d`, `--device <IFACE>` | Network interface to capture on | -- |
| `-I`, `--input <FILE>` | Read packets from a pcap file | -- |
| `-O`, `--output <FILE>` | Write captured packets to a pcap file | -- |
| `-B`, `--buffer <MIB>` | Kernel capture buffer size in MiB | OS default |
| `--snaplen <BYTES>` | Snapshot length for packet capture | OS default |
| `--portrange <RANGE>` | SIP port range to capture | `5060-5061` |
| `--multi-device` | Capture on all available interfaces | off |
| `--no-rtp` | Disable RTP capture and analysis | off |
| `--bpf-file <FILE>` | Read BPF filter from a file | -- |
| `-n`, `--count <N>` | Stop after capturing N packets | -- |
| `--duration <DURATION>` | Stop after duration (e.g., `30s`, `5m`, `1h`) | -- |
| `--autostop <CONDITION>` | Autostop condition (e.g., `filesize:100`) | -- |
| `--split <CONDITION>` | Split output files (e.g., `filesize:50`) | -- |
| `--replay` | Replay pcap file at original timing | off |
| `--pcapng` | Use pcapng format for output files | off |
| `<BPF_FILTER>...` | BPF display filter (trailing positional args) | -- |

## Mode

| Flag | Description | Default |
|------|-------------|---------|
| `-N`, `--no-tui` | Non-interactive mode (no TUI) | off |
| `-c`, `--calls-only` | Show only SIP dialogs, not standalone messages | off |
| `-t`, `--telephone-event` | Capture telephone-event (DTMF) RTP payloads | off |
| `-q`, `--quiet` | Suppress informational output | off |

## Matching

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--ignore-case` | Case-insensitive matching | off |
| `-v`, `--invert` | Invert match (show non-matching messages) | off |
| `-w`, `--word` | Match whole words only | off |
| `--single-line` | Treat multi-line SIP headers as single line | off |
| `--from <PATTERN>` | Filter by SIP From header (regex) | -- |
| `--to <PATTERN>` | Filter by SIP To header (regex) | -- |
| `--contact <PATTERN>` | Filter by SIP Contact header (regex) | -- |
| `--ua <PATTERN>` | Filter by User-Agent header (regex) | -- |
| `--filter <EXPR>` | Advanced filter DSL expression | -- |

## Diagnostic Aliases

| Flag | Description | Default |
|------|-------------|---------|
| `--problems` | Show calls with retransmits, timeouts, errors | off |
| `--slow-setup` | Show calls with setup time >3s | off |
| `--short-calls` | Show calls shorter than 10 seconds | off |
| `--one-way` | Show calls with potential one-way audio | off |
| `--nat-issues` | Show calls with Contact/Via mismatch | off |

## Output

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output as JSON (one object per line) | off |
| `--json-pretty` | Output as pretty-printed JSON | off |
| `--report` | Generate summary report after capture | off |
| `--call-report <CALL-ID>` | Detailed report for a specific Call-ID | -- |
| `--markdown` | Format report output as Markdown | off |
| `--hexdump` | Include hex dump of SIP payloads | off |
| `--delta-time` | Show delta time between consecutive messages | off |
| `-A`, `--after <N>` | Show N messages after each match | -- |
| `--show-empty` | Show messages with empty bodies | off |
| `--line-buffer` | Flush output after each line | off |
| `--color <WHEN>` | Color output: `auto`, `always`, `never` | `auto` |
| `--payload-limit <BYTES>` | Maximum payload bytes to display | -- |
| `-T`, `--text-dump` | Dump raw SIP message text | off |
| `--wireshark` | Launch Wireshark with display filter | off |
| `--tshark-filter <EXPR>` | Generate tshark-compatible display filter | -- |
| `--fail2ban` | Output in fail2ban-compatible format | off |
| `--group-by <FIELD>` | Group output by field (e.g., `call-id`, `from`) | -- |

## Dialog

| Flag | Description | Default |
|------|-------------|---------|
| `-l`, `--limit <N>` | Maximum dialogs to track simultaneously | `100000` |
| `-R`, `--rotate` | Rotate dialog storage when limit reached | off |
| `--dialog-track <METHOD>` | Dialog tracking method (`call-id`, `branch`) | -- |
| `--no-dialog` | Disable dialog tracking (message-only mode) | off |
| `--tag <TAG>` | Filter dialogs by tag value | -- |

## RTP

| Flag | Description | Default |
|------|-------------|---------|
| `--rtp-interval <SECS>` | RTP statistics reporting interval | `1` |
| `--max-streams <N>` | Maximum RTP streams to track | `50000` |
| `--quality-threshold <MOS>` | MOS quality threshold for alerts (1.0-5.0) | `3.0` |

## Security

| Flag | Description | Default |
|------|-------------|---------|
| `--kill-scanner` | Detect and report SIP scanning activity | off |
| `--kill-ua <PATTERN>` | Detect scanners by User-Agent pattern | -- |
| `--kill-response <CODE>` | SIP response code for scanner kill reports | `200` |
| `--fraud-detect` | Enable fraud detection heuristics | off |
| `--reg-flood` | Detect registration flood attacks | off |
| `--digest-leak` | Detect digest credential leaks | off |
| `--alert <CHANNEL>` | Alert channels (repeatable: `syslog`, `json`, `exec`) | -- |
| `--alert-exec <CMD>` | Execute command when alert fires | -- |
| `--stir-shaken` | Validate STIR/SHAKEN identity headers | off |

## Event Exec

| Flag | Description | Default |
|------|-------------|---------|
| `--on-dialog-exec <CMD>` | Execute command on dialog state change | -- |
| `--on-quality-exec <CMD>` | Execute command on quality drop | -- |
| `--exec-rate-limit <N>` | Maximum exec invocations per second | `10` |

## Network Listeners

| Flag | Description | Default |
|------|-------------|---------|
| `--metrics <ADDR>` | Prometheus metrics endpoint (e.g., `0.0.0.0:9090`) | -- |
| `--metrics-auth <TOKEN>` | Bearer token for metrics endpoint | -- |
| `--api <ADDR>` | REST API endpoint (e.g., `0.0.0.0:8080`) | -- |
| `--api-key <KEY>` | API key for REST API authentication | -- |
| `--api-tls-cert <FILE>` | TLS certificate for API endpoint | -- |
| `--api-tls-key <FILE>` | TLS private key for API endpoint | -- |
| `--api-max-conn <N>` | Maximum concurrent API connections | `100` |
| `-L`, `--hep-listen <ADDR>` | Listen for HEP packets | -- |
| `-H`, `--hep-send <ADDR>` | Send captured packets via HEP | -- |
| `-E`, `--hep-parse` | Parse incoming HEP packets | off |
| `--hep-allow <ADDR>` | Allowed HEP source addresses (repeatable) | -- |
| `--hep-rate-limit <N>` | Maximum HEP packets per second | `50000` |
| `--syslog` | Send alerts to syslog | off |

## TLS / Decryption

| Flag | Description | Default |
|------|-------------|---------|
| `-k`, `--tls-key <FILE>` | TLS private key for SIP-TLS decryption | -- |
| `--keylog <FILE>` | TLS key log file (NSS SSLKEYLOGFILE format) | -- |
| `--keylog-watch` | Watch key log file for live decryption | off |
| `--dtls-keylog <FILE>` | DTLS key log file for SRTP key extraction | -- |
| `--srtp-keys <FILE>` | SRTP master keys file for RTP decryption | -- |
| `--pcap-export-mode <MODE>` | Pcap export mode for encrypted traffic | `decrypted` |
| `--allow-coredump` | Allow core dumps (skip prctl disable) | off |

## Privilege

| Flag | Description | Default |
|------|-------------|---------|
| `--user <USER>` | Drop privileges to this user after capture open | -- |
| `--no-priv-drop` | Do not drop privileges | off |
| `--chroot <DIR>` | Chroot to this directory after initialization | -- |

## Resource Limits

| Flag | Description | Default |
|------|-------------|---------|
| `--max-reassembly <N>` | Maximum concurrent TCP/TLS reassembly sessions | `10000` |

## Config

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--config <FILE>` | Path to configuration file | -- |
| `-F`, `--no-config` | Skip loading any configuration file | off |
| `-D`, `--dump-config` | Dump effective configuration and exit | off |
