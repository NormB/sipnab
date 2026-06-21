# CLI Reference

Complete flag reference for sipnab. Flags are organized by functional group.

CLI flags always override config file values. Boolean flags default to `off` (false) unless otherwise noted.

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE>` | auto-detect | Network interface to capture on. Auto-detects the default interface if no `-I` file or `-L` HEP listener is specified |
| `-I`, `--input` | `<FILE>` | -- | Read packets from a pcap file instead of live capture |
| `-O`, `--output` | `<FILE>` | -- | Write captured packets to a pcap file |
| `-B`, `--buffer` | `<MIB>` | OS default | Kernel capture buffer size in MiB |
| `--buffer-budget` | `<MIB>` | `64` | Memory budget for the in-flight capture→processing queue. The queue grows under load up to this budget (capped, never OOM) and shrinks when idle; overrides `[capture] buffer_budget_mb` |
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
| `--filter` | `<EXPR>` | -- | Filter DSL expression OR a diagnostic alias name (`codec-asym`, `late-media`, etc.) — see [filter-dsl.md](filter-dsl.md) |

## Name Resolution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--resolve` | -- | off | Turn name resolution on (manual mappings + `/etc/hosts`). In the TUI, press `n` to cycle Off / Static / DNS; in headless `-O --pcapng` export it embeds a Name Resolution Block |
| `--reverse-dns` | -- | off | Also use reverse DNS (PTR) lookups. Implies `--resolve`. Emits DNS queries for captured IPs |
| `--names` | `<FILE>` | -- | Preload IP → name mappings from an `/etc/hosts`-format file. Repeatable |

See the [Name Resolution](keybindings.md#name-resolution) keys for in-TUI naming (`N`) and persistence.

## pcapng Metadata

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--strip-secrets` | `<OUTPUT>` | -- | With `-I <input>`, write a copy of the input pcapng to `<OUTPUT>` with all Decryption Secrets Blocks removed (the `editcap --discard-all-secrets` analog), then exit. The input is never modified; the output is written atomically. |

Note: name mappings are saved into a pcapng Name Resolution Block when saving with
resolution active — both the TUI save path and headless `-O --pcapng` export
(when `--resolve`/`--names` are set). Headless pcapng exports are also
self-describing: the Section Header Block records the producing application
(`sipnab <version>`) and OS, and the Interface Description Block records the
capture source as the interface name. Embedded NRB names / DSB TLS secrets are
read back (and used for decryption) when a pcapng is opened. See
[the design doc](design/pcapng-metadata.md).

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
| `--json` | -- | off | Output as NDJSON (one JSON object per line, schema in [output-formats.md](output-formats.md)). Requires `-N` |
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
| `--from-to-mode` | `<MODE>` | `default` | Default TUI From/To column display: `default` (user else host:port), `host-port`, `user`, `user-host-port`. Cycle at runtime with `u`. Overrides `[display] from_to` |
| `--payload-limit` | `<BYTES>` | -- | Maximum payload bytes to display |
| `-T`, `--text-dump` | -- | off | Dump raw SIP message text (like sipgrep `-T`) |
| `--no-cli-print` | -- | off | Suppress per-message CLI output (useful with `--report` / `--call-report` so only the post-capture summary reaches stdout) |
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
| `--api-signing-key` | `<KEY>` | -- | HMAC signing key for self-describing bearer tokens (repeatable; the first mints, all are accepted on verify → key rotation). Also reads `$SIPNAB_API_SIGNING_KEY`. See [`auth.md`](./auth.md). Feature: `api` |
| `--api-signing-key-file` | `<FILE>` | -- | Read an API signing key from a file (contents trimmed). Feature: `api` |
| `--api-revoked-file` | `<FILE>` | -- | Revocation denylist: one revoked token `id` per line; reloaded on mtime change. Feature: `api` |
| `--api-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting API tokens with `--mint-token`. Feature: `api` |
| `--mcp` | -- | off | Run sipnab as an MCP server. Feature: `mcp` (or `mcp-http` for HTTP transport). See [`mcp-overview.md`](./mcp-overview.md). |
| `--mcp-transport` | `stdio\|http` | `stdio` | MCP transport. `http` requires the `mcp-http` feature. |
| `--mcp-bind` | `<ADDR>` | -- (defaults to `127.0.0.1:8731` at runtime if `--mcp-transport http` is set without an explicit bind) | HTTP MCP bind address. Non-loopback requires `--mcp-token`. |
| `--mcp-token` | `<TOKEN>` | -- | Bearer token. Also reads `$SIPNAB_MCP_TOKEN`. |
| `--mcp-token-file` | `<FILE>` | -- | Read bearer token from file (preferred over env in systemd units). |
| `--mcp-signing-key` | `<KEY>` | -- | HMAC signing key for MCP bearer tokens (repeatable; first mints, all verify). Also reads `$SIPNAB_MCP_SIGNING_KEY`. See [`auth.md`](./auth.md). |
| `--mcp-signing-key-file` | `<FILE>` | -- | Read an MCP signing key from a file (contents trimmed). |
| `--mcp-revoked-file` | `<FILE>` | -- | MCP revocation denylist (one token `id` per line; reloaded on mtime change). |
| `--mcp-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting MCP tokens with `--mint-token`. |
| `--mcp-allowed-host` | `<HOST>` | -- | Additional `Host` header values the HTTP MCP server will accept (repeatable). rmcp's DNS-rebind protection defaults to `localhost`, `127.0.0.1`, `::1` only — add the public hostname or bind IP when clients connect via that name. Use `*` to disable host checking entirely (pair with a network-level source-IP allowlist). |
| `-L`, `--hep-listen` | `<ADDR>` | -- | Listen for HEP (Homer Encapsulation Protocol) packets. Feature: `hep` |
| `-H`, `--hep-send` | `<ADDR>` | -- | Send captured packets via HEP to a remote collector. Feature: `hep` |
| `-E`, `--hep-parse` | -- | off | Parse incoming HEP packets (enable HEP decoding). Feature: `hep` |
| `--hep-allow` | `<ADDR>` | -- | Allowed source addresses for HEP input (repeatable) |
| `--hep-rate-limit` | `<N>` | `50000` | Maximum HEP packets per second |
| `--syslog` | -- | off | Send alerts to syslog |
| `--mint-token` | -- | off | Mint a signed bearer token from the first configured signing key, print it to stdout, and exit (no capture/servers). See [`auth.md`](./auth.md). |
| `--token-id` | `<ID>` | -- | Token id (`jti`) for `--mint-token`, used for revocation. Defaults to a generated id. |

## TLS / Decryption

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-k`, `--tls-key` | `<FILE>` | -- | RSA private key (PEM) for TLS 1.2 RSA-key-exchange decryption. Non-PFS RSA only; ECDHE/DHE need `--keylog`. Feature: `tls` |
| `--keylog` | `<FILE>` | -- | TLS key log file (NSS `SSLKEYLOGFILE` format). Feature: `tls` |
| `--keylog-watch` | -- | off | Watch key log file for new entries (live decryption). Feature: `tls` |
| `--dtls-keylog` | `<FILE>` | -- | DTLS key log (NSS `SSLKEYLOGFILE`); extracts SRTP keys from DTLS-SRTP handshakes (RFC 5764 exporter, AES-CM profiles). Feature: `tls` |
| `--srtp-keys` | `<FILE>` | -- | SRTP master-keys file for media decryption (AES-CM, RFC 3711); also honors SDES `a=crypto` keys from SDP. Feature: `tls` |
| `--pcap-export-mode` | `<MODE>` | `decrypted` | Pcap export mode for encrypted traffic |
| `--allow-coredump` | -- | off | Allow core dumps (do not call `prctl` to disable them) |

## Privilege

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--user` | `<USER>` | -- | Drop privileges to this user after opening capture devices |
| `--no-priv-drop` | -- | off | Do not drop privileges after opening capture devices |
| `--chroot` | `<DIR>` | -- | Chroot to this directory after initialization |
| `--setup-caps` | -- | off | Grant this binary the Linux capabilities for live capture (`cap_net_raw,cap_net_admin+ep` via `setcap`) so it runs without `sudo`, then exit. Re-invokes through `sudo` when not already root. Linux only. |

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
