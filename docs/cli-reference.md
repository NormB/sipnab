# CLI Reference

Complete flag reference for sipnab. Flags are organized by functional group.

CLI flags always override config file values (see [config-reference.md](config-reference.md)). Boolean flags default to `off` (false) unless otherwise noted. For task-oriented recipes rather than a flag catalog, start with [examples.md](examples.md).

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE>` | auto-detect | Network interface to capture on. Auto-detects the default interface if no `-I` file or `-L` HEP listener is specified |
| `-I`, `--input` | `<FILE>` | -- | Read packets from a pcap file instead of live capture |
| `-O`, `--output` | `<FILE>` | -- | Write captured packets to a pcap file |
| `-B`, `--buffer` | `<MIB>` | `2` | Kernel capture buffer size in MiB |
| `--buffer-budget` | `<MIB>` | `64` | Memory budget for the in-flight capture→processing queue. The queue grows under load up to this budget (capped, never OOM) and shrinks when idle; overrides `[capture] buffer_budget_mb` |
| `--snaplen` | `<BYTES>` | `65535` | Snapshot length for packet capture (bytes) |
| `-S`, `--limitlen` | `<BYTES>` | -- | Parse only the first N bytes of each packet (sipgrep `-S`). Caps what the SIP parser and matchers inspect, independent of `--snaplen` (capture length) and `--payload-limit` (display truncation) |
| `--no-reassembly` | -- | off | Disable IP-fragment and TCP-segment reassembly; every packet is parsed standalone (inverse of sipgrep `-a`). Useful for pure single-packet UDP scanning |
| `-x`, `--quiet-bad-parse` | -- | off | Suppress the per-packet "SIP parse error" diagnostic emitted when a SIP-looking packet fails to parse (sipgrep `-x`). The packet is dropped either way; this only silences the notice on a noisy link |
| `--portrange` | `<RANGE>` | `5060-5061` | SIP port range to capture |
| `--multi-device` | -- | off | Capture on all available interfaces |
| `--no-rtp` | -- | off | Disable RTP capture and analysis |
| `-p`, `--no-promisc` | -- | off | Do not put the interface into promiscuous mode (sipgrep `-p`). Promisc is on by default for a named device; the `any` pseudo-device is never promiscuous |
| `--bpf-file` | `<FILE>` | -- | Read BPF filter from a file |
| `-n`, `--count` | `<N>` | -- | Stop after receiving N packets (counts every packet received, including any a HEP listener later drops by allowlist, rate limit, or auth) |
| `--duration` | `<DURATION>` | -- | Stop after duration (e.g., `30s`, `5m`, `1h`) |
| `--autostop` | `<CONDITION>` | -- | Autostop condition (e.g., `filesize:100`, `duration:60`) |
| `--split` | `<CONDITION>` | -- | Split output files (e.g., `filesize:50` for 50 MiB chunks) |
| `--replay` | -- | off | Replay packets from a pcap file at original timing |
| `--pcapng` | -- | off | Use pcapng format for output files |
| `<BPF_FILTER>...` | positional | -- | BPF display filter expression (trailing positional args) |

**Examples**

```bash
# Record up to 10000 packets from eth0 into a pcap, watching a widened SIP port range
sudo sipnab --device eth0 --output capture.pcap --portrange 5060-5080 --count 10000
# Live-capture a busy link with bigger kernel and queue buffers, a capped snapshot length, and parse-error notices silenced (sipgrep -x)
sudo sipnab --device eth0 --buffer 16 --buffer-budget 128 --snaplen 2048 --quiet-bad-parse
# Capture on all available interfaces headlessly, stopping once the output file reaches 100 MiB
sudo sipnab -N --multi-device --output capture.pcap --autostop filesize:100
# Replay a pcap at its original timing with RTP capture and analysis disabled
sipnab -N --input capture.pcap --replay --no-rtp
# Scan a pcap sipgrep-style: parse only the first 512 bytes of each packet, every packet standalone (no reassembly), without parse-error noise
sipnab -N --input capture.pcap --limitlen 512 --no-reassembly --quiet-bad-parse
# Capture for 5 minutes using a BPF filter read from sip.bpf, without putting the interface into promiscuous mode (sipgrep -p)
sudo sipnab --device eth0 --bpf-file sip.bpf --no-promisc --duration 5m
# Monitor an hour of traffic across a wide SIP port range with enlarged capture buffers
sudo sipnab --device eth0 --portrange 5060-5090 --buffer 8 --buffer-budget 256 --duration 1h
# Replay signaling only from a pcap, parsing at most 1500 bytes of each packet
sipnab -N --input capture.pcap --replay --limitlen 1500 --no-rtp
# Stop after 500 packets that pass the sip.bpf filter, non-promiscuous, with the snapshot length sized for jumbo frames
sudo sipnab --device eth0 --bpf-file sip.bpf --no-promisc --snaplen 9000 --count 500
# Write a one-minute capture that treats every packet standalone (IP-fragment and TCP-segment reassembly off)
sudo sipnab -N --device eth0 --output capture.pcap --autostop duration:60 --no-reassembly
```


## Mode

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-N`, `--no-tui` | -- | off | Non-interactive mode (no TUI). Required for batch/output flags |
| `-c`, `--calls-only` | -- | off | Show only SIP dialogs (calls), not standalone messages |
| `-t`, `--telephone-event` | -- | off | Capture and display telephone-event (DTMF) RTP payloads |
| `-q`, `--quiet` | -- | off | Suppress informational output; only show results |

**Examples**

```bash
# Analyze a pcap headlessly, showing only complete SIP dialogs (calls), not standalone messages
sipnab --no-tui -I capture.pcap --calls-only
# Watch live calls in the TUI with telephone-event (DTMF) RTP payloads captured and displayed
sudo sipnab -d eth0 --calls-only --telephone-event
# Headless live capture that decodes DTMF and suppresses informational output
sudo sipnab --no-tui -d eth0 --telephone-event --quiet
```


## Matching

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-e`, `--match` | `<PATTERN>` | -- | SIP payload match-expression (the sngrep/sipgrep positional match expression). Regex tested against the whole raw message; once any message in a dialog matches, the rest of that dialog is shown too (dialog-following). Honors `-i`/`-v`/`-w`/`--single-line`. Independent of the trailing `<BPF_FILTER>` positional |
| `-i`, `--ignore-case` | -- | off | Case-insensitive matching for header filters and patterns |
| `-v`, `--invert` | -- | off | Invert the match: show messages that do NOT match |
| `-w`, `--word` | -- | off | Match whole words only |
| `--single-line` | -- | off | Treat multi-line SIP headers as a single line for matching |
| `--from` | `<PATTERN>` | -- | Filter by SIP From header (regex pattern) |
| `--to` | `<PATTERN>` | -- | Filter by SIP To header (regex pattern) |
| `--contact` | `<PATTERN>` | -- | Filter by SIP Contact header (regex pattern) |
| `--ua` | `<PATTERN>` | -- | Filter by User-Agent header (regex pattern) |
| `--filter` | `<EXPR>` | -- | Filter DSL expression OR a diagnostic alias name (`codec-asym`, `late-media`, etc.) — see [filter-dsl.md](filter-dsl.md) |

**Examples**

```bash
# Show every dialog that mentions alice@example.com, case-insensitively (dialog-following payload match)
sipnab -N -I capture.pcap --match "alice@example.com" --ignore-case
# Whole-word match for 486 rejections, folding multi-line headers into one line before matching
sipnab -N -I capture.pcap --match "486 Busy Here" --word --single-line
# Live view of everything except REGISTER traffic (inverted match)
sudo sipnab -d eth0 --match "REGISTER" --invert
# Flag scanner traffic live: a known scanner User-Agent (any case) with a Contact pointing into 203.0.113.0/24
sudo sipnab -d eth0 --ua "friendly-scanner" --contact "203\.0\.113\." --ignore-case
# Filter a pcap by User-Agent and a Contact in 192.0.2.0/24, matching even when headers span folded lines
sipnab -N -I capture.pcap --ua "sipcli" --contact "192\.0\.2\." --single-line
# Suppress keep-alive noise: show messages that do not contain the whole word OPTIONS
sipnab -N -I capture.pcap --match "OPTIONS" --word --invert
```


## Name Resolution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--resolve` | -- | off | Turn name resolution on (manual mappings + `/etc/hosts`). In the TUI, press `n` to cycle Off / Static / DNS; in headless `-O --pcapng` export it embeds a Name Resolution Block |
| `--reverse-dns` | -- | off | Also use reverse DNS (PTR) lookups. Implies `--resolve`. Emits DNS queries for captured IPs |
| `--names` | `<FILE>` | -- | Preload IP → name mappings from an `/etc/hosts`-format file. Repeatable |

See the [Name Resolution](keybindings.md#name-resolution) keys for in-TUI naming (`N`) and persistence.

**Examples**

```bash
# Live capture with name resolution from a static hosts-format mapping file
sudo sipnab -d eth0 --resolve --names /etc/sipnab/hosts.map
# Annotate an offline pcap with names, preloading two mapping files on top of /etc/hosts
sipnab -N -I capture.pcap --resolve --names /etc/sipnab/hosts.map --names ~/.config/sipnab/lab-names
# Live capture that also resolves captured IPs via reverse DNS (PTR) lookups
sudo sipnab -d eth0 --reverse-dns
# Replay an offline pcap and resolve its addresses with reverse DNS, supplemented by a local mapping file
sipnab -N -I capture.pcap --reverse-dns --names ~/.config/sipnab/lab-names
```


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

**Examples**

```bash
# Write a sanitized copy of a pcapng with every Decryption Secrets Block removed
sipnab -N -I capture.pcapng --strip-secrets clean.pcapng
# Strip embedded TLS secrets from a decrypted-session capture before sharing it in a support ticket
sipnab -N -I tls-call.pcapng --strip-secrets tls-call-clean.pcapng
```


## Diagnostic Aliases

Shortcut flags that expand to predefined filter DSL expressions. See [filter-dsl.md](filter-dsl.md) for the exact expansion of each alias.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--problems` | -- | off | Show calls matching any diagnostic signal: failed state, one-way audio, RTP loss > 2%, jitter > 50 ms, NAT mismatch, more than 3 retransmits, PDD > 32 s, orphaned RTP, codec/ptime/payload/duration asymmetry, or late media — see [Named Aliases](filter-dsl.md#named-aliases) for the exact expansion |
| `--slow-setup` | -- | off | Show calls with post-dial delay > 3 seconds |
| `--short-calls` | -- | off | Show completed calls shorter than 5 seconds |
| `--one-way` | -- | off | Show calls with potential one-way audio issues |
| `--nat-issues` | -- | off | Show calls with Contact/Via NAT mismatch |

**Examples**

```bash
# Flag completed calls under 5 seconds and calls with suspected one-way audio in a capture
sipnab -N -I capture.pcap --short-calls --one-way
# Live-monitor for one-way audio and Contact/Via NAT mismatches
sudo sipnab -d eth0 -N --one-way --nat-issues
# Summarize short completed calls from a capture in a post-run report
sipnab -N -I capture.pcap --short-calls --report
```


## Output

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--json` | -- | off | Output as NDJSON (one JSON object per line, schema in [output-formats.md](output-formats.md)). Requires `-N` |
| `--json-pretty` | -- | off | Output each message as pretty-printed multi-line JSON (use `--json` for line-oriented NDJSON). Requires `-N` |
| `--report` | -- | off | Generate summary report after capture completes. Requires `-N` |
| `--call-report` | `<CALL-ID>` | -- | Generate a detailed report for a specific Call-ID. Implies non-interactive |
| `--markdown` | -- | off | Format report output as Markdown |
| `--hexdump` | -- | off | Include hex dump of SIP payloads. Requires `-N` |
| `--delta-time` | -- | off | Show delta time between consecutive messages |
| `-A`, `--after` | `<N>` | -- | Show N messages after each match (like `grep -A`) |
| `--show-empty` (`--full`) | -- | off | Show the full header block of bodyless messages (responses, OPTIONS, REGISTER, ACK, BYE); by default they show only the summary line |
| `--proto-number` | -- | off | Annotate the transport tag with the IANA IP protocol number, e.g. `UDP(17)` / `TCP(6)` (sipgrep `-N`). Long-only because `-N` is `--no-tui` here; TLS/WS report their TCP carrier's number (6) |
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

**Examples**

```bash
# Export every SIP message from a capture as pretty-printed JSON, truncating displayed payloads to 1000 bytes
sipnab -N -I capture.pcap --json-pretty --payload-limit 1000 > messages.json
# Stream live SIP traffic as pretty-printed JSON grouped by method, flushing after each line for downstream tooling
sudo sipnab -d eth0 -N --json-pretty --group-by method --line-buffer > live.json
# Dump raw SIP text with hex payloads and IANA protocol numbers, uncolored for log archiving
sipnab -N -I capture.pcap --text-dump --hexdump --proto-number --color never
# Follow live REGISTER traffic in real time, printing raw text plus 2 messages of context after each match
sudo sipnab -d eth0 -N --match REGISTER --after 2 --text-dump --line-buffer --color always
# Review a capture with per-message delta times, empty-bodied messages included, and hex dumps grouped per call
sipnab -N -I capture.pcap --show-empty --delta-time --hexdump --group-by call-id
# Inspect OPTIONS keepalives with 5 messages of trailing context, empty bodies shown, and display capped at 256 payload bytes
sudo sipnab -d eth0 -N --match OPTIONS --after 5 --show-empty --proto-number --payload-limit 256
# Watch the live TUI with host:port From/To columns and hand the capture to Wireshark with a matching display filter
sudo sipnab -d eth0 --from-to-mode host-port --wireshark
# Browse an existing capture in the TUI with full user@host:port From/To columns
sipnab -I capture.pcap --from-to-mode user-host-port
# Print a tshark-compatible display filter for the INVITE traffic in a capture
sipnab -N -I capture.pcap --tshark-filter "method=INVITE"
```


## Dialog

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-l`, `--limit` | `<N>` | `100000` | Maximum number of dialogs to track simultaneously (the dialog-state memory bound; lower it for untrusted/high-volume capture) |
| `-R`, `--rotate` | -- | **on** | Evict the oldest dialog at `--limit` capacity (LRU). On by default; kept for back-compat/explicitness |
| `--no-rotate` | -- | off | Disable rotation: drop *new* dialogs at capacity instead of evicting the oldest (inverts the safe default) |
| `--dialog-track` | `<METHOD>` | `call-id` | Group messages by `call-id` (one unit per dialog) or `branch` (one per SIP transaction) |
| `--no-dialog` | -- | off | Disable dialog tracking entirely (message-only mode) |
| `--tag` | `<TAG>` | -- | Filter dialogs by tag value |

> **`branch` counts transactions, not calls.** RFC 3261 gives the ACK to a 2xx a
> new branch (§17.1.1.3) and the BYE another, so one ordinary call appears as
> three or more units. That is the transaction view working as intended. Use it
> when a capture reuses one Call-ID across many transactions — load generators,
> proxies under test — and note that `--limit` then counts transactions too.

**Examples**

```bash
# Per-transaction view of a load-generator capture that reuses one Call-ID
sipnab -N -I loadtest.pcapng --dialog-track branch --report
# Same capture as dialogs (the default), for a per-call view
sipnab -N -I loadtest.pcapng --dialog-track call-id --report
```


**Examples**

```bash
# Monitor a busy proxy with a tight 5000-dialog memory bound, explicitly evicting the oldest dialog at capacity
sudo sipnab -d eth0 --limit 5000 --rotate
# Analyze a capture keyed by Via branch, dropping new dialogs (instead of evicting old ones) past 20000 tracked
sipnab -N -I capture.pcap --limit 20000 --no-rotate
# Show only dialogs carrying a specific From/To tag, with explicit LRU rotation
sipnab -N -I capture.pcap --tag 1928301774 --rotate
# Live-follow dialogs matching a tag while refusing new dialogs once the tracker is full
sudo sipnab -d eth0 --tag as7d60e14a --no-rotate
# Scan a capture message-by-message with dialog tracking disabled entirely
sipnab -N -I capture.pcap --no-dialog
# Watch raw live SIP messages on an interface without keeping any per-dialog state
sudo sipnab -d eth0 -N --no-dialog
```


## RTP

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--rtp-interval` | `<SECS>` | `1` | RTP statistics reporting interval in seconds |
| `--max-streams` | `<N>` | `50000` | Maximum number of RTP streams to track simultaneously |
| `--quality-threshold` | `<MOS>` | `3.0` | MOS quality threshold for alerts (1.0-5.0 scale) |

**Examples**

```bash
# Monitor live RTP with 5-second statistics reports and MOS alerts below 3.5
sudo sipnab -d eth0 --rtp-interval 5 --quality-threshold 3.5 --max-streams 10000
# Batch-analyze RTP streams in a capture, reporting stats every 2 seconds with a raised stream cap
sipnab -N -I capture.pcap --rtp-interval 2 --max-streams 100000
```


## Security

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--kill-scanner` | -- | off | Detect SIP scanning (known UA signatures + behavioral rate/enumeration) and send the kill response back to the scanner (sipgrep `-J`/`-j`) |
| `--kill-ua` | `<PATTERN>` | -- | Add a custom scanner User-Agent pattern (regex) to `--kill-scanner` detection |
| `--kill-response` | `<CODE>` | `200` | SIP response code for the kill response (100-699) |
| `-K`, `--kill-target` | `<ADDR[:PORT-RANGE]>` | -- | Targeted kill (sipgrep `-K`): send the kill response to any SIP request whose source matches ADDR and an optional port range (`192.0.2.1:5060-5090`, `[::1]:5060`), regardless of UA/behavioral detection. Repeatable; spawns the kill worker on its own (no `--kill-scanner` needed) |
| `--kill-spoof` | `<MODE>` | `auto` | Source-address strategy for the kill response (Linux only; other platforms always `ephemeral`). `auto` forges the victim's ip:port via a raw socket when `CAP_NET_RAW` is available (so the reply appears to come from the targeted SIP port), falling back to an ephemeral source otherwise; `raw` requires the spoof and errors if the raw socket can't be opened; `ephemeral` never spoofs |
| `--fraud-detect` | -- | off | Enable fraud detection heuristics |
| `--reg-flood` | -- | off | Detect registration flood attacks |
| `--digest-leak` | -- | off | Detect digest credential leaks in SIP messages |
| `--alert` | `<CHANNEL>` | -- | Alert channels (repeatable): `syslog`, `json`, `exec` |
| `--alert-exec` | `<CMD>` | -- | Execute this command when an alert fires |
| `--alert-json` | -- | off | Emit each security alert as a structured JSON line on stderr (in addition to the human `[ALERT]` line) |
| `--stir-shaken` | -- | off | Validate STIR/SHAKEN identity headers |

**Examples**

```bash
# Detect SIP scanners (plus a custom UA pattern) and reply 486 with the victim's spoofed source
sudo sipnab -d eth0 --kill-scanner --kill-ua 'friendly-scanner' --kill-response 486 --kill-spoof auto
# Targeted kill of a scanning host across a port range, plus a second scanner UA, replying 480 via raw-socket spoof
sudo sipnab -d eth0 --kill-target 192.0.2.66:5060-5090 --kill-ua 'sipvicious' --kill-response 480 --kill-spoof raw
# Kill requests from one more source port using a non-spoofed ephemeral reply
sudo sipnab -d eth0 --kill-target 198.51.100.77:5060 --kill-spoof ephemeral
# Live security monitoring: registration floods, digest leaks, fraud, STIR/SHAKEN, with JSON alerts and an exec hook
sudo sipnab -N -d eth0 --reg-flood --digest-leak --fraud-detect --stir-shaken --alert json --alert-json --alert-exec '/usr/local/bin/notify.sh'
# Offline audit of a pcap for digest leaks and STIR/SHAKEN validity, emitting structured JSON alerts
sipnab -N -I capture.pcap --stir-shaken --digest-leak --alert-json
```


## Event Execution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--on-dialog-exec` | `<CMD>` | -- | Execute command when a dialog state changes |
| `--on-quality-exec` | `<CMD>` | -- | Execute command when RTP quality drops below threshold |
| `--exec-rate-limit` | `<N>` | `10` | Maximum exec invocations per second |

## Network Listeners

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--metrics` | `<ADDR>` | -- | Prometheus metrics endpoint (e.g., `127.0.0.1:9090`). A non-loopback bind (e.g. `0.0.0.0:9090`) is **refused** unless `--metrics-auth`/`--metrics-auth-file` is also set. Feature: `api` |
| `--metrics-auth` | `<USER:PASS>` | -- | HTTP Basic auth credentials (`user:pass`) required by the metrics endpoint; requests must send `Authorization: Basic <base64>`. Prefer `--metrics-auth-file`. Feature: `api` |
| `--metrics-auth-file` | `<FILE>` | -- | Read the metrics Basic-auth `user:pass` from a file (contents trimmed), keeping the secret out of the process list. Takes precedence over `--metrics-auth`. Feature: `api` |
| `--api` | `<ADDR>` | -- | REST API endpoint (e.g., `0.0.0.0:8080`). Feature: `api` |
| `--api-key` | `<KEY>` | -- | API key for REST API authentication. Also reads `$SIPNAB_API_KEY` Feature: `api` |
| `--api-tls-cert` | `<FILE>` | -- | **Not yet implemented** — built-in API TLS is not wired up, and sipnab exits if this is set. Terminate TLS at a reverse proxy instead. Feature: `api` |
| `--api-tls-key` | `<FILE>` | -- | **Not yet implemented** — see `--api-tls-cert`; terminate TLS at a reverse proxy. Feature: `api` |
| `--api-max-conn` | `<N>` | `100` | Maximum concurrent API connections Feature: `api` |
| `--api-signing-key` | `<KEY>` | -- | HMAC signing key for self-describing bearer tokens (repeatable; the first mints, all are accepted on verify → key rotation). Also reads `$SIPNAB_API_SIGNING_KEY`. See [`auth.md`](./auth.md). Feature: `api` |
| `--api-signing-key-file` | `<FILE>` | -- | Read an API signing key from a file (contents trimmed). Feature: `api` |
| `--api-revoked-file` | `<FILE>` | -- | Revocation denylist: one revoked token `id` per line; reloaded on mtime change. Feature: `api` |
| `--api-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting API tokens with `--mint-token`. Feature: `api` |
| `--mcp` | -- | off | Run sipnab as an MCP server. Requires `-N`/`--no-tui` (stdout carries the JSON-RPC wire) and rejects stdout-writing flags (`--json`, `--report`, …). Feature: `mcp` (or `mcp-http` for HTTP transport). See [`mcp.md`](./mcp.md). |
| `--mcp-transport` | `stdio\|http` | `stdio` | MCP transport. `http` requires the `mcp-http` feature. Feature: `mcp` |
| `--mcp-bind` | `<ADDR>` | -- (defaults to `127.0.0.1:8731` at runtime if `--mcp-transport http` is set without an explicit bind) | HTTP MCP bind address. Non-loopback requires `--mcp-token`. Feature: `mcp-http` |
| `--mcp-token` | `<TOKEN>` | -- | Bearer token. Also reads `$SIPNAB_MCP_TOKEN`. Feature: `mcp-http` |
| `--mcp-token-file` | `<FILE>` | -- | Read bearer token from file (preferred over env in systemd units). Feature: `mcp-http` |
| `--mcp-signing-key` | `<KEY>` | -- | HMAC signing key for MCP bearer tokens (repeatable; first mints, all verify). Also reads `$SIPNAB_MCP_SIGNING_KEY`. See [`auth.md`](./auth.md). Feature: `mcp-http` |
| `--mcp-signing-key-file` | `<FILE>` | -- | Read an MCP signing key from a file (contents trimmed). Feature: `mcp-http` |
| `--mcp-revoked-file` | `<FILE>` | -- | MCP revocation denylist (one token `id` per line; reloaded on mtime change). Feature: `mcp-http` |
| `--mcp-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting MCP tokens with `--mint-token`. Feature: `mcp-http` |
| `--mcp-allowed-host` | `<HOST>` | -- | Additional `Host` header values the HTTP MCP server will accept (repeatable). rmcp's DNS-rebind protection defaults to `localhost`, `127.0.0.1`, `::1` only — add the public hostname or bind IP when clients connect via that name. Use `*` to disable host checking entirely (pair with a network-level source-IP allowlist). Feature: `mcp-http` |
| `-L`, `--hep-listen` | `<ADDR>` | -- | Listen for HEP (Homer Encapsulation Protocol) packets. Feature: `hep` |
| `-H`, `--hep-send` | `<ADDR>` | -- | Send captured packets via HEP to a remote collector. Feature: `hep` |
| `--hep-id` | `<ID>` | `1` | Capture-agent id (HEP `0x000c` chunk) stamped on packets sent via `--hep-send`. Feature: `hep` |
| `--hep-auth` | `<KEY>` | -- | Homer authenticate key (HEP `0x000e` chunk). On `--hep-send` it is stamped on every outgoing packet; on `--hep-listen` it **enables receiver-side authentication** — incoming packets must carry a matching key (constant-time compared) or they are dropped. Also read from `SIPNAB_HEP_AUTH`. **Security note:** the key travels in cleartext inside the HEP datagram, so it defeats blind/off-path spoofing but an on-path sniffer can capture and replay it. Over an untrusted path, tunnel HEP through WireGuard/IPsec/stunnel (the same posture as terminating API TLS in a reverse proxy) rather than relying on the key alone. Feature: `hep` |
| `--hep-auth-file` | `<FILE>` | -- | Read the HEP shared secret from a file (contents trimmed), keeping it out of the process list. Takes precedence over `--hep-auth`. Feature: `hep` |
| `--hep-auth-mode` | `<plain\|hmac>` | `plain` | HEP auth mode. `plain` sends/expects the shared secret verbatim in the 0x000e chunk (Homer-compatible, but replayable by an on-path sniffer). `hmac` sends/expects a per-message token (timestamp + nonce + HMAC-SHA256 over the payload) that resists replay — **sipnab-to-sipnab only**; a stock Homer/Kamailio peer will not understand it. Feature: `hep` |
| `-E`, `--hep-parse` | -- | off | Parse incoming HEP packets (enable HEP decoding). Feature: `hep` |
| `--hep-allow` | `<ADDR>` | -- | Allowed source addresses for HEP input (repeatable). A non-loopback `--hep-listen` bind is **refused** unless either this or `--hep-auth`/`--hep-auth-file` is set. Feature: `hep` |
| `--hep-rate-limit` | `<N>` | `50000` | Maximum HEP packets per second (global ceiling across all senders); `0` disables the global ceiling, consistent with `off` on the per-peer knob Feature: `hep` |
| `--hep-rate-limit-per-peer` | `<N\|auto\|off>` | `off` | Maximum HEP packets/second from any single source IP: a number, `off` (the default), or `auto`. Adds fairness so one flooding peer cannot exhaust the global `--hep-rate-limit`. `auto` divides the global ceiling evenly across the `--hep-allow` sources (stays off when no allowlist is set). The active limiters are logged when the listener starts. Feature: `hep` |
| `--hep-allow-kill` | -- | off | Allow scanner-kill to send active responses for packets received via HEP. **Off by default**: a HEP sender asserts the inner src/dst, so absent `--hep-auth` an attacker could aim the kill at a victim of their choosing. Only enable with authenticated, trusted HEP input. Feature: `hep` |
| `--syslog` | -- | off | Send alerts to syslog |
| `--mint-token` | -- | off | Mint a signed bearer token from the first configured signing key, print it to stdout, and exit (no capture/servers). See [`auth.md`](./auth.md). |
| `--token-id` | `<ID>` | -- | Token id (`jti`) for `--mint-token`, used for revocation. Defaults to a generated id. |

**Examples**

```bash
# Live capture serving a signed-token REST API, a revocation list, and a Basic-auth'd Prometheus endpoint (terminate TLS at a reverse proxy)
sudo sipnab -d eth0 --api 127.0.0.1:8080 --api-signing-key-file /etc/sipnab/signing.key --api-revoked-file /etc/sipnab/revoked.txt --api-token-ttl 7200 --api-max-conn 200 --metrics 127.0.0.1:9090 --metrics-auth alice:s3cret
# Public-facing API tuned to 100 connections and 1h token TTL, with its own auth'd metrics endpoint
sudo sipnab -d eth0 --api 0.0.0.0:8080 --api-signing-key-file /etc/sipnab/signing.key --api-token-ttl 3600 --api-max-conn 100 --metrics 127.0.0.1:9090 --metrics-auth bob:hunter2
# Loopback HTTP MCP server with a bearer token, file-loaded signing key, revocation denylist, and a 30-minute mint TTL
sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 --mcp-token t0ken-alice --mcp-signing-key-file /etc/sipnab/mcp-signing.key --mcp-revoked-file /etc/sipnab/mcp-revoked.txt --mcp-token-ttl 1800
# Non-loopback HTTP MCP server (token required) accepting an extra Host header for named clients
sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-bind 0.0.0.0:8731 --mcp-token t0ken-bob --mcp-signing-key-file /etc/sipnab/mcp-signing.key --mcp-revoked-file /etc/sipnab/mcp-revoked.txt --mcp-allowed-host mcp.example.com
# Forward captured packets to a Homer collector, stamping capture-agent id 42 and an authenticate key
sudo sipnab -N -d eth0 --hep-send 192.0.2.10:9060 --hep-id 42 --hep-auth s3cr3t-homer-key
# Forward to a second collector under a different agent id and auth key
sudo sipnab -N -d eth0 --hep-send 198.51.100.20:9060 --hep-id 7 --hep-auth homerkey2
# Replay-resistant forwarding to another sipnab: HMAC-token auth over an untrusted path (both ends must set --hep-auth-mode hmac)
sudo sipnab -N -d eth0 --hep-send 198.51.100.30:9060 --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac
# The matching sipnab-to-sipnab HMAC collector: verifies the per-message token and rejects replays
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac
# Run a HEP collector that parses incoming packets, only from two allowed CIDRs, capped at 20k pkts/sec
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-allow 192.0.2.0/24 --hep-allow 198.51.100.20/32 --hep-rate-limit 20000
# Authenticated HEP collector on a routable address: incoming packets must carry the shared secret, with a 5k/s per-peer fairness cap
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-rate-limit 40000 --hep-rate-limit-per-peer 5000
# Authenticated HEP collector that is also allowed to actively kill scanners seen in the HEP stream (only safe because the feed is authenticated)
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-allow-kill --kill-scanner
# Inline HEP secret (visible in the process list — prefer --hep-auth-file) with a tight per-peer cap for a busy multi-proxy fleet
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth s3cr3t-homer-key --hep-rate-limit-per-peer 2000 --hep-allow-kill --kill-target 198.51.100.7
# Loopback metrics endpoint reading its Basic-auth credential from a file (keeps user:pass out of the process list)
sipnab -N -I capture.pcap --metrics 127.0.0.1:9090 --metrics-auth-file /etc/sipnab/metrics.cred
# Routable metrics endpoint (non-loopback requires auth) using a file-backed credential; terminate TLS at a reverse proxy
sudo sipnab -d eth0 --metrics 0.0.0.0:9090 --metrics-auth-file /etc/sipnab/metrics.cred
# Mint a signed bearer token with a fixed id (for later revocation) and a 1-hour TTL, then exit
sipnab --mint-token --token-id alice-2026 --api-signing-key-file /etc/sipnab/signing.key --api-token-ttl 3600
```


## TLS / Decryption

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-k`, `--tls-key` | `<FILE>` | -- | RSA private key (PEM) for TLS 1.2 RSA-key-exchange decryption. Non-PFS RSA only; ECDHE/DHE need `--keylog`. Feature: `tls` |
| `--keylog` | `<FILE>` | -- | TLS key log file (NSS `SSLKEYLOGFILE` format). Feature: `tls` |
| `--keylog-watch` | -- | off | Watch key log file for new entries (live decryption). Feature: `tls` |
| `--dtls-keylog` | `<FILE>` | -- | DTLS key log (NSS `SSLKEYLOGFILE`); extracts SRTP keys from DTLS-SRTP handshakes (RFC 5764 exporter, AES-CM profiles). Feature: `tls` |
| `--srtp-keys` | `<FILE>` | -- | SRTP master-keys file for media decryption (AES-CM, RFC 3711); also honors SDES `a=crypto` keys from SDP. Feature: `tls` |
| `--pcap-export-mode` | `<MODE>` | `decrypted` | Pcap export mode for encrypted traffic: `decrypted`, `encrypted+dsb`, or `raw` |
| `--allow-coredump` | -- | off | Allow core dumps (do not call `prctl` to disable them) |

**Examples**

```bash
# Decrypt TLS 1.2 RSA-key-exchange SIP from a pcap using an RSA private key, with core dumps left enabled
sipnab -N -I capture.pcap --tls-key /etc/sipnab/tls-rsa.key --keylog /etc/sipnab/keys.log --allow-coredump
# Decrypt SRTP media in an offline pcap from an SRTP master-keys file plus DTLS-SRTP handshake keys
sipnab -N -I capture.pcap --srtp-keys /etc/sipnab/srtp.keys --dtls-keylog /etc/sipnab/dtls.log
# Live decrypt both SIP (RSA key) and SRTP media, watching the key log for new PFS session keys
sudo sipnab -d eth0 --tls-key /etc/sipnab/tls-rsa.key --srtp-keys /etc/sipnab/srtp.keys --keylog /etc/sipnab/keys.log --keylog-watch --allow-coredump
```


## Privilege

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--user` | `<USER>` | -- | Drop privileges to this user after opening capture devices |
| `--no-priv-drop` | -- | off | Do not drop privileges after opening capture devices |
| `--chroot` | `<DIR>` | -- | Chroot to this directory after initialization |
| `--setup-caps` | -- | off | Grant this binary the Linux capabilities for live capture (`cap_net_raw,cap_net_admin+ep` via `setcap`) so it runs without `sudo`, then exit. Re-invokes through `sudo` when not already root. Linux only. |

**Examples**

```bash
# Live capture that drops root to the sipnab service user once the capture device is open
sudo sipnab -d eth0 --user sipnab
# Long-running monitor that drops to nobody and confines itself to an empty chroot
sudo sipnab -d eth0 --user nobody --chroot /var/empty
# Chrooted capture that keeps root privileges for the whole run
sudo sipnab -d eth0 --chroot /var/empty --no-priv-drop
# Grant the binary the capture capabilities (cap_net_raw,cap_net_admin) so future runs work without sudo, then exit
sudo sipnab --setup-caps
```


## Resource Limits

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--max-reassembly` | `<N>` | `10000` | Maximum concurrent TCP/TLS reassembly sessions |
| `--cores` | `<N>` | `1` | CPU cores for offline pcap reconstruction (`-I`). 1 = single-threaded; >1 shards by host pair for multi-core throughput (dialog+RTP reconstruction, `--report`/`--json`) |

**Examples**

```bash
# Live capture on a busy TCP/TLS trunk with a raised reassembly-session ceiling
sudo sipnab -d eth0 --max-reassembly 50000
# Offline reconstruction sharded across 4 cores, with a tight reassembly bound for an untrusted capture
sipnab -N -I capture.pcap --cores 4 --max-reassembly 2000
```


## Config

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-f`, `--config` | `<FILE>` | -- | Path to configuration file (must exist) |
| `-F`, `--no-config` | -- | off | Skip loading any configuration file |
| `-D`, `--dump-config` | -- | off | Dump effective configuration and exit |
| `--completions` | `<SHELL>` | -- | Print a shell completion script (bash, zsh, fish, elvish, powershell) to stdout and exit |

**Examples**

```bash
# Dump the effective configuration produced by a specific config file, then exit
sipnab --config /etc/sipnab/sipnab.toml --dump-config
# Dump the built-in defaults, skipping any configuration file, then exit
sipnab --no-config --dump-config
# Live capture using a per-user configuration file
sudo sipnab -d eth0 --config ~/.config/sipnab/config.toml
# Analyze an offline pcap with all configuration files ignored
sipnab -N -I capture.pcap --no-config
# Print a bash completion script into a file suitable for /etc/bash_completion.d
sipnab --completions bash > sipnab.bash
# Print a zsh completion script into a file suitable for the zsh fpath
sipnab --completions zsh > _sipnab
```


## Validation Rules

- Output flags (`--json`, `--json-pretty`, `--report`, `--hexdump`, `--fail2ban`) require `-N` / `--no-tui` mode, unless `--call-report` is also specified.
- `--kill-response` accepts values 100-699 only.
- Feature-gated flags (`tls`, `hep`, `api`, `mcp`, `mcp-http`) produce startup errors when the required feature is not compiled in.

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
sipnab 'host 192.0.2.1 and port 5060'

# Advanced filter DSL
sipnab --filter "method == 'INVITE' AND rtp.mos < 3.0"

# Generate detailed report for a call
sipnab -I capture.pcap --call-report "abc123@host" --markdown

# Capture with HEP mirror
sipnab -d eth0 -H 192.0.2.50:9060

# Live TLS decryption
sipnab -d eth0 --keylog /tmp/sslkeys.log --keylog-watch
```

## Exit Codes

Scripts can rely on these:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime failure — capture error, I/O error, or a requested report could not be produced (e.g. `--call-report` Call-ID not found) |
| `2` | Invalid usage — bad flag value or combination, or a flag whose feature is not compiled into this binary |
