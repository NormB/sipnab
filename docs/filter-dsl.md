# Filter DSL reference

> **Quick start:** `sipnab --filter "state == 'Failed'"` to find all failed calls, or `sipnab --problems` for a one-flag diagnostic sweep.

sipnab includes a declarative, non-Turing-complete filter language for matching SIP dialogs and their associated RTP streams. You pass expressions through the [`--filter` CLI flag](cli-reference.md#matching) or the `expression` key in the [`[filter]` config section](config-reference.md#filter). The [Diagnostic Aliases](cli-reference.md#diagnostic-aliases) CLI flags (`--problems`, `--slow-setup`, and so on) expand to the named aliases documented below.

## Grammar

```text
expr        = or_expr
or_expr     = and_expr ("OR" and_expr)*
and_expr    = not_expr ("AND" not_expr)*
not_expr    = "NOT" atom | atom
atom        = comparison | "(" expr ")"
comparison  = field operator value
```

Operator precedence (highest to lowest): `NOT`, `AND`, `OR`. Use parentheses to override.

## Fields

All 31 addressable fields, organized by type.

### String fields

| Field | Description | Example Values |
|-------|-------------|----------------|
| `from.user` | User part of the SIP From header | `"1001"`, `"alice"` |
| `to.user` | User part of the SIP To header | `"1002"`, `"bob"` |
| `method` | SIP request method | `"INVITE"`, `"REGISTER"`, `"BYE"` |
| `ua` | User-Agent header (first non-empty across dialog messages) | `"Olle"`, `"friendly-scanner"` |
| `call_id` | SIP Call-ID header | `"abc123@host"` |
| `payload` | Raw message content — matches when ANY message in the dialog contains/matches the value (sngrep-style payload grep) | `"X-Custom-Header"`, `"sipsak"` |
| `src.ip` | Source IP address (first message) | `"192.0.2.1"` |
| `dst.ip` | Destination IP address (first message) | `"192.0.2.2"` |
| `state` | Dialog state machine value | `"Trying"`, `"InCall"`, `"Failed"` |
| `rtp.codec` | RTP codec name (matches if ANY linked stream matches) | `"PCMU"`, `"opus"` |
| `rtp.ssrc` | RTP SSRC in hex format (matches if ANY linked stream matches) | `"0x12345678"` |

**Valid `state` values:** `Trying`, `Ringing`, `InCall`, `Completed`, `Cancelled`, `Failed`, `Redirected`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`

> **`payload` vs `-e`/`--match`:** the `payload` field matches per dialog (true
> if any message matches). The `-e`/`--match` flag is the sngrep/sipgrep-style
> per-message match-expression: it selects the matching messages and then
> *follows the dialog* — every message after the first match in that dialog is
> emitted too. Use `-e` for grep-style streaming output; use `payload` inside a
> larger `--filter` expression.

### Numeric fields

| Field | Description | Unit |
|-------|-------------|------|
| `src.port` | Source port (first message) | port number |
| `dst.port` | Destination port (first message) | port number |
| `duration` | Dialog duration | seconds (float) |
| `msg_count` | Number of SIP messages in dialog | count |
| `pdd` | Post-dial delay (time to first ringing/response) | seconds (float) |
| `setup_time` | Call setup time (INVITE to 200 OK) | seconds (float) |
| `retransmits` | Total retransmit count in dialog | count |
| `rtp.mos` | Mean Opinion Score (worst across streams, E-model R-factor approximation) | 1.0 - 5.0 |
| `rtp.jitter` | Jitter (worst/highest across streams) | milliseconds |
| `rtp.loss` | Packet loss (worst/highest across streams) | percentage (0-100) |
| `rtp.packets` | Total RTP packets (sum across all streams) | count |

### Boolean fields

| Field | Description |
|-------|-------------|
| `rtp.orphaned` | True if any associated RTP stream has no matching SIP dialog |
| `one_way` | True if one-way audio detected (via diagnosis engine) |
| `nat_mismatch` | True if NAT mismatch detected (Contact/Via IP discrepancy) |
| `no_media` | True if no media detected for established call |
| `codec_asymmetry` | True if A and B legs negotiated different RTP codecs |
| `ptime_asymmetry` | True if the two legs use different `ptime` (packetization interval) |
| `payload_asymmetry` | True if dynamic payload type numbers differ across legs (with the same codec) |
| `duration_asymmetry` | True if one leg's media duration is materially shorter than the other's |
| `late_media` | True if RTP starts noticeably later than the answering 200 OK |

## Operators

| Operator | Applies To | Description |
|----------|------------|-------------|
| `==` | string, numeric, boolean | Equal |
| `!=` | string, numeric, boolean | Not equal |
| `<` | string, numeric | Less than |
| `>` | string, numeric | Greater than |
| `<=` | string, numeric | Less than or equal |
| `>=` | string, numeric | Greater than or equal |
| `=~` | string | Regex match (Rust regex syntax) |

Notes:
- Boolean fields only support `==` and `!=`.
- Regex (`=~`) is not applicable to numeric or boolean fields.
- Numeric equality uses epsilon comparison for floating-point precision. For computed values (`duration`, `pdd`, `rtp.mos`) prefer range operators (`>=`, `<`) over `==` — an exact match on a derived float rarely hits.

> **Note:** String comparisons are case-sensitive. `state` values must exactly match one of the 12 values listed under [String Fields](#string-fields) above (`'Failed'`, not `'failed'`). Use `=~` with a case-insensitive regex pattern if you need case-insensitive matching: `state =~ '(?i)failed'`.

## Values

| Syntax | Type | Examples |
|--------|------|---------|
| `'...'` or `"..."` | String | `'INVITE'`, `"alice"` |
| Number | Numeric (f64) | `3.0`, `100`, `0.5` |
| `true` / `false` | Boolean (case-insensitive) | `true`, `FALSE` |
| `'...'` with `=~` | Regex | `'friendly.*scanner'`, `'^1001'` |

Inside a quoted string a backslash escapes the next character, so the
delimiter itself is expressible: `\'` and `\"` yield a literal quote
(`'it\'s'`, `"say \"hi\""`). Every other `\x` sequence — including `\\` — stays
verbatim, backslash and all, so regex metacharacters and
classes still reach the engine unchanged (`from.user =~ '\d\d\d\d'`,
`payload =~ 'example\.com'`, and `'\\'` for a literal backslash in a regex).

> **Tip:** sipnab compiles each regex once and reuses it across all messages. Avoid unbounded quantifiers on large captures (e.g., prefer `from.user =~ '^100[0-9]$'` over `from.user =~ '.*100[0-9].*'`).

## Boolean combinators

| Keyword | Description |
|---------|-------------|
| `AND` | Both sides must match (case-insensitive) |
| `OR` | Either side must match (case-insensitive) |
| `NOT` | Negates the following atom (case-insensitive) |

Parentheses `( )` group sub-expressions to override default precedence.

## Named aliases

These preset expressions are available as dedicated CLI flags where they exist
(`--problems`, etc.), as shorthand to `--filter` (e.g. `--filter codec-asym`),
and as `kinds` entries for the MCP [`find_problems`](mcp.md#find_problems)
tool. They expand to DSL expressions internally.

| Alias | Dedicated CLI Flag | Expansion |
|-------|--------------------|-----------|
| `problems` | `--problems` | `state == 'Failed' OR one_way == true OR rtp.loss > 2.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 32.0 OR rtp.orphaned == true OR codec_asymmetry == true OR ptime_asymmetry == true OR payload_asymmetry == true OR duration_asymmetry == true OR late_media == true` |
| `slow-setup` | `--slow-setup` | `pdd > 3.0` |
| `short-calls` | `--short-calls` | `duration < 5.0 AND state == 'Completed'` |
| `one-way` | `--one-way` | `one_way == true` |
| `nat-issues` | `--nat-issues` | `nat_mismatch == true` |
| `codec-asym` | — (use `--filter codec-asym`) | `codec_asymmetry == true` |
| `ptime-asym` | — (use `--filter ptime-asym`) | `ptime_asymmetry == true` |
| `payload-asym` | — (use `--filter payload-asym`) | `payload_asymmetry == true` |
| `duration-asym` | — (use `--filter duration-asym`) | `duration_asymmetry == true` |
| `late-media` | — (use `--filter late-media`) | `late_media == true` |

`--filter` first tries to resolve the argument as an alias name. If no alias
matches, it parses the argument as a DSL expression. The alias and the
expression it expands to select the same dialogs, so
`sipnab -N -I capture.pcap --filter codec-asym` and
`sipnab -N -I capture.pcap --filter "codec_asymmetry == true"` are equivalent —
pick whichever reads better in the command you are writing.

## Examples

Each entry below is one complete expression, and `--filter` takes exactly one:
these are catalogs to pick a line from, not blocks to copy whole.

### Basic field matching

- `method == 'INVITE'`
- `from.user == '1001'`
- `state == 'InCall'`

### Regex matching

- `ua =~ 'friendly-scanner'`
- `from.user =~ '^100[0-9]'`
- `call_id =~ 'abc.*@'`

### Numeric comparisons

- `pdd > 3.0`
- `rtp.mos < 3.0`
- `rtp.loss > 2.0`
- `duration < 5.0`
- `retransmits > 3`
- `rtp.jitter > 50.0`
- `rtp.packets > 10000`

### Boolean fields

- `one_way == true`
- `nat_mismatch == true`
- `rtp.orphaned == true`
- `no_media == true`
- `codec_asymmetry == true`
- `late_media == true`

### Compound expressions

- `method == 'INVITE' AND rtp.mos < 3.0`
- `from.user =~ '^1001' AND state == 'Failed'`
- `pdd > 3.0 OR retransmits > 5`
- `NOT ua =~ 'friendly-scanner'`
- `(state == 'Failed' OR state == 'Cancelled') AND duration < 1.0`

### Real-world diagnostic queries

The DSL has no comment syntax, so this page labels each query in prose — a `#`
line handed to `--filter` is a parse error, not a note.

- Find calls with poor quality from a specific extension: `from.user =~ '^1001' AND rtp.mos < 3.0`
- Find failed registrations from a subnet: `method == 'REGISTER' AND state == 'Failed' AND src.ip =~ '^10\.0\.1\.'`
- Find short calls that completed (possible robocalls): `duration < 5.0 AND state == 'Completed' AND method == 'INVITE'`
- Find calls with audio issues: `one_way == true OR no_media == true OR rtp.jitter > 100.0`
- Find scanner activity by User-Agent: `ua =~ 'sipvicious|friendly-scanner|sipcli'`

> **Note:** The filter DSL evaluates against dialogs, not individual messages. A filter like `method == 'INVITE'` matches dialogs that opened with an INVITE, including all subsequent messages in that dialog (180, 200, ACK, BYE, etc.).

## Operational Recipes

Filter-DSL recipes, one per real-world task, each a complete command line. Swap
`-I capture.pcap` for `-d eth0` (as root) to run any of them against live
traffic. For broader task recipes beyond the DSL, see the
[Cookbook](examples.md) and [Troubleshooting](troubleshooting.md).

### Poor audio quality (low MOS)

```bash
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0 AND state == 'Completed'" --json
```

Only completed calls -- in-progress calls may not have enough RTP data for an accurate MOS calculation. MOS values follow the ITU-T G.107 E-model: 4.0+ is toll quality, 3.5-4.0 is acceptable, below 3.0 is noticeable degradation.

### One-way audio

```bash
sipnab -N -I capture.pcap --filter "one_way == true AND duration > 10.0" --report
```

The duration check avoids false positives during early call setup when RTP hasn't started flowing yet. For calls where no RTP ever flowed at all, use `no_media == true` instead.

### NAT issues

```bash
sipnab -N -I capture.pcap --filter "nat_mismatch == true AND method == 'INVITE'" --json
```

NAT mismatch means the Contact header IP/port doesn't match the actual packet source. This is a common cause of one-way audio and call setup failures behind NAT -- combine with the `one_way` field to catch the classic case.

### High jitter or packet loss

```bash
sipnab -N -I capture.pcap --filter "rtp.jitter > 50.0 OR rtp.loss > 1.0" --json
```

Jitter arrives in milliseconds (RFC 3550 interarrival jitter algorithm), and high values indicate network congestion. Loss is a percentage (0.0-100.0) whose acceptable thresholds are codec-dependent.

### Failed international calls

```bash
sipnab -N -I capture.pcap --filter "from.user =~ '^\+' AND (state == 'Failed' OR state == 'Cancelled')" --json
```

The `^\+` regex matches E.164 formatted numbers (international prefix).

### Registration storms

```bash
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND retransmits > 5" --report
```

High retransmit counts on REGISTER indicate network issues, DNS failures, or server overload. Append `AND src.ip == '192.0.2.50'` to isolate a specific endpoint.

### Scanner activity

```bash
sipnab -N -I capture.pcap --filter "ua =~ 'sipvicious|friendly-scanner|sipcli'" --json
```

### Short completed calls (possible robocalls)

```bash
sipnab -N -I capture.pcap --filter "duration < 5.0 AND state == 'Completed' AND method == 'INVITE'" --json
```

### SIP trunk failures

```bash
sipnab -N -I capture.pcap --filter "dst.ip == '198.51.100.100' AND state == 'Failed' AND method == 'INVITE'" --report
```

Filter for failures targeting a specific SIP trunk IP.

### Orphaned RTP streams

```bash
sipnab -N -I capture.pcap --filter "rtp.orphaned == true" --json
```

Orphaned streams have no matching SIP dialog/SDP. This often indicates RTP arriving on unexpected ports (check your NAT/ALG config) or calls that started before capture began.

### Track one user's packet loss (B2BUA debugging)

```bash
sipnab -N -I capture.pcap --filter "(from.user == '1001' OR to.user == '1001') AND rtp.loss > 0.5" --report
```

Tracks a specific user's calls that have packet loss, regardless of call direction.

### Chatty dialogs (debugging retransmissions)

```bash
sipnab -N -I capture.pcap --filter "msg_count > 20 AND method == 'INVITE'" --json
```

Dialogs with many messages often indicate retransmission issues or complex call flows (transfers, re-INVITEs).

### Stream investigation by codec or SSRC

Select every dialog carrying one codec, for codec-specific quality analysis:

```bash
sipnab -N -I capture.pcap --filter "rtp.codec == 'PCMU'" --json
```

Trace a single media stream by its SSRC. `rtp.ssrc` compares against the SSRC
rendered as `0x`-prefixed lowercase hex, so the literal needs the `0x` prefix or
it matches nothing:

```bash
sipnab -N -I capture.pcap --filter "rtp.ssrc == '0x12345678'" --json
```

### RTCP extended reports

When RTCP XR (PT=207) is present in the capture, sipnab extracts VoIP Metrics (RFC 3611 Section 4.7) including:
- Round-trip delay, end-system delay
- Signal/noise levels
- R-factor, external R-factor
- MOS-LQ, MOS-CQ
- Burst/gap loss metrics

These metrics appear in the call flow detail panel and in JSON/report output, augmenting the RTP-derived MOS calculation with endpoint-reported quality data.

## Parser constraints

- Maximum parenthesis nesting depth: **50 levels**
- Maximum regex pattern size: **1 MB** (1,000,000 bytes)
- Empty expressions produce a parse error
- Trailing unparsed input produces a parse error with position
- Unknown field names produce a parse error
- Invalid regex patterns produce a parse error

## See also

- [cli-reference.md](cli-reference.md) — the `--filter` flag and the
  dedicated diagnostic-alias flags
- [keybindings.md](keybindings.md) — the TUI filter dialog (F7), which
  compiles its fields down to this DSL
- [examples.md](examples.md) — recipes that put these filters to work
