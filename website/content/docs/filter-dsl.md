+++
title = "Filter DSL"
weight = 5
description = "Declarative filter language for matching SIP dialogs and RTP streams."
+++

> **Quick start:** `sipnab --filter "state == 'Failed'"` to find all failed calls, or `sipnab --problems` for a one-flag diagnostic sweep.

sipnab includes a declarative, non-Turing-complete filter language for matching SIP dialogs and their associated RTP streams. Expressions are passed via the `--filter` CLI flag or the `expression` key in the `[filter]` config section.

## Grammar

```
expr        = or_expr
or_expr     = and_expr ("OR" and_expr)*
and_expr    = not_expr ("AND" not_expr)*
not_expr    = "NOT" atom | atom
atom        = comparison | "(" expr ")"
comparison  = field operator value
```

Operator precedence (highest to lowest): `NOT`, `AND`, `OR`. Use parentheses to override.

## Fields

All 30 addressable fields, organized by type.

### String Fields

| Field | Description | Example Values |
|-------|-------------|----------------|
| `from.user` | User part of the SIP From header | `"1001"`, `"alice"` |
| `to.user` | User part of the SIP To header | `"1002"`, `"bob"` |
| `method` | SIP request method | `"INVITE"`, `"REGISTER"`, `"BYE"` |
| `ua` | User-Agent header (first non-empty across dialog messages) | `"Olle"`, `"friendly-scanner"` |
| `call_id` | SIP Call-ID header | `"abc123@host"` |
| `src.ip` | Source IP address (first message) | `"10.0.0.1"` |
| `dst.ip` | Destination IP address (first message) | `"10.0.0.2"` |
| `state` | Dialog state machine value | `"Trying"`, `"InCall"`, `"Failed"` |
| `rtp.codec` | RTP codec name (first stream) | `"PCMU"`, `"opus"` |
| `rtp.ssrc` | RTP SSRC in hex format (first stream) | `"0x12345678"` |

**Valid `state` values:** `Trying`, `Ringing`, `InCall`, `Completed`, `Cancelled`, `Failed`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`

### Numeric Fields

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

### Boolean Fields

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
- Numeric equality uses epsilon comparison for floating-point precision.

> **Note:** String comparisons are case-sensitive. State values must match exactly: `'Completed'`, `'Failed'`, `'Trying'`, `'Ringing'`, `'InCall'`, `'Cancelled'`, `'Terminated'`. Use `=~` with a case-insensitive regex pattern if you need case-insensitive matching: `state =~ '(?i)failed'`.

## Values

| Syntax | Type | Examples |
|--------|------|---------|
| `'...'` or `"..."` | String | `'INVITE'`, `"alice"` |
| Number | Numeric (f64) | `3.0`, `100`, `0.5` |
| `true` / `false` | Boolean (case-insensitive) | `true`, `FALSE` |
| `'...'` with `=~` | Regex | `'friendly.*scanner'`, `'^1001'` |

> **Tip:** Regex patterns are compiled once and reused across all messages. Avoid unbounded quantifiers on large captures (e.g., prefer `from.user =~ '^100[0-9]$'` over `from.user =~ '.*100[0-9].*'`).

## Boolean Combinators

| Keyword | Description |
|---------|-------------|
| `AND` | Both sides must match (case-insensitive) |
| `OR` | Either side must match (case-insensitive) |
| `NOT` | Negates the following atom (case-insensitive) |

Parentheses `( )` group sub-expressions to override default precedence.

## Named Aliases

These preset expressions are available as CLI flags (`--problems`, etc.) and expand to DSL expressions internally.

Aliases are accepted by `--filter` directly (`--filter codec-asym`), as
dedicated CLI flags where they exist (`--problems`, etc.), and as `kinds`
entries in the MCP `find_problems` tool.

| Alias | Dedicated CLI Flag | Expansion |
|-------|--------------------|-----------|
| `problems` | `--problems` | `state == 'Failed' OR one_way == true OR rtp.loss > 2.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 32.0 OR rtp.orphaned == true` |
| `slow-setup` | `--slow-setup` | `pdd > 3.0` |
| `short-calls` | `--short-calls` | `duration < 5.0 AND state == 'Completed'` |
| `one-way` | `--one-way` | `one_way == true` |
| `nat-issues` | `--nat-issues` | `nat_mismatch == true` |
| `codec-asym` | — (use `--filter codec-asym`) | `codec_asymmetry == true` |
| `ptime-asym` | — (use `--filter ptime-asym`) | `ptime_asymmetry == true` |
| `payload-asym` | — (use `--filter payload-asym`) | `payload_asymmetry == true` |
| `duration-asym` | — (use `--filter duration-asym`) | `duration_asymmetry == true` |
| `late-media` | — (use `--filter late-media`) | `late_media == true` |

`--filter` first tries to resolve its argument as an alias name, then falls
back to parsing it as a DSL expression. Both forms below are equivalent:

```
sipnab -N -I capture.pcap --filter codec-asym
sipnab -N -I capture.pcap --filter "codec_asymmetry == true"
```

## Examples

### Basic field matching

```
method == 'INVITE'
from.user == '1001'
state == 'InCall'
```

### Regex matching

```
ua =~ 'friendly-scanner'
from.user =~ '^100[0-9]'
call_id =~ 'abc.*@'
```

### Numeric comparisons

```
pdd > 3.0
rtp.mos < 3.0
rtp.loss > 2.0
duration < 5.0
retransmits > 3
rtp.jitter > 50.0
```

### Boolean fields

```
one_way == true
nat_mismatch == true
rtp.orphaned == true
no_media == true
```

### Compound expressions

```
method == 'INVITE' AND rtp.mos < 3.0
from.user =~ '^1001' AND state == 'Failed'
pdd > 3.0 OR retransmits > 5
NOT ua =~ 'friendly-scanner'
(state == 'Failed' OR state == 'Cancelled') AND duration < 1.0
```

### Real-world diagnostic queries

```
# Find calls with poor quality from a specific extension
from.user =~ '^1001' AND rtp.mos < 3.0

# Find failed registrations from a subnet
method == 'REGISTER' AND state == 'Failed' AND src.ip =~ '^10\.0\.1\.'

# Find short calls that completed (possible robocalls)
duration < 5.0 AND state == 'Completed' AND method == 'INVITE'

# Find calls with audio issues
one_way == true OR no_media == true OR rtp.jitter > 100.0

# Find scanner activity by User-Agent
ua =~ 'sipvicious|friendly-scanner|sipcli'
```

## Real-World Scenarios

Scenario-based examples showing how to combine filter expressions with CLI flags for common operational tasks.

### Find calls with poor audio quality

```
rtp.mos < 3.0 AND state == 'Completed'
```

Only completed calls -- in-progress calls may not have enough RTP data for an accurate MOS calculation.

```bash
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0 AND state == 'Completed'" --json
```

### Find all failed international calls

```
from.user =~ '^\+' AND (state == 'Failed' OR state == 'Cancelled')
```

The `^\+` regex matches E.164 formatted numbers (international prefix).

### Find registration storms

```
method == 'REGISTER' AND retransmits > 5
```

High retransmit counts on REGISTER indicate network issues, DNS failures, or server overload. Combine with source IP filtering to isolate a specific endpoint:

```
method == 'REGISTER' AND retransmits > 5 AND src.ip == '10.0.0.50'
```

### Find calls with NAT issues

```
nat_mismatch == true AND method == 'INVITE'
```

NAT mismatch means the Contact header IP/port doesn't match the actual packet source. This is a common cause of one-way audio and call setup failures behind NAT.

### Find one-way audio after call establishment

```
one_way == true AND duration > 10.0
```

The duration check avoids false positives during early call setup when RTP hasn't started flowing yet.

### Complex B2BUA debugging

```
(from.user == '1001' OR to.user == '1001') AND rtp.loss > 1.0
```

Track a specific user's calls that have packet loss, regardless of call direction.

### Find chatty dialogs (debugging retransmissions)

```
msg_count > 20 AND method == 'INVITE'
```

Dialogs with many messages often indicate retransmission issues or complex call flows (transfers, re-INVITEs).

### Monitor for SIP trunk failures

```
dst.ip == '192.168.1.100' AND state == 'Failed' AND method == 'INVITE'
```

Filter for failures targeting a specific SIP trunk IP.

> **Note:** The filter DSL evaluates against dialogs, not individual messages. A filter like `method == 'INVITE'` matches dialogs that were initiated with an INVITE, including all subsequent messages in that dialog (180, 200, ACK, BYE, etc.).

## RTP Quality & Media Queries

The filter DSL provides direct access to RTP stream metrics. These fields query the aggregate quality of all RTP streams associated with a dialog.

### MOS-Based Quality Monitoring

```bash
# Find calls with MOS below carrier threshold
sipnab -N -I capture.pcap --filter "rtp.mos < 3.5" --json

# Find calls with excellent quality (verify your codecs are performing)
sipnab -N -I capture.pcap --filter "rtp.mos > 4.0 AND state == 'Completed'"

# Live alert: MOS drops below 3.0 on any active call
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0" --json | tee /var/log/sipnab/quality.ndjson
```

MOS values follow the ITU-T G.107 E-model: 4.0+ is toll quality, 3.5-4.0 is acceptable, below 3.0 is noticeable degradation.

### Jitter & Packet Loss

```bash
# High jitter (network congestion indicator)
sipnab -N -I capture.pcap --filter "rtp.jitter > 50.0" --json

# Packet loss above 1% (codec-dependent threshold)
sipnab -N -I capture.pcap --filter "rtp.loss > 1.0" --json

# Combined: calls where quality is degraded by both jitter AND loss
sipnab -N -I capture.pcap --filter "rtp.jitter > 30.0 AND rtp.loss > 0.5" --report
```

Jitter is reported in milliseconds (RFC 3550 interarrival jitter algorithm). Loss is a percentage (0.0–100.0).

### RTP Stream Investigation

```bash
# Find calls with orphaned RTP streams (no matching SDP)
sipnab -N -I capture.pcap --filter "rtp.orphaned == true" --json

# Filter by codec (useful for codec-specific quality analysis)
sipnab -N -I capture.pcap --filter "rtp.codec == 'PCMU'" --json

# Find calls with specific SSRC (trace a specific media stream)
sipnab -N -I capture.pcap --filter "rtp.ssrc == '12345678'" --json

# High packet count calls (long duration or high-rate codecs)
sipnab -N -I capture.pcap --filter "rtp.packets > 10000" --json
```

### One-Way Audio & Media Path Issues

```bash
# Detect one-way audio (one direction has zero RTP packets)
sipnab -N -I capture.pcap --filter "one_way == true" --json

# Calls with no media at all (SDP negotiated but no RTP ever flowed)
sipnab -N -I capture.pcap --filter "no_media == true" --json

# NAT mismatch + one-way audio (the classic NAT problem)
sipnab -N -I capture.pcap --filter "nat_mismatch == true AND one_way == true" --report

# One-way audio after call establishment (filter out early-media false positives)
sipnab -N -I capture.pcap --filter "one_way == true AND duration > 10.0" --json
```

### RTCP Extended Reports

When RTCP XR (PT=207) is present in the capture, sipnab extracts VoIP Metrics (RFC 3611 Section 4.7) including:
- Round-trip delay, end-system delay
- Signal/noise levels
- R-factor, external R-factor
- MOS-LQ, MOS-CQ
- Burst/gap loss metrics

These metrics appear in the call flow detail panel and in JSON/report output, augmenting the RTP-derived MOS calculation with endpoint-reported quality data.

### Combining RTP with SIP Filters

```bash
# Failed calls that also had quality issues (correlate signaling + media)
sipnab -N -I capture.pcap --filter "state == 'Failed' AND rtp.mos < 3.0" --json

# Calls from a specific user with packet loss
sipnab -N -I capture.pcap --filter "from.user == '1001' AND rtp.loss > 0.5" --report

# Trunk monitoring: all calls to a specific destination with quality metrics
sipnab -N -I capture.pcap --filter "dst.ip == '10.0.0.100' AND rtp.mos < 4.0" --json

# Registration + quality correlation (find endpoints with both reg and quality issues)
sipnab -N -I capture.pcap --filter "method == 'INVITE' AND retransmits > 3 AND rtp.jitter > 30"
```

## Parser Constraints

- Maximum parenthesis nesting depth: **50 levels**
- Maximum regex pattern size: **1 MB** (1,000,000 bytes)
- Empty expressions produce a parse error
- Trailing unparsed input produces a parse error with position
- Unknown field names produce a parse error
- Invalid regex patterns produce a parse error
