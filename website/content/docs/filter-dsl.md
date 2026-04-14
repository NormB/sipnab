+++
title = "Filter DSL"
description = "sipnab filter DSL reference: grammar, fields, operators, named aliases, and example queries."
weight = 5

[extra]
weight = 5
+++

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

All 24 addressable fields, organized by type.

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

## Values

| Syntax | Type | Examples |
|--------|------|---------|
| `'...'` or `"..."` | String | `'INVITE'`, `"alice"` |
| Number | Numeric (f64) | `3.0`, `100`, `0.5` |
| `true` / `false` | Boolean (case-insensitive) | `true`, `FALSE` |
| `'...'` with `=~` | Regex | `'friendly.*scanner'`, `'^1001'` |

## Boolean Combinators

| Keyword | Description |
|---------|-------------|
| `AND` | Both sides must match (case-insensitive) |
| `OR` | Either side must match (case-insensitive) |
| `NOT` | Negates the following atom (case-insensitive) |

Parentheses `( )` group sub-expressions to override default precedence.

## Named Aliases

These preset expressions are available as CLI flags (`--problems`, etc.) and expand to DSL expressions internally.

| Alias | CLI Flag | Expansion |
|-------|----------|-----------|
| `problems` | `--problems` | `state == 'Failed' OR one_way == true OR rtp.loss > 2.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 32.0 OR rtp.orphaned == true` |
| `slow-setup` | `--slow-setup` | `pdd > 3.0` |
| `short-calls` | `--short-calls` | `duration < 5.0 AND state == 'Completed'` |
| `one-way` | `--one-way` | `one_way == true` |
| `nat-issues` | `--nat-issues` | `nat_mismatch == true` |

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

## Parser Constraints

- Maximum parenthesis nesting depth: **50 levels**
- Maximum regex pattern size: **1 MB** (1,000,000 bytes)
- Empty expressions produce a parse error
- Trailing unparsed input produces a parse error with position
- Unknown field names produce a parse error
- Invalid regex patterns produce a parse error
