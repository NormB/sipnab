# Filter DSL reference

> **Quick start:** `sipnab -N -I capture.pcap --filter "state == 'Failed'"`
> shows the failed calls in a capture, and
> `sipnab -N -I capture.pcap --problems` sweeps for every kind of problem at
> once. Keep the `-N`: without it the TUI opens instead.

sipnab includes a declarative, non-Turing-complete filter language for matching SIP dialogs and their associated RTP streams. You pass expressions through the [`--filter` CLI flag](cli-reference.md#matching) or the `expression` key in the [`[filter]` config section](config-reference.md#filter). The [Diagnostic Aliases](cli-reference.md#diagnostic-aliases) CLI flags (`--problems`, `--slow-setup`, and so on) expand to the named aliases documented below.

## What a filter narrows

A filter selects **dialogs**, and every output that lists dialogs honors it:

- The per-message stream (the default output, `--json`, `-T`) emits only
  messages belonging to matching dialogs.
- `--json-dialogs` emits one line per matching dialog.
- `--report` prints only matching dialogs, and the RTP tables beneath the dialog
  table hold only the streams linked to them. With no filter it still lists
  every stream the capture holds, orphans included.
- `--call-report <CALL-ID>` is **not** narrowed: it names one call, and a lookup
  by name is not a listing.

The [`--since`/`--until` time window](cli-reference.md#scope-a-run-to-a-time-window)
joins the filter: the run's filter is `(<your filter>) AND time >= '<since>' AND
time < '<until>'`, and `--json-analyze` reports it in that form.

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

### Matching boolean fields

- `one_way == true`
- `nat_mismatch == true`
- `no_media == true`
- `codec_asymmetry == true`
- `late_media == true`

### Compound expressions

- `method == 'INVITE' AND rtp.mos < 3.0`
- `from.user =~ '^1001' AND state == 'Failed'`
- `pdd > 3.0 OR retransmits > 5`
- `NOT ua =~ 'friendly-scanner'`
- `(state == 'Failed' OR state == 'Canceled') AND duration < 1.0`

### Real-world diagnostic queries

The DSL has no comment syntax, so this page labels each query in prose — a `#`
line handed to `--filter` is a parse error, not a note.

- Find calls with poor quality from a specific extension: `from.user =~ '^1001' AND rtp.mos < 3.0`
- Find failed registrations from a subnet: `method == 'REGISTER' AND state == 'Failed' AND src.ip =~ '^198\.51\.100\.'`
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
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0 AND rtp.packets > 0 AND state == 'Completed'" --json
```

An unmeasured `rtp.mos` is unknown, and an unknown value matches no threshold
in either direction. A dialog that carried no RTP never matches
`rtp.mos < 3.0`, so `rtp.packets > 0` no longer guards against a `0.0`.

This page used to say the clause was mandatory, because a signaling-only
dialog reported `0.0` and satisfied the threshold. That was true before the
fix and is not true now.

The clause is still worth keeping for a different reason. It excludes calls
that carried too few packets for the E-model to mean anything, which is a
judgment about sample size rather than a guard against a phantom zero. To
select the calls that carry no media, write `rtp.packets == 0` or
`no_media == true` instead.

`state == 'Completed'` keeps only completed calls -- in-progress calls may not
have enough RTP data for an accurate MOS calculation.

MOS values follow the ITU-T G.107 E-model: 4.0+ is toll quality, 3.5-4.0 is
acceptable, below 3.0 is noticeable degradation.

### One-way audio

```bash
sipnab -N -I capture.pcap --filter "one_way == true AND duration > 10.0" --report
```

The duration check avoids false positives during early call setup when RTP hasn't started flowing yet. For calls where no RTP ever flowed at all, use `no_media == true` instead.

### NAT issues

```bash
sipnab -N -I capture.pcap --filter "nat_mismatch == true AND method == 'INVITE'" --json
```

NAT mismatch means RTP reached the capture point from an address that no SDP in
the dialog advertised, which is what a NAT rewriting the media source looks
like from the wire. It is a common cause of one-way audio and of call setup
failures behind NAT -- combine it with the `one_way` field to catch the classic
case.

### High jitter or packet loss

```bash
sipnab -N -I capture.pcap --filter "rtp.jitter > 50.0 OR rtp.loss > 1.0" --json
```

Jitter arrives in milliseconds ([RFC 3550](https://www.rfc-editor.org/rfc/rfc3550) interarrival jitter algorithm), and high values indicate network congestion. Loss is a percentage (0.0-100.0) whose acceptable thresholds are codec-dependent.

### Failed international calls

```bash
sipnab -N -I capture.pcap --filter "from.user =~ '^\+' AND (state == 'Failed' OR state == 'Canceled')" --json
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
sipnab -N -I capture.pcap --report
```

Orphaned streams have no matching SIP dialog or SDP, so no dialog filter can
select them and the DSL offers no field for them. The boolean-field note above
covers why `rtp.orphaned` is a parse error. The `--report`
output carries an "Orphaned Streams" section, and the [REST
API](rest-api.md#get-v1streams) answers the same question at
`/v1/streams?orphaned=true` when you run sipnab with `--api`. Orphans usually
mean RTP arriving on unexpected ports (check your NAT/ALG config) or calls that
started before capture began.

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

When a capture carries RTCP XR (PT=207), sipnab decodes the VoIP Metrics block
([RFC 3611](https://www.rfc-editor.org/rfc/rfc3611) Section 4.7) and keeps it beside the stream the block names:

- Round-trip delay and end-system delay
- Signal level, noise level and residual echo return loss
- R-factor and external R-factor
- MOS-LQ and MOS-CQ
- Burst and gap loss densities and durations
- Jitter buffer nominal, maximum and absolute maximum delay

**Every figure above belongs to the endpoint that sent it, not to sipnab.** The
TUI Stream Detail view shows them in a **Reported by Far End (RTCP XR)** section
of their own, below everything sipnab measured. Nothing there feeds the MOS,
jitter or loss sipnab computes. RTCP carries no authentication, and a mid-path
capture watches a different path segment than the endpoint reports on, so the
two disagreeing is the finding rather than a conflict to resolve. This is the
same rule the reception-report figures follow -- see
[mos-and-codecs.md](mos-and-codecs.md#mos-comes-from-what-sipnab-measured-never-from-what-the-far-end-claimed).

RFC 3611 reserves the value 127 for "this parameter is unavailable" on all
seven of its single-byte quality fields: the R-factor and the external
R-factor, both MOS fields, the signal and noise levels, and the residual echo
return loss. sipnab renders each of those as `n/a`. A raw render would put an R-factor of 127
on a scale that stops at 100, and a MOS of 12.7 on a scale that stops at 5.0.

No surface reads any other XR block type yet. The parser turns three of them
into typed values -- Loss RLE, Duplicate RLE and Receiver Reference Time -- and
records Packet Receipt Times, DLRR and Statistics Summary by block-type number
alone.

`--json`, `--report`, the REST API and the Prometheus exporter carry sipnab's own
measurements only. No filter DSL field matches an XR value.

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

All 42 addressable fields, organized by type. They answer to 43 names: `response_code` is also spelled `final_status_code`, and an alias is not a second field. Beyond these, `header.<name>` reads any SIP header by a name you choose. See [Any header by name](#any-header-by-name).

### String fields

| Field | Description | Example Values |
|-------|-------------|----------------|
| `from.user` | User part of the SIP From header | `"1001"`, `"alice"` |
| `to.user` | User part of the SIP To header | `"1002"`, `"bob"` |
| `from.host` | Host of the From URI, without the port | `"carrier-a.example"`, `"203.0.113.5"` |
| `to.host` | Host of the To URI, without the port | `"pbx.example"` |
| `from.uri` | The From URI as written, URI parameters included, without the display name or `tag` | `"sip:+15551230000@carrier-a.example;user=phone"` |
| `to.uri` | The To URI as written | `"sip:7000@pbx.example"` |
| `ruri` | Request-URI of the request that opened the dialog; empty when the capture began on a response | `"sip:7000@192.0.2.10"` |
| `pai.user` | User part of the opening request's P-Asserted-Identity; empty when it has none | `"+15559876543"` |
| `side` | Where the opening request went relative to the PBX addresses in [`[pbx] addresses`](config-reference.md#pbx): `inbound` (sent to the PBX), `outbound` (sent by it), `internal` (between two of its addresses), or empty | `"inbound"`, `"outbound"` |
| `endpoint` | The name the run gives the source or destination address, from the hosts file, `--names` files and `[names.manual]`; matches when either end's name matches. Reverse DNS is never used here | `"pbx-1"`, `"carrier-a-gw"` |
| `method` | SIP request method | `"INVITE"`, `"REGISTER"`, `"BYE"` |
| `ua` | User-Agent header (first non-empty across dialog messages) | `"Olle"`, `"friendly-scanner"` |
| `call_id` | SIP Call-ID header | `"abc123@host"` |
| `payload` | Raw message content — matches when ANY message in the dialog contains/matches the value (payload grep) | `"X-Custom-Header"`, `"sipsak"` |
| `src.ip` | Source IP address (first message) | `"192.0.2.1"` |
| `dst.ip` | Destination IP address (first message) | `"192.0.2.2"` |
| `state` | Dialog state machine value | `"Trying"`, `"InCall"`, `"Failed"` |
| `response_class` | IANA class of the final response | `"2xx"`, `"4xx"`, `"5xx"`, `"6xx"` |
| `rtp.codec` | RTP codec name (matches if ANY linked stream matches) | `"PCMU"`, `"opus"` |
| `rtp.codecs` | Every codec the dialog's streams used, distinct, sorted and comma-joined; empty with no streams | `"PCMU,telephone-event"` |
| `rtp.ssrc` | RTP SSRC in hex format (matches if ANY linked stream matches) | `"0x12345678"` |

**Valid `state` values:** `Trying`, `Ringing`, `InCall`, `Completed`, `Canceled`, `Failed`, `Redirected`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`

> **`payload` vs `-e`/`--match`:** the `payload` field matches per dialog (true
> if any message matches). The `-e`/`--match` flag is the
> per-message match-expression: it selects the matching messages and then
> *follows the dialog* — every message after the first match in that dialog is
> emitted too. Use `-e` for grep-style streaming output. Use `payload` inside a
> larger `--filter` expression.

### Numeric fields

| Field | Description | Unit |
|-------|-------------|------|
| `src.port` | Source port (first message) | port number |
| `dst.port` | Destination port (first message) | port number |
| `duration` | Dialog duration | seconds (float) |
| `msg_count` | Number of SIP messages in dialog | count |
| `response_code` | Final response code of the dialog's INVITE, or of the request that opened a dialog without one (`REGISTER`, `PUBLISH`, `SUBSCRIBE` …). Also spelled `final_status_code`, which is the name the JSON, the schema and the MCP answers return. Unknown while the call is in progress, so a ringing dialog matches no comparison at all | 100-699 |
| `pdd` | Post-dial delay (time to first ringing/response) | seconds (float) |
| `setup_time` | Call setup time (INVITE to 200 OK) | seconds (float) |
| `retransmits` | Total retransmit count in dialog | count |
| `rtp.mos` | Mean Opinion Score (worst across streams, E-model R-factor approximation) | 1.0 - 5.0, unknown with no RTP |
| `rtp.jitter` | Jitter (worst/highest across streams) | milliseconds, unknown with no RTP |
| `rtp.loss` | Packet loss (worst/highest across streams) | percentage (0-100), unknown with no RTP |
| `rtp.packets` | Total RTP packets (sum across all streams) | count (`0` is a real count, never unknown) |

> **An unmeasured value matches no comparison.** `pdd`, `setup_time`,
> `rtp.mos`, `rtp.jitter` and `rtp.loss` are unknown when the capture holds
> nothing to measure them from — no RTP for the media fields, no captured
> INVITE or 200 OK for the timing ones. An unknown matches no numeric operator,
> including `!=`: it is not "different from 3.0", it is unknown. This is the
> rule SQL uses for `NULL`, for the same reason.
>
> Reading them as `0` instead would put them below every threshold anyone
> would type, so `rtp.mos < 3.0` would select every call carrying no media at
> all: 2292 of 2311 dialogs on one real trunk capture, rather than the 2
> genuine ones. A saved filter carrying an `AND rtp.packets > 0` guard is
> redundant rather than wrong.
>
> To select the calls that carry no media, ask for that directly: `rtp.packets
> == 0` is a real count of zero, and `no_media` is the diagnosis itself.
> **Pair any `rtp.*` threshold with `rtp.packets > 0`** to ask about calls that
> actually had media.


### Asking by class

The [IANA registry](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-7)
groups every response code into six classes, and `response_class` is that
class. Ask by number or by the registry's own name — they mean the same thing:

| Class | Number | Name |
|---|---|---|
| Provisional | `1xx` | `provisional` |
| Successful | `2xx` | `successful`, `success` |
| Redirection | `3xx` | `redirection`, `redirect` |
| Request Failure | `4xx` | `request failure`, `client failure` |
| Server Failure | `5xx` | `server failure` |
| Global Failures | `6xx` | `global failures`, `global failure` |

```bash
sipnab -N -I capture.pcap --filter "response_class == 'server failure'"
```

**`failure` means all three failure classes** — 4xx, 5xx and 6xx together —
because that is what the word means at a console. `failures` and `failed` are
the same question. Naming one class is how you ask for one class:

```bash
sipnab -N -I capture.pcap --filter "response_class == 'failure'"
```

Matching is membership, not string equality, so `!=` stays honest: a 503 is a
server failure by every spelling, and `response_class != 'Server Failure'` is
false for it. Case, hyphens and underscores are typing variants, not different
questions.

`response_code >= 500 AND response_code < 600` says the same as `'5xx'`, and
says it as arithmetic. A bound wrong by one is silent.

**A dialog is never `1xx`, and that is not an omission.** This is the class of
the FINAL response, and a provisional one is by definition not final — a call
sitting on 183 has no outcome yet, so it has no class at all, the same as a
call that has heard nothing. Reach for `state` there instead.

**This is not the classification on the
[response-code reference](sip-response-codes.md).** That page groups codes by
what they mean for a CALL, and it is narrower: there a challenge, a
cancellation and a decline are each *not* failures, because each tells the
operator to do something different. `response_class` is the numeric registry
and nothing else. Neither one borrows the other's name, deliberately.

### Why `response_code` and not just `state`

`state` answers what happened. `response_code` answers why, and they are not
the same question. Every one of 403, 404, 408, 486, 503 and 603 is
`state == 'Failed'`, and they have different owners: a 403 is authorization, a
408 is a timer, a 486 is the callee, a 503 is capacity upstream.

Asking "which
release cause dominates on this trunk in the last ten minutes" needs the code,
and asking it by class needs a numeric field rather than a set of names:

Every server-side failure, whatever the specific cause:

```bash
sipnab -N -I capture.pcap --filter "response_code >= 500 AND response_code < 600"
```

The one cause you suspect, on the carrier you suspect:

```bash
sipnab -N -I capture.pcap --filter "response_code == 503 AND dst.ip == '198.51.100.7'"
```

A call still in progress has no final response. It matches NOTHING -- not
`response_code < 400`, not `>= 400`, not `== 0` -- because a zero default would
sweep every ringing call into the success bucket.

Auth challenges follow
[`final_status_code`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs):
a call challenged and then answered reports 200, not the 407, because the
challenge was intermediate. A call only ever challenged reports the challenge,
because then it was the outcome.

### Boolean fields

| Field | Description |
|-------|-------------|
| `one_way` | True if one-way audio detected (via diagnosis engine) |
| `nat_mismatch` | True if RTP arrived from an address no SDP in the dialog advertised — see the note below |
| `no_media` | True if an answered call negotiated media that never arrived — see the note below |
| `codec_asymmetry` | True if A and B legs negotiated different RTP codecs |
| `ptime_asymmetry` | True if the two legs use different `ptime` (packetization interval) |
| `payload_asymmetry` | True if dynamic payload type numbers differ across legs (with the same codec) |
| `duration_asymmetry` | True if one leg's media duration is materially shorter than the other's |
| `late_media` | True if RTP starts noticeably later than the answering 200 OK |

> **What `nat_mismatch` compares.** A dialog advertises a media address on each
> side — the caller's in the offer, the callee's in the answer — and a
> re-INVITE may add more. `nat_mismatch` is true when a stream carries a source
> address that **none** of them named.
>
> Set membership, not equality against one
> `c=` line: a healthy two-way call sources RTP from two different advertised
> addresses, so comparing each stream against a single `c=` would flag one
> direction of every call in the capture. Addresses only, never ports, because
> NAT and RTP proxies rewrite the port on ordinary calls without breaking
> anything.
>
> **What `no_media` requires.** All four: the far end answered an offer, the
> dialog reached a 2xx, at least one exchange described media that should carry
> audio, and no RTP arrived for the call. "Should carry audio" excludes the
> forms that ask for silence —
> `a=inactive`, `m=` port `0`, a black-holed `c=0.0.0.0`, and non-RTP transports
> such as T.38 `m=image ... udptl` — so a call held for its whole life is not
> reported as a media failure.
>
> **`no_media` is silent on a capture that holds no RTP.** A signaling-only
> tap, a HEP feed or `--no-rtp` cannot show that one call had no audio, because
> no call in it has any. On such a capture the flag stays false by design rather
> than selecting every answered dialog. Pair `no_media` with the knowledge of
> where your tap sits: if media does not traverse it, the question is
> unanswerable and sipnab declines to answer it.
>
> **`rtp.orphaned` is a parse error, not a field.** It would ask whether a
> stream *belonging to this dialog* belongs to no dialog: a stream counts as an
> orphan exactly when no dialog claims it, so the two halves exclude each other
> and the field matches nothing on any capture while `NOT rtp.orphaned` matches
> everything. Rejecting it at the parser beats a silent falsehood.
>
> Orphaned media is real and still reachable: read the "Orphaned Streams" section of
> `--report`, or the REST API's `/v1/streams?orphaned=true`, both of which model
> streams rather than dialogs.

### Time field

| Field | Description | Value |
|-------|-------------|-------|
| `time` | The instant of the dialog's first message | a quoted [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) instant, such as `'2026-10-09T10:00:00Z'` |

`time` takes `<`, `<=`, `>`, `>=` and `==`, and nothing else: `!=`, `=~` and
`in_subnet` are parse errors, and so is a literal that is not a quoted RFC 3339
instant. sipnab converts an offset other than `Z`, so `'2026-10-09T12:00:00+02:00'`
is the same instant as `'2026-10-09T10:00:00Z'`.

It is the instant the REST `/v1/dialogs` `after`/`before` window, the MCP
`search_by_time` tool and the `--since`/`--until` flags bound. Write a window
half-open, `>=` at the start and `<` at the end, to select what those select:

```text
time >= '2026-10-09T10:00:00Z' AND time < '2026-10-09T11:00:00Z'
```

### Named filters

Define a filter once in the config file's [`[filters]`](config-reference.md#filters)
table and use it by name, as `@name`, wherever sipnab takes a filter
expression. A name can appear inside a larger expression and inside another
named filter, and an expression can reference the built-in aliases the same way:

```toml
[filters]
carrier-a = "src.ip in_subnet '203.0.113.0/24'"
sales     = "@carrier-a AND to.user =~ '^8[0-9]{3}$'"
bad-sales = "@sales AND @problems"
```

```bash
sipnab -N -I capture.pcap --config sipnab.toml --filter "@sales AND method == 'INVITE'"
```

sipnab replaces `@name` with the named filter's expression in parentheses, so
each definition keeps the precedence it has as written. An `@` inside a
quoted string is text, not a reference. sipnab resolves every name when it
starts. See [`[filters]`](config-reference.md#filters) for what it refuses.
sipnab refuses a filter given at run time that names something undefined, on
the command line or through REST or MCP, and lists the defined names.

### Any header by name

`header.<name>` compares the value of a SIP header you name, as a string. It
matches when any header of that name, on any message sipnab holds for the
dialog, satisfies the comparison. sipnab compares a header that appears on
several lines one line at a time, matches header names without regard to
case, and expands a compact form first, so `header.f` reads `From`.

```text
header.X-Trunk == 'north-east'
header."P-Asserted-Identity" =~ 'sip:alice@'
```

Write the name bare, or in quotes when it holds a character that would end a
bare name. Either way it must be an [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
token of at most 256 bytes (see [Parser constraints](#parser-constraints)).

## Operators

| Operator | Applies To | Description |
|----------|------------|-------------|
| `==` | string, numeric, boolean, `time` | Equal |
| `!=` | string, numeric, boolean | Not equal |
| `<` | string, numeric, `time` | Less than (for `time`, earlier) |
| `>` | string, numeric, `time` | Greater than (for `time`, later) |
| `<=` | string, numeric, `time` | Less than or equal |
| `>=` | string, numeric, `time` | Greater than or equal |
| `=~` | string | Regex match (Rust regex syntax) |
| `in_subnet` | address-valued string | The left address falls inside the right CIDR block |

Notes:
- Boolean fields only support `==` and `!=`.
- Regex (`=~`) is not applicable to numeric or boolean fields.
- `in_subnet` takes a CIDR literal on the right and an address-valued field on the left (`src.ip`, `dst.ip`). It uses the same rule as `--hep-allow`, so IPv4, IPv6 and IPv4-mapped IPv6 addresses ([RFC 4291 section 2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2)) all compare as the allowlist compares them, and a bare address with no prefix reads as a host route. An unparseable address or block matches nothing rather than matching everything.
- Numeric equality uses epsilon comparison for floating-point precision. For computed values (`duration`, `pdd`, `rtp.mos`) prefer range operators (`>=`, `<`) over `==` — an exact match on a derived float rarely hits.

> **Note:** String comparisons are case-sensitive. `state` values must exactly match one of the 13 values listed under [String Fields](#string-fields) above (`'Failed'`, not `'failed'`). Use `=~` with a case-insensitive regex pattern if you need case-insensitive matching: `state =~ '(?i)failed'`.

## Values

| Syntax | Type | Examples |
|--------|------|---------|
| `'...'` or `"..."` | String | `'INVITE'`, `"alice"` |
| Number | Numeric (f64) | `3.0`, `100`, `0.5` |
| `true` / `false` | Boolean (case-insensitive) | `true`, `FALSE` |
| `'...'` with `=~` | Regex | `'friendly.*scanner'`, `'^1001'` |
| `'...'` after `time` | RFC 3339 instant | `'2026-10-09T10:00:00Z'`, `'2026-10-09T12:00:00+02:00'` |

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
as the value of any MCP tool's `filter` argument, as the value of the REST API's
[`filter` query parameter](rest-api.md#get-v1dialogs) (e.g.
`/v1/dialogs?filter=codec-asym`), and as `kinds` entries for the MCP
[`find_problems`](mcp-tools-core.md#find_problems) tool. They expand to DSL
expressions internally, through one function, with the thresholds the run's
flags and config set.

| Alias | Dedicated CLI Flag | Expansion |
|-------|--------------------|-----------|
| `problems` | `--problems` | `state == 'Failed' OR one_way == true OR rtp.loss > 5.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 11.0 OR codec_asymmetry == true OR ptime_asymmetry == true OR payload_asymmetry == true OR duration_asymmetry == true OR late_media == true` |
| `slow-setup` | `--slow-setup` | `pdd > 11.0` |
| `short-calls` | `--short-calls` | `duration < 3.0 AND state == 'Completed'` |
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

The dedicated flag, the `--filter <alias>` spelling and the MCP `kinds` entry
are three names for one expression: `sipnab --short-calls`,
`sipnab --filter short-calls` and
`sipnab --filter "duration < 3.0 AND state == 'Completed'"` all select the same
dialogs. Combining several flags ORs their expansions together. If `--filter`
is also present, its expression is ANDed with that result. For example,
`--problems --filter "from.user == '1001'"` keeps problem calls from user 1001.

`--nat-issues` / `--filter nat-issues` selects the calls whose RTP arrived from
an address the SDP never advertised. The boolean-field note above says what that
means and what it deliberately ignores.

## Parser constraints


- **Expression nodes: 1024** (`MAX_EXPRESSION_NODES`). The bound a caller is
  most likely to reach, and the reason it exists is not tidiness: without it a
  deeply repetitive expression drove the parser into a stack overflow that
  aborts the process rather than returning an error. A filter over the cap is
  refused by `validate_filter` and by every flag that takes one.
- Maximum parenthesis nesting depth: **50 levels** (`MAX_NESTING_DEPTH`).
  It bounds recursion in the parser itself. How large the resulting tree may
  grow is the separate node bound above.
- **Header name length: 256 bytes** (`MAX_HEADER_NAME_LEN`), for the
  `header.<name>` field. Whoever sent the message chose the header name, so
  sipnab bounds the field that names one like every other input.
  `FilterExpr::parse` refuses a longer name and states the limit.
- Maximum regex pattern size: **1 MB** (1,000,000 bytes)
- Empty expressions produce a parse error
- Trailing unparsed input produces a parse error with position
- Unknown field names produce a parse error
- Invalid regex patterns produce a parse error

## See also

- [cli-reference.md](cli-reference.md) — the `--filter` flag and the
  dedicated diagnostic-alias flags
- [keybindings.md](keybindings.md#filter-dialog-f7) — the TUI filter dialog (F7), which
  compiles its fields down to this DSL
- [examples.md](examples.md) — recipes that put these filters to work
