# MCP tool reference: relay bundle

The `relay` bundle puts questions to the configured media relay and decodes
the relay control messages sipnab captured.

Load only these tools with `--mcp-tools relay`, or combine bundles as
[Choosing which tools load](mcp-tools.md#choosing-which-tools-load) describes.
Every tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.
[Ask a media relay about itself](relay-statistics.md#let-an-agent-ask) shows
the three tools that transmit in use, with the server they need.

| Tool | Parameters | Returns |
|---|---|---|
| [`decode_ng`](#decode_ng) | `frame_ref` | Decodes the relay control message one pointer names: the command, the call, whether it carries SDP, and which delivery path carried it |
| [`query_relay`](#query_relay) | `call_id?`, `max_calls?`, `sessions?`, `scan?` | **Transmits.** Asks the configured relay what it holds right now, or with `sessions` whether media reaches it per call and direction. Needs `--mcp-allow-relay-query` and a live source; the destination comes from operator configuration only |
| [`relay_stats`](#relay_stats) | `call_id?`, `names_only?` | **Transmits.** Asks the configured relay for its own counters (global, per-call, or the names it knows), tiered `relay_reported`. Same opt-in and live-source gate as `query_relay` |
| [`relay_stats_polled`](#relay_stats_polled) | -- | The newest reading of the relay's own counters that this run's `--relay-stats-interval` poll obtained, with its age. Sends nothing; needs no opt-in |
| [`relay_compare`](#relay_compare) | `call_id` | **Transmits.** Sets the relay's per-call RTP count beside sipnab's measured count, both tiers named and a word verdict, never a sum. Same gate as `query_relay` |


## Evidence and provenance

Every finding a tool reports points back at captured bytes. These retrieve those bytes, prove which frame they came from, and package them so someone else can check the work.

### `decode_ng`

**Parameters:** `frame_ref` (string, required) — one frame pointer, in the
`<source>#<ordinal>@<digest>` form the query tools emit.

`decode_evidence` decodes a SIP frame. This decodes a relay control message,
and adds the question no other surface answers: **which path carried it, and did
that path authenticate whoever sent it.**

That distinction decides what the message is worth. Anything on the segment can put a
control message on the HEP port, and landing there is the whole reason sipnab
credits it -- whereupon it names a call and binds media to an address its sender
chose. One delivered to an
HMAC-authenticated listener is a different claim entirely. Both decode to the
same bytes.

`delivery` is `hep` or `sniffed-udp`. `delivery_trust` uses the same scale as
[`explain_attribution`](mcp-tools-media.md#explain_attribution), and here it is
always `port-gated-only`. `decode_ng` reads the frame back out of a capture file: no HEP
listener on this run admitted it, and `decode_ng` does not verify a shared
secret or HMAC token, so `--hep-auth-mode` does not raise it. `on_believed_mirror_port` stands
apart because it is the ONLY reason anything believes a sniffed message at all,
and a reader should see the whole of that reason rather than its conclusion.

Status is `verified`, `unverified` or `unresolvable`, as in
[`decode_evidence`](mcp-tools-captures.md#decode_evidence), and a pointer leading nowhere returns
a reason rather than failing the call.

```jsonc
// decode_ng { "frame_ref": "relay.pcap#412@9f2c1a" }
{
  "pointer": "relay.pcap#412@9f2c1a",
  "status": "verified",
  "source": "relay.pcap",
  "ordinal": 412,
  "delivery": "hep",
  "delivery_trust": "port-gated-only",
  "delivery_note": "accepted because it arrived on the expected port and for no other reason: the source is not authenticated",
  "on_believed_mirror_port": true,
  "command": "offer",
  "call_id": "call-2c9d47@192.0.2.10",
  "has_sdp": true,
  "sdp_bytes": 231,
  "schema_version": 1
}
```


## Capture control (opt-in, off by default)

The tools that change server state rather than read it. Every one stays off until you turn it on server-side.

### `query_relay`

**This tool transmits, as `relay_stats` and `relay_compare` do.** Every other
tool answers from bytes sipnab already holds. These three put a packet on the
network.

It closes a gap a passive decoder cannot. A call already in progress when
sipnab started has no control exchange left to read, so the relay's own view is
the only way to learn which ports belong to it -- and incident response usually
begins mid-call, which is exactly when that gap is worst.

The tool needs three things, and says which one is missing:

| requirement | why |
|---|---|
| `--mcp-allow-relay-query` | transmitting is a larger act than reading, so an operator opts in |
| the relay control flag | names which relay to ask |
| a live source | a run reading a file can obtain no transmit permit |

**There is no address parameter, deliberately.** The destination comes from
operator configuration and from nowhere else. A tool argument naming the
destination would turn this surface into a way to make sipnab send packets to a
host the caller chose, and an address sipnab could otherwise infer is one it
learned from packets -- a host that served as a relay during the capture, and
may be somebody's laptop now.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id?` | string? | One Call-ID to ask the relay about. | **Switches modes** — the tool enumerates what the relay holds. |
| `max_calls?` | u32? | Enumeration and sessions. A cap on the Call-IDs the relay returns, and on the calls a sessions scan queries, the selected `call_id` included. 1 to 1024. Above 1024, sipnab asks for 1024 and the answer carries `cap_clamped`. sipnab refuses 0 with `invalid_params`. A query about one `call_id` ignores it. | The operator's `--relay-holdings-max`, or 32. |
| `sessions?` | bool? | `true` returns the sessions snapshot: `list`, then `query` for `call_id` and, with `scan`, for the held calls, each direction with a verdict. | The tool answers as before. |
| `scan?` | bool? | With `sessions`, `true` queries every held call too, up to `max_calls`. | The tool asks about `call_id` alone. |

`max_calls` takes its name from what it bounds rather than from `limit`,
because it is the relay's own `list` argument traveling to another process
rather than a page over data sipnab holds. rtpengine warns that raising it may push the answer past
one UDP datagram, and sipnab reports a truncated answer rather than padding it.

Omit `call_id` to enumerate. `truncated` reports that the relay held more than
it returned, because "the relay holds these 32 calls" and "the relay returned
the first 32 of an unknown number" are different statements.

`max_calls` follows the rule every surface follows, in
[Choose how many held calls one ask covers](relay-statistics.md#choose-how-many-held-calls-one-ask-covers).
sipnab answers a request above 1024 for 1024, never refuses it, and says so:
`"cap_clamped": {"requested": 100000, "ceiling": 1024}` beside the
enumeration's `call_ids`, or inside `sessions` for a sessions answer.

When the relay gives no usable answer, the tool reports one of three classes,
the same ones `--relay-holdings` and `GET /v1/relay/holdings` report:

| class | what happened | what the tool returns |
|---|---|---|
| unreachable | asked, nothing came back (a timeout or a socket error) | an `internal_error` (-32603) whose message reads `relay (rtpengine at ADDR) did not answer (ERROR); asked, nothing came back.`, followed by what is not known |
| refused | the relay answered and declined | a success with `outcome: "refused"` and the relay's own words in `refusal` |
| suspect | a reply arrived that sipnab could not trust: a reply to another request, no cookie framing, not bencode, or missing what its answer needs | a success with `outcome: "suspect"` and a `detail` that reads `relay (rtpengine at ADDR): REASON; the reply was discarded and not read` |

`relay_stats` and `relay_compare` report the same three classes the same way.

With `sessions: true` the answer is `asked: "sessions"`, `outcome: "sessions"`,
and a `sessions` field holding the snapshot `GET /v1/relay/sessions` returns,
without its `outcome`: per queried call, each party's direction with a
`verdict` of `never_received`, `stalled`, `flowing` or `not_reported`, the
relay's counters per socket, `sip_dialog`, and the held calls not queried in
`not_queried`. The fields are additive. Without `sessions` the answer stays
as before. The tool reports a `list` the relay did not answer in the three
classes above. [See whether media reaches the relay](relay-statistics.md#see-whether-media-reaches-the-relay)
shows a live answer.

```jsonc
// query_relay { "call_id": "call-2c9d47@192.0.2.10" }
{
  "asked": "query",
  "relay_address": "127.0.0.1:22222",
  "outcome": "call",
  "call_id": "call-2c9d47@192.0.2.10",
  "tags": [
    {
      "tag": "from-tag-9a1c",
      "in_dialogue_with": ["to-tag-4b7e"],
      "codec": "PCMU",
      "streams": [
        {
          "local_address": "192.0.2.10",
          "local_port": 30000,
          "endpoint": "198.51.100.4:16388",
          "is_rtcp": false,
          "ssrcs": [305419896]
        }
      ]
    }
  ],
  "delivery_trust": "asked",
  "delivery_note": "sipnab asked the relay over its control socket; no third party could answer",
  "schema_version": 1
}
```

### `relay_stats`

**Transmits, like [`query_relay`](#query_relay).** It asks the configured relay
for the statistics it keeps about ITSELF -- never a figure sipnab derived -- so
each value carries the tier `relay_reported` and never blends with what sipnab
measured. That comparison is [`relay_compare`](#relay_compare).

Three modes from two parameters:

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id?` | string? | One Call-ID, to scope the counters to that call. | The relay's own global counters. |
| `names_only?` | bool? | `true` returns the NAMES the relay knows, not their values -- "what can I even ask for", since the key set is version-specific. | `false`. A `call_id` overrides it. |

It needs the same three things `query_relay` does, and refuses identically when
one is missing: `--mcp-allow-relay-query`, a configured relay control address,
and a live source.

A relay that answers but declines -- a Call-ID it does not hold -- is a
**success** carrying `outcome: "refused"` and the relay's own words, not an
error: the relay answered, it just said no. A reply that arrived but that sipnab
could not trust is a success carrying `outcome: "suspect"` and a `detail`. An
unreachable relay is the error, because nothing is then known. These are the
classes [`query_relay`](#query_relay) reports.

```jsonc
// relay_stats { "call_id": "call-2c9d47@192.0.2.10" }
{
  "relay_address": "127.0.0.1:22222",
  "tier": "relay_reported",
  "outcome": "ok",
  "statistics": [
    { "name": "totals.RTP.packets", "value": "9000" },
    { "name": "totals.RTP.bytes", "value": "1440000" }
  ],
  "delivery_trust": "asked",
  "delivery_note": "sipnab asked the relay over its control socket; no third party could answer",
  "schema_version": 1
}
```

A `names_only` answer carries `names`, a `names_source` (`listed` when the relay
enumerated them, `probed` when they are the names that did not refuse) and a
`names_note` stating how sipnab determined the set -- so a probed set is never
read as a definitive enumeration.

### `relay_stats_polled`

**Sends nothing.** It returns the newest reading of the relay's global
counters that this run's own `--relay-stats-interval` poll obtained. Starting a
poll stays the operator's, on the command line: a poll is a standing
instruction to transmit, and an agent does not own the host it would transmit
from. Reading what the poll already obtained needs no `--mcp-allow-relay-query`.

It takes no parameters. `outcome` is one of three values:

- `ok`: the reading, with `relay`, `obtained_at`, `origin: "polled"`,
  `interval_secs`, `age_secs` (seconds since the relay answered),
  `statistics` with each value's tier, and `refusals`.
- `no_reading_yet`: the poll runs and has obtained nothing, with
  `interval_secs`.
- `not_polling`: this run does not poll, with a `detail` naming what starts
  one.

`last_poll` names the newest attempt (`unreachable` or `suspect`, with `at` and
`detail`) when it failed after the reading. An `age_secs` that keeps growing
beside a `last_poll` is a poll that has stopped getting answers.

```jsonc
// relay_stats_polled {}
{
  "age_secs": 3,
  "interval_secs": 5,
  "obtained_at": "2026-11-03T12:00:00Z",
  "origin": "polled",
  "outcome": "ok",
  "refusals": [],
  "relay": "rtpengine at 127.0.0.1:22222",
  "statistics": [
    { "name": "currentstatistics.sessionsown", "tier": "relay_reported", "value": "0" }
  ]
}
```

`GET /v1/relay/stats/polled` returns the same fields and values.
[Read the newest poll without asking again](relay-statistics.md#read-the-newest-poll-without-asking-again)
walks through it.

### `relay_compare`

**Transmits, like [`query_relay`](#query_relay).** It sets the relay's own RTP
packet count for one call beside the count sipnab measured from the packets it
captured. A comparison, never a sum: both figures travel with their tiers
(`relay_reported` and `sipnab_measured`), the verdict is a word, and it never
computes `relay - sipnab` as a value -- the two count different sockets over
different windows, so an ordinary gap is not a relay fault.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | The Call-ID to compare. | Required -- the call fails. |

Same opt-in and live-source gate as `relay_stats`. It reports an absent side as
absent, never coercing it to zero: a call the relay does not hold carries sipnab's
count and no relay figure (`outcome: "relay_does_not_hold_call"`), and a call
sipnab never captured carries the relay's figure and no measured one
(`outcome: "sipnab_has_no_rtp"`). Only when both sides produced a count -- a
real zero included -- are they compared.

```jsonc
// relay_compare { "call_id": "call-2c9d47@192.0.2.10" }
{
  "relay_address": "127.0.0.1:22222",
  "call_id": "call-2c9d47@192.0.2.10",
  "outcome": "compared",
  "relay_reported": { "value": 9000, "name": "totals.RTP.packets" },
  "sipnab_measured": 9000,
  "verdict": "match",
  "note": "the relay and sipnab agree at 9000 RTP packets",
  "delivery_trust": "asked",
  "delivery_note": "sipnab asked the relay over its control socket; no third party could answer",
  "schema_version": 1
}
```
