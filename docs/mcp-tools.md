# MCP tool reference

Every tool the MCP server exposes, what it answers, and what it returns.

This is lookup material, not reading material.

- [MCP server](mcp.md) — what MCP is, and a first working example.
- [MCP deployment](mcp-deploy.md) — the deployment shapes.
- [MCP protocol](mcp-protocol.md) — the wire contract, security model and error semantics.


The v0.5 sipnab MCP tool surface. No tool edits the analysis in place, and
every response carries a ceiling. That ceiling defaults to 1000 rows and is an
operator setting, not a build-time fact: `--mcp-max-rows N`, or `[limits]
mcp_max_rows` in the config file, with the flag winning. The right value
belongs to the consumer — a model with a small context window wants far fewer,
a batch client piping to a file wants far more. Note this is a DIFFERENT limit
from `dialog_limit`, which bounds dialogs tracked over the whole run and
defaults 100x higher. One tool replaces
the analysis outright — `open_capture`, off unless you enable it — and it mints
a new capture identity so the replacement cannot reach a consumer as an
ordinary update.

| Tool | Parameters | Returns |
|---|---|---|
| [`list_dialogs`](#list_dialogs) | `filter?`, `limit?`, `cursor?` | A page of dialog summaries, with the total behind it |
| [`get_dialog_report`](#get_dialog_report) | `call_id`, `format?` | Structured per-call report (JSON / Markdown / text) |
| [`aggregate_dialogs`](#aggregate_dialogs) | `group_by`, `filter?`, `top_n?` | Counts dialogs grouped by ONE field, in the store rather than in the model |
| [`get_capture_report`](#get_capture_report) | `format?` | Whole-capture analysis: findings, orphaned media, STUN/ICMP evidence, what the caps shed |
| [`find_problems`](#find_problems) | `kinds?`, `filter?`, `limit?`, `cursor?` | A page of dialogs matching one or more diagnostic alias names |
| [`get_dialog`](#get_dialog) | `call_id`, `max_messages?`, `cursor?` | Paginated dialog with full SIP messages |
| [`get_message`](#get_message) | `call_id`, `index` | Single SIP message at a given index |
| [`render_ladder`](#render_ladder) | `call_id`, `format?` | Call-flow ladder (Markdown / text) |
| [`rtp_stats`](#rtp_stats) | `call_id?`, `min_mos?`, `max_mos?`, `limit?`, `cursor?` | One call's RTP quality and diagnosis, or a capture-wide stream sweep |
| [`media_diagnostics`](#media_diagnostics) | `call_id` | The facts under the MOS: QoS marking, jitter grounding, delay provenance, silence, and what the far end reported |
| [`search_messages`](#search_messages) | `query`, `limit?`, `cursor?` | A page of substring matches across method/From/To/UA/body, with the total behind it |
| [`tail_dialogs`](#tail_dialogs) | `cursor?`, `limit?` | Cursor-based incremental dialog fetch |
| [`security_findings`](#security_findings) | `kinds?`, `since?`, `limit?` | Recent `scanner` / `fraud` / `digest` / `reg_flood` findings, plus the detectors this server runs |
| [`capture_status`](#capture_status) | -- | What this server captures: live or file, uptime, and whether stopping loses unsaved packets |
| [`capture_health`](#capture_health) | `sample_seconds` | Capture-path counters read twice: run totals, deltas across the window, `undecoded_fraction`, and undecodable frames by reason |
| [`triage_call`](#triage_call) | `call_id` | First-pass verdict: signaling problem, media problem, both, or none, with evidence |
| [`lint_dialog`](#lint_dialog) | `call_id`, `rulesets?`, `severity_min?`, `suppression_file?` | Conformance findings for one call, declaration against observation included, each with its RFC and section |
| [`validate_message`](#validate_message) | `call_id`, `index`, `suppression_file?` | Conformance findings for one message, read alone |
| [`explain_rule`](#explain_rule) | `rule_id` | The catalog entry behind one rule identifier: citation, basis, scope, selectors |
| [`show_evidence`](#show_evidence) | `refs`, `max_bytes?` | Follows frame pointers back to the captured bytes: verified, unverified, or unresolvable with a reason |
| [`check_codec_negotiation`](#check_codec_negotiation) | `call_id` | Codecs offered vs answered and whether they intersect — for 488s |
| [`diagnose_registration`](#diagnose_registration) | `call_id` | Whether an endpoint registered, hit a rejection, is looping on auth, or got a short expiry |
| [`explain_response_code`](#explain_response_code) | `code` | IANA registry meaning and class for a SIP status code |
| [`compare_dialogs`](#compare_dialogs) | `call_id_a`, `call_id_b` | Two calls side by side, with the differences named |
| [`find_correlated`](#find_correlated) | `call_id`, `limit?` | The other legs of the same call across a B2BUA, each with a score AND the strategy that matched it |
| [`get_sdp_timeline`](#get_sdp_timeline) | `call_id` | SDP offer/answer exchanges in order: codecs, ptime, direction |
| [`search_by_time`](#search_by_time) | `start`, `end?`, `filter?`, `limit?`, `cursor?` | Dialogs whose first message falls in an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) window |
| [`list_captures`](#list_captures) | -- | Capture files in `--mcp-file-root`, with sizes |
| [`export_capture`](#export_capture) | `filename` | Writes held SIP signaling to a pcap in `--mcp-file-root` (re-synthesised frames, no RTP) |
| [`export_audio`](#export_audio) | `call_id`, `filename` | Writes a call's RTP audio to a WAV in `--mcp-file-root`; needs the server started with `--retain-audio` |
| [`export_vcon`](#export_vcon) | `call_id` | One dialog as a vCon conversation container, structured JSON. Unsigned, retained audio inline, and it carries what the capture missed |
| [`shutdown_server`](#shutdown_server) | `dry_run?`, `save_to?`, `discard_unsaved?` | **Destructive.** Stops the process. Needs `--mcp-allow-shutdown`; dry-run by default |
| [`open_capture`](#open_capture) | `filename` | **Destructive.** Replaces every dialog and stream with another capture from `--mcp-file-root`. Needs `--mcp-allow-open-capture`; loads in the background |
| [`save_findings`](#save_findings) | `summary`, `call_id?`, `detail?` | **Write.** Records the agent's conclusion to sipnab's log. Needs `--mcp-allow-save-findings`; no tool reads it back |
| [`server_capabilities`](#server_capabilities) | -- | sipnab version and the optional features this binary carries |
| [`list_tls_libraries`](#list_tls_libraries) | -- | which TLS libraries this host runs, and whether sipnab could read their plaintext without keys |
| [`start_tls_capture`](#start_tls_capture) | `flavors`, `libraries` | installs kernel uprobes and reads SIP plaintext with no key; needs `--mcp-allow-tls-capture` |
| [`stop_tls_capture`](#stop_tls_capture) | -- | stops that capture and removes its kernel probes |

### Rules every tool follows

Five rules hold across the whole surface. Each tool section below states only
what it does differently, so read these once and skip them afterwards.

**A required parameter has no default.** Leave one out, or send the wrong JSON
type, and the call fails with `invalid_params` (-32602) before the tool runs.
Optional parameters carry a `?` in every table on this page, and each row says
what the tool does when you omit that one.

**A `limit` of `0` means the default, not "no rows".** `limit` defaults to 50
everywhere it appears. The server clamps anything larger to `--mcp-max-rows`
(1000 unless the operator lowered it) and returns the clamped page without an
error. Both edges bite the same caller: a client that computes `limit` from
"rows I still want" asks for 50 when it meant to ask for none, and a client
that asks for 5000 to "get everything" receives 1000 and no complaint. Read
`returned` rather than the length you asked for.

**Pass a cursor back exactly as it arrived.** `next_cursor` pairs a timestamp
with an identity — `<RFC 3339>|<Call-ID>` for dialogs, and
`<RFC 3339>|0xSSRC@src>dst` for the `rtp_stats` sweep. A hand-rebuilt bare
timestamp still parses, so rebuilding one costs rows instead of raising an
error. `next_cursor: null` marks the final page.

**Every list-style tool answers with a page object, never a bare array.** The
rows sit under a named key — `dialogs`, `hits`, `streams`, `findings` — beside
`returned` and `total_matched`, so counting the rows is never necessary and
never right. `search_messages` and `security_findings` carry the
page fields too. `tail_dialogs` is the one page object with no
total, because a tail cannot have one. [Response
bounding](#response-bounding) tabulates it.

**Capture text arrives fenced, and identifiers do not.** Free text an endpoint
wrote — display names, `User-Agent`, SDP, whole messages — comes wrapped in
`⟦untrusted-capture-data⟧` … `⟦/untrusted-capture-data⟧`, and the tools that
emit it append a provenance note as the LAST content block. Call-IDs, cursors,
addresses and timestamps stay verbatim so they pass straight into the next
call. [Untrusted capture text](mcp-protocol.md#untrusted-capture-text) gives the per-tool
breakdown. Every JSON sample below shows the markers where the server really
emits them.

### Reproduce every example on this page

Each tool section names the capture its example ran against. Start a server on
that capture, then call the tool. These two cover most of the page:

```bash
# The paging examples: 1334 dialogs, no RTP.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sipp-branch-scenario.pcapng
```

```bash
# The media examples: one completed call, two RTP streams.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sip-rtp-g711.pcap
```

Drive either one with the [raw HTTP test](mcp-deploy.md#test-the-http-wire-by-hand) recipe below, or point
a client at `http://127.0.0.1:8731/mcp`. A loopback bind needs no token.

Numbers in the samples are what those captures produce. Jitter and MOS come out
byte-identical run to run, because a file replay reads packet timestamps rather
than arrival times, so a value that fails to match points at a real change
rather than at timing noise.

### `list_dialogs`

Returns one page of dialog summaries from the live capture store.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `filter` | string? | A diagnostic alias name — `problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`, `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media` — **or** a raw [filter DSL](filter-dsl.md) expression. Anything else fails with `invalid_params` naming the position it stopped parsing at. | Every dialog in the store matches. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 unless the operator changed it). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest dialog. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `dialogs` | `DialogSummary[]` | This page, oldest first (ties broken by Call-ID). |
| `returned` | usize | Rows in `dialogs`, so counting the array is never necessary. |
| `total_matched` | usize | Dialogs matching the filter across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `truncated` | bool | `true` when matches remain after this page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered — see [`capture_status`](#capture_status). A changed `instance` voids every cursor you hold. |

Each `DialogSummary` row carries `call_id`, `state`, `method`, `from_user`,
`to_user`, `msg_count`, `duration_sec`, `created_at`, `updated_at`, a `timing`
object (`pdd_ms`, `setup_ms`, `retransmits`, `duration_ms`, each `null` when the
capture never showed it) and a `frame` pointer for
[`show_evidence`](#show_evidence). `from_user` and `to_user` arrive fenced,
because an endpoint chose them.

The example below runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng),
which holds 1334 dialogs. `limit: 2` therefore reports 2 of 1334 — and says so:

```jsonc
// list_dialogs { "limit": 2 }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-1-synth@192.0.2.10",
      "state": "Registered",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 7,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.303349+00:00",
      "updated_at": "2016-11-17T21:52:35.339349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#0@0f039ad14545671e"
    },
    {
      "call_id": "call-2-synth@192.0.2.10",
      "state": "Registered",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 7,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.403349+00:00",
      "updated_at": "2016-11-17T21:52:35.439349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#7@f7951dd197e419b9"
    }
  ],
  "returned": 2,
  "total_matched": 1334,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:35.403349+00:00|call-2-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1ae7318cb5c11b1a306dd-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

Two fields in there catch people writing a client from this page. `from_user`
reads `⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧`, not `ua-a`, so a
comparison against the bare name never matches — strip the markers, or match
inside them. And `capture_identity.node` names the box that answered, which
decides whose capture a fact came from once an agent holds several servers.

#### Why the page object, and why the cursor is compound

A bare array hides its own size. This tool returned 50 of 2311 dialogs on a
production capture with nothing in the reply to mark the cut, and `limit` alone
could not close the gap: requests above 1000 clamp to the hard cap, leaving 1311
dialogs no call could reach. An agent asked "how many calls failed?" counts the
rows it holds and answers with that number, so a short list does not read as an
incomplete answer — it reads as a confident wrong one. `total_matched` and
`truncated` name the shortfall. `cursor` closes it.

`next_cursor` pairs a timestamp with a Call-ID for the same reason
[`tail_dialogs`](#tail_dialogs) does. Dialogs share a `created_at` routinely — a
burst of registrations lands on one millisecond — and a bare timestamp forces a
choice between dropping the rest of that group and serving it twice. Resuming
after the `(created_at, Call-ID)` pair splits the group exactly where the page
ended. **Pass the value back unmodified.** A bare RFC 3339 timestamp still
parses, so rebuilding one by hand fails silently rather than erroring.

The two tools page on different clocks, deliberately. `tail_dialogs` follows
`updated_at`, because reporting change is its job. `list_dialogs` pages on
`created_at`, which never moves: a dialog that gains one more message mid-sweep
would jump forward in an `updated_at` ordering, past a cursor that had already
gone by, and vanish from the listing.

### Narrowing a row with `fields`

`list_dialogs`, `find_problems`, `tail_dialogs` and `search_by_time` take an
optional `fields` array. This surface already bounds rows three ways -- `limit`, `--mcp-max-rows`, and
cursors -- and it bounded columns not at all, so asking for a page to read two
values off it still paid for every other value on every row.

```jsonc
// list_dialogs { "limit": 200, "fields": ["state", "final_status_code"] }
{ "call_id": "1-1966@10.0.2.20", "state": "Completed", "final_status_code": 200 }
```

Three rules, each there for a reason:

- **`call_id` always survives**, listed or not. Every follow-up tool here takes
  a Call-ID, so a row an agent cannot address is a row it can do nothing with.
- **An unknown name fails**, naming both the typo and the fields the row
  actually carries. Silently returning rows without the field asked for reads
  as "no such data", which is a wrong answer rather than an error.
- **The envelope is never projected.** `total_matched`, `truncated`,
  `next_cursor` and `capture_identity` are how a caller knows what it did NOT
  get, and dropping them to save bytes would trade away the very thing the
  bounds exist to report.

A field already absent from a row stays absent rather than reappearing as
null: the projection runs on the serialized page, so `skip_serializing_if`
still decides what exists.

### `aggregate_dialogs`

Counts dialogs grouped by one field, inside the store.

Counting is the operation a language model gets wrong most reliably, and this
page documents that failure elsewhere: an agent asked "how many calls failed?"
counts the rows it is holding and answers with that number. The page object
fixed exactly one count — `total_matched`, for one filter. Every other count
still meant fetching pages and tallying them in the model's head, or issuing N
filtered queries with the buckets guessed in advance.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `group_by` | string | One of `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip`, `rtp.codec`. Anything else fails with `invalid_params` naming the legal set. | Required. |
| `filter` | string? | Alias or DSL, applied before grouping. | No filter — the whole store. |
| `top_n` | integer? | Bounded by `--mcp-max-rows`, the same knob that bounds dialog rows — not a second ceiling of sipnab's own. Anything past it lands in `other_count` rather than disappearing. | The same default as any row limit. |

```jsonc
// aggregate_dialogs { "group_by": "response_code", "filter": "state == 'Failed'" }
{
  "group_by": "response_code",
  "buckets": [ { "value": "503", "count": 412 }, { "value": "486", "count": 77 } ],
  "other_count": 11,
  "distinct_values": 6,
  "total_matched": 500
}
```

**The buckets plus `other_count` always equal `total_matched`.** A truncated
aggregate that does not say what it left out is a wrong total rather than a
partial one, so nothing is silently dropped — including nulls, which become the
literal `(none)`: "how many dialogs carry no User-Agent" is a real question.

**One dimension, and no time bucketing.** That is a deliberate cap, not an
unfinished feature. Two dimensions is a pivot table, a pivot table wants a UI,
and [positioning](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)
puts that outside what sipnab is. Narrow the window with `filter` instead.

**Grouping by `from.user`, `to.user` or `ua` returns fenced values.** Those are
text the packet's sender wrote, and they reach a model here exactly as they
would in a row. A state name, a status code, an IP or a codec is sipnab's own
derivation and comes back verbatim — fencing those would tell the agent to
distrust the analysis.

### `get_capture_report`

The whole-capture analysis, the one `--report` prints. Backed by
[`analysis::analyze`](https://github.com/NormB/sipnab/blob/main/src/analysis.rs)
and rendered by `output::analysis_report`.

[`get_dialog_report`](#get_dialog_report) and [`render_ladder`](#render_ladder)
both answer for ONE Call-ID, so everything the report says about the capture as
a whole had no MCP path: orphaned media, STUN, ICMP errors quoting SIP or RTP,
and what the retention caps shed. [`capture_status`](#capture_status) could hand an agent a count, and no tool
could expand it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `format` | string? | `"json"`, `"markdown"` or `"text"`. Anything else fails with `unknown format 'x', expected json\|markdown\|text`. | `"json"`. |

Frames read comes from the same process-global counter the Prometheus scrape
reports (`sipnab_capture_packets_total`), so the denominator here is the one
every other number in the run measures against.

A capture with no findings still answers with the clean line rather than an
empty body, because silence is indistinguishable from the tool not having run:

```jsonc
// get_capture_report { "format": "text" }
// A capture with findings names each one; a clean capture says so outright.
"Capture analysis: 2 finding(s) across 1 dialog(s), 2 stream(s), 535000 frame(s) read."
```

**`json` is the default and returns an OBJECT**, serialized from the analysis
itself — `findings`, `dialogs_examined`, `streams_examined`, `frames_read` and
`complete`. Read `complete` before the findings: it is `false` when the capture
lost packets, hit a retention cap, or held frames no decoder could read, and a
findings list from such a capture is a **floor, not a total**.

> Before 0.5.125 this default returned the TEXT rendering. `format` chooses
> between markdown headings and plain text inside the renderer and never had a
> JSON arm, so the tool asked for JSON, got prose, and fell back to a text
> block. An agent that called it with no argument received prose and nothing to
> say the structure it asked for was never there.

`GET /v1/report` answers the same question over REST.

### `get_dialog_report`

Per-call diagnostic report for one Call-ID. Backed by
`output::generate_call_report` — same content as `--call-report`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `invalid_params` (-32602) naming the value. | Required — the call fails. |
| `format` | string? | `"json"`, `"markdown"` or `"text"`. Anything else fails with `unknown format 'x', expected json\|markdown\|text`. | `"json"`. |

`"json"` answers with the structured object below. `"markdown"` and `"text"`
answer with one text block holding the rendered report, byte-identical to what
[`render_ladder`](#render_ladder) produces for the same dialog. All three append
the provenance note as a second content block.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_dialog_report { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "state": "Completed",
  "method": "INVITE",
  "final_status_code": 200,
  "final_status_reason": "OK",
  "from": "sipp",
  "from_display": "PCMU/8000",
  "to": "test",
  "to_display": "test",
  "msg_count": 6,
  "duration_sec": 8.504,
  "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
  "timing": {
    "retransmits": 0,
    "setup_ms": 4,
    "teardown_ms": 0,
    "trying_delay_ms": 0
  },
  "diagnosis": {
    "hints": [
      "RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."
    ],
    "nat_mismatch": false,
    "no_media": false,
    "one_way_audio": true
  },
  "sdp_timeline": [ /* the same rows get_sdp_timeline returns */ ],
  "streams": [ /* the same rows rtp_stats returns, without mos */ ]
}
```

This report bundles what [`triage_call`](#triage_call),
[`get_sdp_timeline`](#get_sdp_timeline) and [`rtp_stats`](#rtp_stats) answer
separately, so one call replaces three when you already know which call to read.
Its `streams` rows omit `mos` and `mos_grounded` — ask `rtp_stats` when the
question is audio quality rather than what the call did.

Unlike the summary rows elsewhere, `from` and `to` here arrive **unfenced**, and
the trailing provenance note explains why: a rendered report interleaves
sipnab's diagnosis with header values the sender wrote, and fencing the whole
document would tell an agent to distrust the analysis as well.

### `find_problems`

Convenience wrapper over `list_dialogs` that ORs each named alias, then ANDs
the optional `filter`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds` | string[]? | One or more of the ten diagnostic aliases listed under [`list_dialogs`](#list_dialogs), OR-ed together. An unknown name fails with `invalid_params`. An empty array behaves as omitted. | `["problems"]`. |
| `filter` | string? | An alias name or a raw [DSL](filter-dsl.md) expression, **ANDed** with the alias match. | The alias match alone decides the page. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim. | Starts at the oldest match. |

Returns the same page object as [`list_dialogs`](#list_dialogs) — `dialogs`,
`returned`, `total_matched`, `truncated`, `next_cursor`, `schema_version` and
`capture_identity` — with the same meanings and the same fenced `from_user` and
`to_user`.

`filter` is what makes this the triage entry point rather than a firehose. The
aliases answer "is this call interesting". The filter answers "is it one of
mine", so `{"kinds": ["problems"], "filter": "dst.ip == '203.0.113.9'"}` asks a
question that previously needed a client-side join. The two AND together —
ORing them would widen the sweep instead of narrowing it.

An unknown alias, or a filter that neither names an alias nor parses, returns
invalid_params (-32602) naming the offending value.

```jsonc
// find_problems { "limit": 1, "filter": "msg_count > 5" }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-1197-synth@192.0.2.10",
      "state": "Failed",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 6,
      "duration_sec": 0.03,
      "created_at": "2016-11-17T21:54:34.903349+00:00",
      "updated_at": "2016-11-17T21:54:34.933349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#8028@42ba0f02341ca2f7"
    }
  ],
  "returned": 1,
  "total_matched": 6,
  "truncated": true,
  "next_cursor": "2016-11-17T21:54:34.903349+00:00|call-1197-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1ae7318cb5c11b1a306dd-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

The same capture answers `find_problems {}` with `total_matched: 127`. Six of
those 127 carry more than five messages, which is what the filter selects.

### `get_dialog`

Paginated dialog with full SIP messages.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `call_id 'x' not found`. | Required — the call fails. |
| `max_messages` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 100 messages. |
| `cursor` | u32? | A message index, counting from 0. Unlike the dialog cursors elsewhere, this one is a plain integer, and past-the-end returns an empty page rather than an error. | Starts at message 0. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `dialog` | object | The same summary [`list_dialogs`](#list_dialogs) returns, with `from_user` and `to_user` fenced. |
| `messages` | object[] | This page of full messages, in dialog order. |
| `total_messages` | usize | Messages in the whole dialog, so `truncated` is unnecessary here. |
| `next_cursor` | u32? | Index to resume at. `null` on the final page. |
| `complete` | bool | `true` when this page reaches the end of the dialog. |

Every `messages` row carries `call_id`, `is_request`, `cseq` (`method` and
`number`), `from`, `to`, `src`, `src_port`, `dst`, `dst_port`, `transport`,
`timestamp`, `frame` and `schema_version`. The rest depends on the direction,
so branch on `is_request` rather than expecting one shape:

- **A request** adds `method`, and `contact` and `sdp` when it carried them.
- **A response** adds `status_code`, `reason`, `response_context` and `ua`, and
  carries no `method` — read `cseq.method` for the transaction it answers.

> **This tool does not fence, and it is the one that returns the most capture
> text.** `from`, `to`, `contact` and `sdp` in `messages[]` come back verbatim,
> with no provenance note on the response, while
> [`get_message`](#get_message) returns the same fields wrapped in
> `⟦untrusted-capture-data⟧` markers. Treat every string in `messages[]` as
> attacker-written regardless. Reach for `get_message` when the text is going
> into a model's context.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_dialog { "call_id": "1-1966@10.0.2.20", "max_messages": 1 }
{
  "complete": false,
  "total_messages": 6,
  "next_cursor": 1,
  "dialog": {
    "call_id": "1-1966@10.0.2.20",
    "state": "Completed",
    "method": "INVITE",
    "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
    "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
    "msg_count": 6,
    "duration_sec": 8.504,
    "created_at": "2016-11-26T14:52:59.666393+00:00",
    "updated_at": "2016-11-26T14:53:08.170676+00:00",
    "timing": { "pdd_ms": null, "setup_ms": 4, "retransmits": 0, "duration_ms": 8499 },
    "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
  },
  "messages": [
    {
      "call_id": "1-1966@10.0.2.20",
      "method": "INVITE",
      "is_request": true,
      "cseq": { "method": "INVITE", "number": 1 },
      "from": "\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1",
      "to": "test <sip:test@10.0.2.15:5060>",
      "contact": "sip:sipp@10.0.2.20:5060",
      "src": "10.0.2.20",
      "src_port": 5060,
      "dst": "10.0.2.15",
      "dst_port": 5060,
      "transport": "UDP",
      "timestamp": "2016-11-26T14:52:59.666393+00:00",
      "sdp": "v=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n",
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
      "schema_version": 1
    }
  ]
}
```

`total_messages` is 6 and `next_cursor` is 1, so five messages remain. Call
again with `cursor: 1` to continue, and stop when `complete` turns `true`.

### `get_message`

Single SIP message at a given zero-based index.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `index` | u32 | `0` to `msg_count - 1` for that dialog. | Required — the call fails. |

**Where an index comes from,** because the number means nothing on its own:
`msg_count` on any [`list_dialogs`](#list_dialogs) row is the count, so the last
valid index is `msg_count - 1`. [`get_dialog`](#get_dialog) pages messages from
its `cursor`, so the Nth row of that page sits at `cursor + N`, and every
[`lint_dialog`](#lint_dialog) finding reports the `message_index` it fired on.

An index at or past the end fails with `index 999 out of range for dialog with
7 messages` — the count is in the message, so a caller that guessed corrects
itself without another round trip.

Returns one message in the same shape [`get_dialog`](#get_dialog) uses for a
`messages` row, plus the provenance note as a second content block. The
difference is the fencing: this tool wraps `from`, `to`, `contact`, `sdp`, `ua`,
`reason` and `malformed`, and leaves `call_id`, addresses, ports, `method`,
`status_code`, `cseq` and timestamps verbatim so they pass into the next call.

```jsonc
// get_message { "call_id": "1-1966@10.0.2.20", "index": 0 }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "method": "INVITE",
  "is_request": true,
  "cseq": { "method": "INVITE", "number": 1 },
  "from": "⟦untrusted-capture-data⟧\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1⟦/untrusted-capture-data⟧",
  "to": "⟦untrusted-capture-data⟧test <sip:test@10.0.2.15:5060>⟦/untrusted-capture-data⟧",
  "contact": "⟦untrusted-capture-data⟧sip:sipp@10.0.2.20:5060⟦/untrusted-capture-data⟧",
  "sdp": "⟦untrusted-capture-data⟧v=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n⟦/untrusted-capture-data⟧",
  "src": "10.0.2.20",
  "src_port": 5060,
  "dst": "10.0.2.15",
  "dst_port": 5060,
  "transport": "UDP",
  "timestamp": "2016-11-26T14:52:59.666393+00:00",
  "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
}
```

### `render_ladder`

Call-flow ladder for one Call-ID.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `format` | string? | `"markdown"` or `"text"`. Anything else, `"json"` included, fails with `unknown format 'x', expected markdown\|text`. | `"markdown"`. |

Returns one text content block holding the rendered report, and the provenance
note as a second block. There is no JSON shape here — ask
[`get_dialog_report`](#get_dialog_report) with `format: "json"` for fields a
program can read.

```jsonc
render_ladder { "call_id": "1-1966@10.0.2.20" }
```

Output is byte-identical to the report
`sipnab -N --call-report <id> --markdown --no-cli-print` /
`sipnab -N --call-report <id> --no-cli-print` writes for the same dialog.
`--no-cli-print` matters for the comparison: without it the CLI writes the whole
capture's per-message dump ahead of the report, and the tool never does.

```text
# Call Report: 1-1966@10.0.2.20

## Summary

| Field | Value |
|-------|-------|
| Time | 2016-11-26 14:52:59 -> 14:53:08 (8s) |
| From | sipp |
| To | test |
| State | Completed |

## Timing

| Metric | Value |
|--------|-------|
| PDD | - |
| Setup | 0.00s |
| Ring | - |
| Teardown | 0.00s |
| Retransmits | 0 |

## Media Streams

| SSRC | Codec | Source | Destination | Packets | Jitter | Loss |
|------|-------|--------|-------------|---------|--------|------|
| 0x343da99b | PCMU | 10.0.2.15:27942 | 10.0.2.20:6000 | 425 | 0ms | 0.0% |

## Issues

- RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected.
```

### `rtp_stats`

Per-stream RTP quality for one call, or across the whole capture.

This tool has **two modes**, and `call_id` is the switch. Pass it for one
dialog's streams. Omit it to sweep the whole capture. The four sweep-only
parameters fail with `invalid_params` when a `call_id` accompanies them, rather
than quietly doing nothing:

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string? | A Call-ID the store holds. | **Switches modes** — the tool sweeps every stream in the capture, orphans included. |
| `min_mos` | f64? | Sweep only. Keeps streams scoring at or above this. Rejected alongside `call_id`. | No lower bound. |
| `max_mos` | f64? | Sweep only. Keeps streams scoring strictly below this. Rejected alongside `call_id`. | No upper bound. |
| `limit` | u32? | Sweep only. Ceiling is `--mcp-max-rows` (1000 by default), higher clamps to it, `0` means the default. | 50 streams. |
| `cursor` | string? | Sweep only. The previous response's `next_cursor`, verbatim (`<RFC 3339>\|0xSSRC@src>dst`). | Starts at the earliest stream. |

**With `call_id`** the answer keeps its existing shape — `{ call_id, streams, diagnosis }`,
where `streams` is an array of stream JSON objects (codec, MOS, jitter, loss%,
packets, SSRC, quality intervals) and `diagnosis` carries the standard one-way /
NAT-mismatch flags plus the asymmetry signals (`codec_asymmetry`,
`ptime_asymmetry`, `payload_type_asymmetry`, `duration_asymmetry`,
`late_media`). A MOS bound alongside a `call_id` returns invalid_params
(-32602) rather than quietly doing nothing.

```jsonc
// rtp_stats { "call_id": "1-1966@10.0.2.20" }
{
  "call_id": "1-1966@10.0.2.20",
  "streams": [
    {
      "associated_dialog": "1-1966@10.0.2.20",
      "codec": "PCMU",
      "src": "10.0.2.15:27942",
      "dst": "10.0.2.20:6000",
      "ssrc": "0x343da99b",
      "payload_type": 0,
      "packets": 425,
      "octets": 68000,
      "loss_pct": 0.0,
      "jitter_ms": 0.0054046519599899685,
      "mos": 4.358100599599484,
      "mos_grounded": true,
      "mos_grounding": "published",
      "orphaned": false,
      "first_seen": "2016-11-26T14:52:59.689083+00:00",
      "last_seen": "2016-11-26T14:53:08.169060+00:00",
      "round_trip_note": "Not measured. No endpoint reported a round trip for this stream, so latency is unknown rather than good — a stream with clean jitter and no loss can still be unusable on delay alone (ITU-T G.114).",
      "quality_intervals": [
        {
          "jitter_ms": 0.0063823922199494915,
          "loss_pct": 0.0,
          "packets": 252,
          "timestamp": "2016-11-26T14:53:04.709076+00:00"
        }
      ],
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#5@ae02f78d2d48b4f0",
      "schema_version": 1
    }
  ],
  "diagnosis": {
    "actual_media": null,
    "hints": [
      "RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."
    ],
    "nat_mismatch": false,
    "no_media": false,
    "one_way_audio": true,
    "sdp_media": "10.0.2.20"
  }
}
```

Per-call mode returns no `total_matched`, `truncated` or `next_cursor` — a call
holds every stream it holds, so there is nothing to page. `quality_intervals`
holds one entry per completed sampling window, so a short call legitimately
returns an empty array while this eight-second one returns a single row.

Each stream carries **`mos_grounded`** and **`mos_grounding`**. `estimate_mos`
returns the same number — 4.216 at 10 ms jitter — for AMR, AMR-WB, EVS, G.722
*and* for a stream whose codec was never identified, because sipnab only has
published ITU-T G.113 impairment values for G.711, G.729 and Opus. When
`mos_grounded` is `false` the MOS means **unknown**, not "about 4.2", and a
`mos_note` says so.

`mos_grounding` names which basis the number rests on, because "grounded" now
covers two of them:

| `mos_grounding` | `mos_grounded` | What the number rests on |
|---|---|---|
| `published` | `true` | An ITU-T G.113 impairment value sipnab implements. |
| `operator_declared` | `true` | An `Ie` this deployment supplied in `[media.codec_ie]`. A `mos_note` says so, so an agent citing the figure cites the operator rather than a standard. |
| `unpublished` | `false` | Nothing published and nothing declared. Placeholder. |

For AMR-WB specifically the placeholder is wrong by roughly a full MOS point in
either direction: its nine modes genuinely span about 4.49 down to 3.51. Do not
report a MOS to a human without checking this field. See
[MOS and codecs](mos-and-codecs.md) for the full picture.

#### Who named the dialog — `dialog_assertion`

Each stream also says who asserted the SDP media endpoint that tied it to its
Call-ID:

| `dialog_assertion` | Who said it | What the address is |
|---|---|---|
| `signaled` | a negotiating party, in its own SDP | that party's endpoint |
| `media-relay` | an rtpengine relay, about a port it allocated | the leg's **midpoint** |

A relay cannot be wrong about which socket it opened, so the address is
authoritative — and it is still not an endpoint. An agent reasoning about where
media went must not report a `media-relay` address as the far party's, because
it names the box in the middle and the two lead to opposite conclusions.

sipnab emits the key whenever it knows the answer, `signaled` included. **Absent
means nobody recorded who asserted it**, never "a party did". Do not default it.

Distinct from `dialog_origin`, which names the capture **source** that delivered
the assertion rather than its author. See
[rtpengine relay attribution](rtpengine.md).

#### Capture-wide sweep — omit `call_id`

"Every stream with a MOS below 3.5" is one call rather than a listing plus one
`rtp_stats` per dialog, which costs thousands of round trips on a real capture.
The sweep also reaches streams the per-call mode cannot: a stream that never
linked to a dialog has no Call-ID to ask about, and an orphan is not an oddity —
it is what a NAT or one-way-audio fault looks like from the media side.

| Field | Type | Description |
|---|---|---|
| `streams` | object[] | This page, oldest `first_seen` first. |
| `returned` | usize | Rows in `streams`. |
| `total_matched` | usize | Streams matching across the whole store. |
| `ungrounded_excluded` | usize | Streams a MOS bound could not judge. |
| `truncated` | bool | `true` when matches remain after this page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |

**A MOS bound only judges codecs sipnab has a real impairment value for** —
one G.113 publishes, or one this deployment declared in `[media.codec_ie]`.
`min_mos` and `max_mos` skip every ungrounded stream and count it in
`ungrounded_excluded`,
because a bound on a placeholder picks calls out of a guess — and it goes
wrong in both directions. A healthy AMR-WB stream never appears in a `max_mos`
sweep, while a degraded one turns up on a figure that never described it.
Reporting the skipped count keeps the difference visible: "2 streams below 3.5"
and "2 streams below 3.5, plus 200 I cannot score" describe different captures,
and on any network carrying AMR-WB, EVS or G.722 the second one is the truth.
Omit both bounds and the sweep lists every stream, including the codecs with no
published value, each still carrying `mos_grounded`.

The example runs against [`tests/pcap-samples/codec-negotiation.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/codec-negotiation.pcap), which
carries four streams — two PCMU, two G722 — and no dialogs at all:

```jsonc
// rtp_stats { "max_mos": 4.5, "limit": 1 }
{
  "schema_version": 1,
  "streams": [
    {
      "codec": "PCMU",
      "dst": "127.0.0.1:5084",
      "first_seen": "2026-07-08T18:35:27.407583+00:00",
      "frame": "tests/pcap-samples/codec-negotiation.pcap#5@5d4c3e3d970a836b",
      "jitter_ms": 0.26954164761616456,
      "last_seen": "2026-07-08T18:35:30.407077+00:00",
      "loss_pct": 0.0,
      "mos": 4.357953149337916,
      "mos_grounded": true,
      "mos_grounding": "published",
      "octets": 24160,
      "orphaned": true,
      "packets": 151,
      "payload_type": 0,
      "quality_intervals": [],
      "round_trip_note": "Not measured. No endpoint reported a round trip for this stream, so latency is unknown rather than good — a stream with clean jitter and no loss can still be unusable on delay alone (ITU-T G.114).",
      "schema_version": 1,
      "src": "127.0.0.1:5094",
      "ssrc": "0x0e330af3"
    }
  ],
  "returned": 1,
  "total_matched": 2,
  "ungrounded_excluded": 2,
  "truncated": true,
  "next_cursor": "2026-07-08T18:35:27.407583+00:00|0x0e330af3@127.0.0.1:5094>127.0.0.1:5084",
  "capture_identity": {
    "node": "capture-01",
    "instance": "22fa418cb5c799c57abef-1",
    "dialog_generation": 1,
    "stream_generation": 4
  }
}
```

The sweep adds `frame`, `capture_identity` and the page fields the per-call mode
omits.

**`orphaned` means "no dialog claims this stream", and nothing else.** It is
`associated_dialog.is_none()`, which sipnab computes while building the
response, so the two fields can never disagree: every stream above reports `orphaned: true`, which
is the truth about a capture holding four streams and no dialogs at all.

sipnab computes `orphaned` per response as `associated_dialog.is_none()`, so a
stream reports it from its FIRST packet. That matters because a short unclaimed
stream is exactly what a NAT or one-way-audio fault looks like from the media
side: an agent filtering for orphans to find one must not have to wait for a
sweep to notice. Reading `associated_dialog` directly means the same thing.

`total_matched: 2` and `ungrounded_excluded: 2` account for all four streams.
The two G722 streams score 4.22 from the placeholder arm, which would have put
them under a 4.5 bound on a number that means nothing.

### `media_diagnostics`

"The MOS is 3.6 — why?" `rtp_stats` gives the score. This gives the facts
underneath it, and each one says what kind of number it is.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |

**Read `applicable` first.** It is `false` when no RTP stream belongs to the
dialog, and the response then holds only `call_id`, `reason`,
`capture_identity` and `schema_version`. An empty `streams` array would read as
"sipnab checked the media and it was fine", which is a different claim from "no
media reached the capture point".

Otherwise `streams` carries one entry per stream, each with five blocks:

| Block | Answers | The honesty flag |
|---|---|---|
| `qos` | Which queue the sender asked the network to put this media in | `marking_observed` — `false` for a HEP-fed stream, where sipnab saw no IP header. `dscp: 0` means observed best effort, a real and frequently wrong marking |
| `jitter` | The interarrival jitter, and whether it is a measurement | `grounded` — `false` when the stream supplied no clock rate and sipnab fell back to a default. Jitter is an RTP-timestamp difference divided by that rate, so a wrong divisor gives a different quantity, not a rough one. An ungrounded stream reports no `measured_ms` at all |
| `delay` | The one-way delay behind the published MOS | `assumed` — `true` when neither the operator nor any RTCP supplied one |
| `silence` | Comfort-noise frames and detected silence periods | -- (counts, not estimates) |
| `endpoint_reported` | What the far end said over RTCP | The whole block is the flag. Omitted entirely when no RTCP arrived |

`endpoint_reported` sits apart from everything beside it on purpose. Nobody
authenticates RTCP and anyone can forge it, and a report describes the path
from the sender to *the reporter* — on a mid-path capture, a different segment
from the one sipnab watches. The two disagreeing is normal and informative, and
merging them would destroy exactly that signal. Nothing under this key feeds the
MOS.

`qos.remarked_to` appears only when the stream's last packet carries a different
code point from its first — an SBC or a policy boundary rewriting the marking in
flight. Its presence is the finding, and a steady stream omits it rather than
repeating the same number.

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// media_diagnostics { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "applicable": true,
  "streams": [
    {
      "ssrc": "0x343da99b",
      "src": "10.0.2.15:27942",
      "dst": "10.0.2.20:6000",
      "codec": "PCMU",
      "packets": 425,
      "qos": {
        "marking_observed": true,
        "dscp": 0,
        "name": "CS0 / default (best effort)",
        "expedited": false
      },
      "jitter": {
        "grounded": true,
        "clock_basis": "rfc3551",
        "clock_rate_hz": 8000,
        "measured_ms": 0.0054046519599899685
      },
      "delay": { "source": "assumed", "assumed": true, "one_way_ms": 100.0 },
      "silence": { "cn_frames": 0, "periods": 0, "total_ms": 0 }
    }
  ],
  "capture_identity": {
    "instance": "6dac718cb96d767d0f490-1",
    "node": "sbc-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

Three things in that answer are worth reading together. The media is in the
default queue, so it competes with bulk traffic — the most common cause of
jitter that adding bandwidth does not fix. The jitter figure IS a measurement,
because payload type 0 has a clock rate [RFC 3551](https://www.rfc-editor.org/rfc/rfc3551)
Table 4 fixes. And the delay behind the MOS is a default, not anything this
capture showed, so a MOS built on it is only as good as that assumption.

`clock_basis` has three values: `rfc3551` (a static payload type), `rtpmap` (a
dynamic one an SDP named), and `assumed` (neither, and the reason `grounded` is
`false`).

### `search_messages`

Case-insensitive substring search over method, status, From, To,
User-Agent, and body across all dialogs.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `query` | string | Any substring. Matching ignores case. | Required — the call fails. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 hits. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>#<zero-padded message index>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest match. |

**Returns** — the same page shape [`list_dialogs`](#list_dialogs) returns, not
a bare array, plus the provenance note as a second content block:

| Field | Type | Description |
|---|---|---|
| `hits` | object[] | This page of `{ call_id, message_index, snippet }`, ordered by the dialog's `created_at`, then Call-ID, then message index. |
| `returned` | usize | Rows in `hits`. |
| `total_matched` | usize | Messages matching the query across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `truncated` | bool | `true` when matches remain after this page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered. A changed `instance` voids the cursor. |

`snippet` holds the whole raw message, fenced, and stops at 4 KB. Pass `call_id`
and `message_index` straight to [`get_message`](#get_message) for the parsed
form.

> **Count from the fields, never from the rows.** A capped result and a
> complete one hold the same shape, so the row count cannot tell them apart:
> on the sample capture below, `{ "query": "REGISTER" }` returns 50 rows and
> `limit: 1000` returns 1000, while 1334 messages match. `total_matched` is
> the number that answers "how many are there", `truncated` says whether you
> are seeing all of them, and `next_cursor` reaches the rest.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng):

```jsonc
// search_messages { "query": "REGISTER", "limit": 1 }
{
  "schema_version": 1,
  "hits": [
    {
      "call_id": "call-1-synth@192.0.2.10",
      "message_index": 0,
      "snippet": "⟦untrusted-capture-data⟧REGISTER sip:example.net SIP/2.0\r\n…⟦/untrusted-capture-data⟧"
    }
  ],
  "returned": 1,
  "total_matched": 1334,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:35.303349+00:00|call-1-synth@192.0.2.10#0000000000",
  "capture_identity": {
    "node": "capture-01",
    "instance": "12100b18cb6971cf461cff-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

Passing that `next_cursor` back returns `call-2-synth@192.0.2.10` and reports
the same `total_matched: 1334`: the total describes the store, not the page.
The index half of the cursor carries leading zeros because the server compares
the cursor as text — rebuild one by hand and `#10` sorts before `#2`, which
silently skips eight messages of a dialog. Pass it back exactly as it arrived.

### `tail_dialogs`

Incremental fetch of the dialogs updated after a cursor position.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339>\|<Call-ID>`). A bare RFC 3339 timestamp also parses, and filters strictly after it. | Starts from the beginning of the store. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |

Returns `{ dialogs, next_cursor, source_exhausted, capture_identity }`, where
`dialogs` holds the same summary rows [`list_dialogs`](#list_dialogs) returns,
fencing included. This page object carries no `returned`, `total_matched` or
`truncated` — "how many are there" is not a question a tail can answer, because
the store keeps changing underneath it. Poll until `dialogs` comes back empty
and `source_exhausted` is `true`.

`next_cursor` is compound — `<RFC 3339>|<Call-ID>` — not a bare
timestamp. Dialogs can share an `updated_at`, so resuming from the
`(updated_at, Call-ID)` pair is what keeps a tie group split across a
page boundary from vanishing or arriving twice. Pass it back
unmodified. A client that rebuilds a bare timestamp from a dialog's
`updated_at` instead falls back to the pre-compound strictly after
filter and loses or repeats the tied dialogs — that bare-timestamp
form is still accepted, so the mistake is silent rather than an error.
`|` occurs in neither an RFC 3339 timestamp nor a valid Call-ID
([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) `word`), so the split is unambiguous.

`source_exhausted` is `false` while more dialog updates can still
arrive and `true` once the capture source is fully drained — the end of
an `-I` pcap replay, or a live capture that has hit its
`--count`/`--duration`/`--autostop` stop condition. sipnab keeps
serving MCP after that, so this is the flag to poll to learn a replay
has finished: stop when it turns `true` instead of polling forever.

```jsonc
// tail_dialogs { "limit": 1 }
{
  "dialogs": [
    {
      "call_id": "1-1966@10.0.2.20",
      "state": "Completed",
      "method": "INVITE",
      "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
      "msg_count": 6,
      "duration_sec": 8.504,
      "created_at": "2016-11-26T14:52:59.666393+00:00",
      "updated_at": "2016-11-26T14:53:08.170676+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": 4,
        "retransmits": 0,
        "duration_ms": 8499
      },
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
    }
  ],
  "next_cursor": "2016-11-26T14:53:08.170676+00:00|1-1966@10.0.2.20",
  "source_exhausted": true,
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

### `security_findings`

Recent findings from active detection rules (scanner, fraud, digest,
reg-flood, etc.). Backed by the AlertEngine's bounded ring buffer
(default 1000 entries, kept in memory only).

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds` | string[]? | Exactly four names: `scanner`, `fraud`, `digest`, `reg_flood`. Anything else fails with `invalid_params` naming all four — including `reg-flood` with a hyphen, which suggests the underscore spelling. | Findings of every kind. |
| `since` | string? | RFC 3339. Keeps findings recorded strictly after it. A malformed value fails with `since must be RFC 3339`. | The whole retained history. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 findings. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `findings` | object[] | This page of `{ rule_name, src_ip, detail, timestamp }`, newest first. |
| `returned` | usize | Rows in `findings`. |
| `total_matched` | usize | Findings matching `kinds` and `since` across the whole retained ring buffer. |
| `truncated` | bool | `true` when matches remain after this page. There is no cursor — narrow with `since`, or raise `limit`. |
| `armed_kinds` | string[] | The detectors this server runs. Empty means it runs none, so `findings` could only ever be empty. |
| `detection_armed` | bool | `false` when `armed_kinds` is empty, stated separately so a caller can branch on one field. |
| `note` | string? | Present **only** when no detector runs, saying so in words. |
| `schema_version` | u32 | `1` for this shape. |

> **Read `armed_kinds` before you read `findings`.** An empty findings list
> means "nothing tripped" only on a server that armed something; on any other
> it means nothing was watching, and the two are opposite operational states.
> A `kinds` value outside the vocabulary fails rather than answering with an
> empty list, which would be a third way to read `[]`. Cross-checking
> [`server_capabilities`](#server_capabilities) is not necessary for this
> question: the answer is in the response.

The page fields carry the meanings they do everywhere else on this surface —
[`search_messages`](#search_messages) documents the same four. `armed_kinds` is
per detector, which is what makes it worth reading rather than a bare
"detection is on": a server started with `--kill-scanner` alone answers
"no fraud findings" for a capture full of toll fraud, and `armed_kinds:
["scanner"]` is what tells an agent that the question was never asked.

Arming a rule takes a flag on the server command line, such as `--kill-scanner`
or `--digest-leak`. Findings then land in a bounded in-memory ring buffer
(1000 entries by default, `--findings-history` to change it) and go nowhere
else — stopping the process discards them.

`timestamp` records when the rule **fired during analysis**, not when the packet
arrived. On a replayed pcap those differ by years, so a `since` value copied
from a dialog's `created_at` returns everything.

The example runs against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng)
on a server started with `--digest-leak`:

```jsonc
// security_findings {}
{
  "schema_version": 1,
  "findings": [
    {
      "rule_name": "digest",
      "src_ip": "203.0.113.101",
      "detail": "WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)",
      "timestamp": "2026-08-13T16:16:02.880725566+00:00"
    }
  ],
  "returned": 1,
  "total_matched": 1,
  "truncated": false,
  "armed_kinds": ["digest"],
  "detection_armed": true
}
```

The same tool on a server started without a detection flag answers with an
empty `findings` list, `armed_kinds: []`, `detection_armed: false` and a `note`
saying that nothing was watching. `armed_kinds: ["digest"]` above says the
opposite in the same field: this server watched for digest weaknesses and for
nothing else, so it answers nothing about scanners either way.

### `triage_call`

**Start here.** The first question in VoIP triage is which half of the stack
failed.
Signaling decides whether a call *connects*. RTP decides whether you can
*hear* it. They have different causes and different fixes, and confusing them
is the most common wrong turn — so ask this before anything else.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds, as
returned by [`list_dialogs`](#list_dialogs). An unknown one fails with
`invalid_params` (-32602) naming the value. There are no optional parameters.

```jsonc
// triage_call { "call_id": "1-1966@10.0.2.20" }
{
  "verdict": "media",              // "signaling" | "media" | "both" | "none"
  "state": "InCall",
  "final_status_code": 200,
  "signaling": { "problem": false, "hints": [] },
  "media": {
    "problem": true,
    "one_way_audio": true,
    "nat_mismatch": false,
    "no_media": false,
    "stream_count": 1,
    "hints": ["RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."]
  }
}
```

A clean `200 OK` with one-way audio is a **media** problem. Nothing in the SIP
exchange is wrong, and time spent reading it is time lost.

Where to go next, by verdict:

| Verdict | Next tool |
|---|---|
| `signaling` | [`explain_response_code`](#explain_response_code) on the final code, then [`get_dialog`](#get_dialog) |
| `media` | [`rtp_stats`](#rtp_stats), and [`check_codec_negotiation`](#check_codec_negotiation) if the call failed |
| `both` | Signaling first — media symptoms are often downstream of a failed negotiation |
| `none` | The call is fine. Check you have the right Call-ID |

### `check_codec_negotiation`

For `488 Not Acceptable Here`, which usually means nobody offered the far end a
codec it accepts.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters.

Returns `offered`, `answered`, `common`, `result`, `sdp_exchange_count`,
`final_status_code`, `call_id` and `schema_version`. Codec names come from the
SDP unfenced, because they are tokens from a registry rather than free text.

```jsonc
// check_codec_negotiation { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "offered": ["PCMU"],
  "answered": ["PCMU", "telephone-event"],
  "common": ["PCMU"],
  "result": "ok",
  "final_status_code": 200,
  "sdp_exchange_count": 2
}
```

`result` has five values, and the distinction matters:

| Result | Meaning | What to do |
|---|---|---|
| `ok` | The two sides agreed | Codecs are not your problem |
| `no_common_codec` | Both offered codecs, none shared | A codec policy problem — compare the lists |
| `no_answer` | An offer went out, nothing came back | The call did not get far enough to negotiate |
| `sdp_present_but_no_codecs` | Both sides exchanged SDP, but neither listed a codec | Look at the SDP itself — a malformed or media-less `m=` line |
| `no_sdp_in_capture` | No SDP at all | Not a codec problem. Hold with inactive media, or a reject before any offer |

`no_answer` and `no_sdp_in_capture` are deliberately separate: reporting the
first for the second sends you hunting a reply that was never expected.

### `diagnose_registration`

"Is this phone online?" — a different question from "why did this call fail?".

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters. The call need not carry a `REGISTER`, and the answer says
so when it does not.

**Read `applicable` first.** It is `false` for a dialog carrying no `REGISTER`,
and the response then holds only `call_id`, `reason` and `schema_version` — no
`hints`, no `registration_failure`. Reporting a healthy registration for a call
that never attempted one would be worse than admitting the question does not
apply:

```jsonc
// diagnose_registration { "call_id": "1-1966@10.0.2.20" }   — an INVITE dialog
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "applicable": false,
  "reason": "this dialog carries no REGISTER request"
}
```

When it does apply, `registration_failure` is `null` for a registration that
worked, and otherwise names the `kind` — `rejected`, `shortened_expiry` or an
auth loop reported through `auth_loop`. `evidence` lists the message indexes
behind the verdict, ready for [`get_message`](#get_message). The example runs
against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng):

```jsonc
// diagnose_registration { "call_id": "auth-fail-register-synth@203.0.113.1" }
{
  "schema_version": 1,
  "call_id": "auth-fail-register-synth@203.0.113.1",
  "applicable": true,
  "final_status_code": null,
  "auth_loop": null,
  "registration_failure": {
    "kind": "rejected",
    "code": 403,
    "evidence": [0, 3],
    "requested_expiry_sec": null,
    "granted_expiry_sec": null
  },
  "hints": [
    "Call failed: 403 Forbidden.",
    "Registration rejected: 403 Forbidden. The endpoint answered an authentication challenge and the registrar refused the credentials it offered, so the fault is in the account, its password or its permission to register — none of which is a reachability problem."
  ]
}
```

`final_status_code` is `null` here even though the registrar answered 403,
because the dialog never reached a state that records one. Read
`registration_failure.code` for the status that decided the verdict.

### `lint_dialog`

Conformance, which is not the question `triage_call` answers. That tool asks
why a call failed. This one asks whether the traffic obeys the specification. A
call can complete over messages that break four MUSTs, and a fully conformant
call can hit a busy signal.

The rules that earn this tool its place compare the declaration against the
observation. sipnab holds the signaling and the RTP in one process, so it can
report that the SDP declared PCMU on payload type 0 while the wire carried
payload type 8, that RTP arrived on a port no `m=` line advertised, that
`sendrecv` promised media in both directions and the capture holds it in one,
or that the packet spacing contradicts `a=ptime`. A linter reading message text
reaches none of that, because the defect sits in neither message.

The RFC 3261 syntax rules and the [RFC 3264](https://www.rfc-editor.org/rfc/rfc3264) offer/answer rules run alongside
them. Everything citing [RFC 4566](https://www.rfc-editor.org/rfc/rfc4566), 3551 or 5761 belongs to the observation half.
[SIP conformance rules](sip-lint-rules.md) lists every rule, the section behind
it, and the suppression syntax.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `rulesets` | string[]? | The 15 selectors below, OR-ed together. An unknown one fails with `invalid_params` listing all 15. | The whole catalog, reported back as `rulesets: ["all"]`. |
| `severity_min` | string? | `info`, `notice`, `warning` or `error`. Anything else fails with `unknown severity 'x'. Valid values: info, notice, warning, error`. | `info`, so the floor drops nothing. |
| `suppression_file` | string? | A bare filename inside `--mcp-file-root`. A file sipnab cannot open fails with `invalid_params` rather than linting with every rule on. | sipnab walks for a `.sipnablint` beside the capture and upward to the project root. |

Selectors take two forms — the catalog's own names, and one per RFC the rules
cite:

- **By category:** `all`, `must`, `rfc` (MUST and SHOULD together), `interop`,
  `observation` (`observed` also works) and `syntax`.
- **By RFC:** `rfc3261`, `rfc3262`, `rfc3264`, `rfc3551`, `rfc4028`, `rfc4566`,
  `rfc5761`, `rfc7989`.

An unknown selector fails with `invalid_params` (-32602) naming the whole
vocabulary, so a typo such as `rfc3621` cannot quietly select nothing and hand
back an empty list that reads as a clean call. Passing an empty array behaves
as omitting the parameter.

The example runs against [`tests/pcap-samples/b2bua-asterisk.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/b2bua-asterisk.pcapng). Its SDP
negotiates `sendrecv` in both directions, and the capture carries 355 RTP
packets in one:

```jsonc
// lint_dialog { "call_id": "b2bua-leg-synth@203.0.113.101:5060",
//               "rulesets": ["observed"] }
{
  "schema_version": 1,
  "call_id": "b2bua-leg-synth@203.0.113.101:5060",
  "rulesets": ["observed"],
  "severity_min": "info",
  "message_count": 15,
  "rtp_streams_observed": 1,
  "finding_count": 1,
  "severity_counts": { "error": 0, "warning": 1, "notice": 0, "info": 0 },
  "findings": [
    {
      "rule_id": "OBS-3264-6.1-DIRECTION-UNMET",
      "severity": "warning",
      "basis": "observation",
      "rfc": 3264,
      "section": "6.1",
      "message_index": 0,
      "observed": "355 RTP packets observed, none of them toward one negotiated endpoint",
      "expected": "media in both directions, as a=sendrecv promised",
      "explanation": "§6.1 makes sendrecv a promise to send as well as receive. ..."
    }
  ],
  "rules_not_evaluated": [
    {
      "reason": "needs the endpoint pairs RTCP arrived on. ...",
      "rule_ids": ["OBS-5761-5.1.1-RTCP-MUX-UNANSWERED"]
    }
  ],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

`rfc` and `section` stay separate fields rather than prose inside the
explanation, and that is the whole point of the shape. An agent quotes RFC 3264
§6.1 out of the data instead of inventing a section number that reads
plausibly, and `explain_rule` turns the identifier back into the citation and
the link.

`rules_not_evaluated` names what the run could not settle, grouped by reason. A
rule that found nothing and a rule that never ran leave the same empty finding
list behind, and only this field separates them. Two reasons appear on this
tool:

- No RTP reached the call, so the `OBS-` rules had nothing to compare the
  declaration against.
- `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` needs the endpoint pairs RTCP arrived
  on. The stream store folds an RTCP report into the stream it describes and
  keeps no record of where it landed, so no MCP tool raises this rule.

#### Suppression, and what it must tell you

A project silences rules with a `.sipnablint` — one identifier per line, or a
prefix ending `*`, with `#` starting a comment. [SIP conformance
rules](sip-lint-rules.md) documents the pattern syntax.

sipnab looks for one beside the capture, then climbs toward the project root
and stops there. A capture that sits outside any project — a corpus mount, a
share, `/tmp` — adopts nothing from above itself, because inheriting a
stranger's suppression list would switch off rules nobody here turned off.
`suppression_file` overrides the search outright, and a file it names that
sipnab cannot open returns invalid_params rather than quietly linting with every
rule on.

Two response fields carry the consequences, and every call includes both, even
when every number is zero:

```jsonc
"suppressions": {
  "file": "/srv/captures/.sipnablint",   // null when none applied
  "patterns": ["OBS-*", "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING"],
  "findings_suppressed": 4
},
"findings_withheld": { "suppressed": 4, "below_severity": 2, "capped": 0 }
```

A response carrying no field and a response carrying zero must not be the same
bytes. The first says nothing about whether the run hid findings. The second
says it hid none.

The three counts stay apart because they send you to three different places:
something you wrote down silenced it, your severity floor dropped it, or there
was simply too much of it and the per-rule cap stopped after 25.
`capped` is the only lower bound of the three — a rule may stop evaluating once
it hits the cap, and nothing can count what it then never raises. `suppressed`
and `below_severity` are exact, which is why suppression deliberately does not
short-circuit the rule.

The response names the file rather than merely acknowledging one. "4 findings
suppressed" leaves you nothing to act on when the search walked up three
directories to find the file that did it.

### `validate_message`

The same rules against one message, named by its zero-based index — the shape a
CI job or a header-level argument with a vendor wants. `lint_dialog` reports
`message_index` on every finding, so this tool narrows a hit rather than
finding new ones.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `index` | u32 | `0` to `msg_count - 1`. Out of range fails with `invalid_params` (-32602) naming the message count. | Required — the call fails. |
| `suppression_file` | string? | A bare filename inside `--mcp-file-root`, exactly as [`lint_dialog`](#lint_dialog) takes it. Wins outright over the discovery walk. | sipnab walks for a `.sipnablint` beside the capture and upward. |

There is no `rulesets` or `severity_min` here. Every rule that can run on one
message runs, and the response reports the rest under `rules_not_evaluated`.

```jsonc
// validate_message { "call_id": "options-ping-c-synth@198.51.100.206", "index": 0 }
{
  "schema_version": 1,
  "call_id": "options-ping-c-synth@198.51.100.206",
  "message_index": 0,
  "message_count": 2,
  "finding_count": 2,
  "severity_counts": { "error": 0, "warning": 2, "notice": 0, "info": 0 },
  "findings": [
    {
      "rule_id": "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING",
      "severity": "warning", "basis": "must", "rfc": 3261, "section": "8.1.1.6",
      "message_index": 0,
      "observed": "no Max-Forwards header field",
      "expected": "Max-Forwards: 70",
      "explanation": "§8.1.1.6 makes a UAC insert one into every request it originates. ..."
    },
    {
      "rule_id": "SIP-3261-8.1.1.7-BRANCH-COOKIE",
      "severity": "warning", "basis": "must", "rfc": 3261, "section": "8.1.1.7",
      "message_index": 0,
      "observed": "top Via branch without the z9hG4bK prefix",
      "expected": "branch=z9hG4bK...",
      "explanation": "§8.1.1.7 makes every compliant branch begin with z9hG4bK. ..."
    }
  ],
  "rules_not_evaluated": [
    { "reason": "reads a dialog's messages against each other, and this tool reads one message alone. Call lint_dialog.",
      "rule_ids": ["SIP-3261-8.1.1.2-TO-TAG-IN-INITIAL-REQUEST", "..."] },
    { "reason": "compares the declaration against the observed media, and this tool reads one message alone. Call lint_dialog.",
      "rule_ids": ["OBS-3264-6.1-PT-UNDECLARED", "..."] },
    { "reason": "needs the endpoint pairs RTCP arrived on. ...",
      "rule_ids": ["OBS-5761-5.1.1-RTCP-MUX-UNANSWERED"] }
  ],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

That example runs against [`tests/pcap-samples/sip-488-codec-reject.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-488-codec-reject.pcapng),
whose first `OPTIONS` ping carries neither a `Max-Forwards` header field nor
the RFC 3261 branch cookie.

Thirteen of the thirty-two rules skip on a one-message run, which is why the
response names them. Reach for `lint_dialog` first and use this to confirm one
message.

### `explain_rule`

Turns a rule identifier back into its catalog entry, so an identifier lifted
out of a finding, a CI log or a suppression file resolves without a round trip
to the source.

**Parameters:** `rule_id` (string, required) — one of the 32 catalog
identifiers, matched exactly, such as `OBS-3264-6.1-PT-UNDECLARED`. No optional
parameters, and the tool reads no capture, so it answers the same on any
server. An unknown identifier fails with `invalid_params` (-32602) **listing all
32**, which doubles as the way to enumerate them.

```jsonc
// explain_rule { "rule_id": "OBS-3264-6.1-DIRECTION-UNMET" }
{
  "schema_version": 1,
  "rule_id": "OBS-3264-6.1-DIRECTION-UNMET",
  "title": "sendrecv negotiated, media observed one way",
  "severity": "warning",
  "basis": "observation",
  "rfc": 3264,
  "section": "6.1",
  "citation": "RFC 3264 §6.1",
  "url": "https://www.rfc-editor.org/rfc/rfc3264#section-6.1",
  "scope": "media",
  "rulesets": ["all", "observation", "observed", "rfc3264"],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

`rulesets` lists every selector that reaches this rule, so any entry passes
straight back as a `lint_dialog` `rulesets` value. `scope` says what the rule
has to read before it can run: `message`, `dialog` or `media`.

An unknown identifier returns invalid_params (-32602) listing all thirty-two,
because an empty answer would read as "that rule found nothing".

### `show_evidence`

Follows a frame pointer back to the bytes it names, turning one from a string
into something a reader can check without reopening the capture.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `refs` | string[] | At least one pointer in `<source>#<ordinal>@<digest>` form. An empty array fails with `refs must name at least one frame pointer`, because an empty result would read as "nothing resolved". | Required — the call fails. |
| `max_bytes` | u32? | 1 to 4096 bytes of hex per frame. Higher clamps to 4096, and to the frame length when the frame is shorter. **`0` means zero bytes here**, not the default — this is the one parameter on the surface that does not read `0` as "unset". | 256 bytes, enough for a SIP start line and its headers. |

A pointer whose `@digest` half is missing still resolves, and comes back
`unverified` rather than `verified`. Batching is the normal use — one bad
pointer never discards the rest, so each entry reports its own `status`.

**Not every tool returns a pointer, and the two that do use different key
names.** A caller planning around "every tool returns `frame_ref`" would look
for a key most responses do not carry:

- **`frame_ref`** — the findings `lint_dialog` and `validate_message` return.
  Named apart because a finding cites a message *index*, and the pointer is
  what makes it checkable without the list that index counts within.
- **`frame`** — `list_dialogs`, `find_problems`, `tail_dialogs`, `get_dialog`
  (its dialog and its messages), `get_message`, the JSON `get_dialog_report`,
  and the streams in `rtp_stats`.
- **No pointer at all** — `search_messages`, `search_by_time`,
  `find_correlated`, `triage_call`, `check_codec_negotiation`,
  `diagnose_registration`, `compare_dialogs`, `get_sdp_timeline`, the RTCP
  remote reports, and the capture-level counters.

A fact with no pointer omits the key entirely — never `""`, never frame 0, both
of which read as a real pointer.

The example follows the `frame` pointer that
[`list_dialogs`](#list_dialogs) returned for the first call in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
with `max_bytes` cut to 64 to keep the hex short:

```jsonc
// show_evidence { "refs": ["tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"],
//                 "max_bytes": 64 }
{
  "schema_version": 1,
  "requested": 1,
  "resolved": 1,
  "verified": 1,
  "summary": "1 of 1 pointer(s) resolved; 1 verified against a recorded digest",
  "frames": [
    {
      "pointer": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
      "status": "verified",
      "source": "sip-rtp-g711.pcap",
      "ordinal": 0,
      "frame_bytes": 500,
      "hex_bytes_shown": 64,
      "truncated": true,
      "hex": "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 01 e6 fe 17 40 00 40 11 22 cd 0a 00 02 14 0a 00 02 0f 13 c4 13 c4 01 d2 1a 06 49 4e 56 49 54 45 20 73 69 70 3a 74 65 73 74 40 31 30 2e 30 2e 32"
    }
  ]
}
```

`source` reports the bare filename, not the path the pointer carried — the tool
keeps only the final component and pushes it through the file-root guard. A
pointer that resolves to nothing keeps its entry and gains a `reason` instead of
the byte fields:

```jsonc
// show_evidence { "refs": ["bogus#1@deadbeef"] }
{
  "schema_version": 1,
  "requested": 1,
  "resolved": 0,
  "verified": 0,
  "summary": "0 of 1 pointer(s) resolved; 0 verified against a recorded digest",
  "frames": [
    {
      "pointer": "bogus#1@deadbeef",
      "status": "unresolvable",
      "reason": "cannot open '<file-root>/bogus': Failed to open pcap file ..."
    }
  ]
}
```

`status` has three values and they are deliberately not interchangeable:

| Status | Means |
|---|---|
| `verified` | The frame is there and its bytes hash to what the pointer recorded. The capture has not changed under the claim. |
| `unverified` | The frame is there, the pointer carried no `@digest`, so this checked **nothing**. The bytes could come from a rotated capture. |
| `unresolvable` | No bytes. `reason` says why — a malformed pointer, a source outside the file root, a frame past the end, or a digest mismatch. |

A digest mismatch is `unresolvable`, not a resolved frame with a warning.
Returning bytes from a capture that changed after someone made the pointer
would manufacture exactly the confidence this feature exists to provide.

The file root confines every source. A pointer carries whatever path the
producing run read, which usually sits outside the server's reach. The tool
therefore takes only the final component and pushes it through the same guard
the file tools use.
A pointer naming a live device or a HEP listener is `unresolvable`: sipnab
retains parsed messages, not frames, so there is nothing on disk to seek to.

One bad pointer never discards the rest of a batch — each gets its own entry, so
a caller can tell which one failed. `max_bytes` caps the hex per frame (default
256, maximum 4096) and `truncated` says when a frame was longer.

### `explain_response_code`

The IANA registry, not an agent's recollection.

**Parameters:** `code` (integer, required) — a SIP status code from 100 to 699.
Outside that range fails with `999 is not a SIP response code (100-699)`. No
optional parameters, and this tool reads no capture either, so it answers on a
server holding nothing.

```jsonc
// explain_response_code { "code": 488 }
{
  "schema_version": 1,
  "code": 488,
  "class": "failure",     // provisional|success|redirect|challenge|canceled|declined|failure
  "explanation": "488 Not Acceptable Here — Codec negotiation failed. Compare the SDP offer against the callee's supported codecs and ptime values.",
  "registered": true
}
```

`class` distinguishes a challenge from a failure: `401` is `challenge`, not
`failure`, because a challenged call has not failed — it is mid-handshake.
`registered: false` means the code is outside the registry, usually a vendor
extension. The tool says so rather than inventing a meaning.

### `find_correlated`

Finds the other legs of one call — the far side of a B2BUA, SBC or PBX hop.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds — the leg to correlate **from**. | Required — the call fails. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 legs. |

Returns `source_call_id`, `legs`, `total_matched`, `heuristic_only`,
`capture_identity`, `timing_clock` and `schema_version`. A leg the source has no
relationship with answers with an empty `legs` array and `total_matched: 0`,
never an error. There is no cursor — raise `limit` to reach past a truncated
answer, and a call with more than 1000 correlated legs is a capture problem
rather than a paging one.

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
whose two calls share an SDP origin:

```jsonc
// find_correlated { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "source_call_id": "1-1966@10.0.2.20",
  "legs": [
    { "call_id": "1-1968@10.0.2.20", "score": 90, "strategy": "sdp_origin",
      "identifier_match": true, "observed_gap_ms": null }
  ],
  "total_matched": 1,
  "heuristic_only": false,
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  },
  "timing_clock": null              // non-null only when a timing_heuristic leg is returned
}
```

**Read `strategy`, not just `score`.** Two strategies score 100 and they are not
the same claim:

| `strategy` | What it means | Survives a B2BUA? |
|---|---|---|
| `session_id` | [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) `Session-ID` matched | **Yes, by design** |
| `x_call_id` | A configured header matched (`X-Call-ID` by default) | Only if the SBC inserts it |
| `charging_vector_related_icid` | One leg's [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) `related-icid` names the other's `icid-value` | Yes — but only when the B2BUA chose to emit it (`MAY`) |
| `sdp_origin` | The [RFC 8866](https://www.rfc-editor.org/rfc/rfc8866) SDP origin tuple matched | Only if the SBC forwards SDP untouched |
| `charging_vector_icid` | Both legs carry the same RFC 7315 `icid-value` | Not by design: an ICID identifies one dialog, and a B2BUA is two |
| `via_branch` | Two INVITEs shared a Via branch | No: a new transaction gets a new branch |
| `timing_heuristic` | Same endpoint, close in time | Not an identifier at all |

**The two `P-Charging-Vector` rows are one header and two different claims.**
[RFC 7315 §4.6](https://www.rfc-editor.org/rfc/rfc7315#section-4.6) says the ICID identifies *a dialog*, so a conformant B2BUA emits
a different `icid-value` on each side and `charging_vector_icid` is silent
across it — a match there means some intermediary copied a per-dialog
identifier onto a second dialog, which no RFC grants. The parameter that
addresses the hop is `related-icid` (§4.6.4.1), and it is optional. Two limits
worth knowing before you rely on either: the first proxy generates the icid
(§5.6), so a leg arriving from an endpoint carries none and this is useless at
the access edge. And §4.6.2.2 lets the next hop *"modify the contents"*, which
§6.6 calls normal behavior, so unlike `Session-ID` there is no end-to-end
constancy requirement at all. Full argument:
[`docs/design/icid-correlation.md`](design/icid-correlation.md).

Neither strategy puts the matched value in the response. [RFC 7315 §4.6](https://www.rfc-editor.org/rfc/rfc7315#section-4.6)'s own
suggested construction embeds the generating proxy's hostname or address in the
icid, so it is operator-internal rather than opaque, and `strategy` names the
strategy and nothing else.

`identifier_match` carries that distinction as a boolean, so a caller can filter
on it without knowing which names mean what. `heuristic_only` says whether
*every* returned leg came from a guess — a call tree built only from timing is a
hypothesis, and an agent that cannot tell presents it as a finding.

`observed_gap_ms` appears **only** for `timing_heuristic`, because there it is
the evidence: a 15 ms gap on a quiet box and a 1,900 ms gap on a busy SBC score
identically and mean very different things. On an identifier match it is null,
since the elapsed time is not why they matched.

A caveat worth stating plainly: most deployments emit no correlation header at
all. Where none is present, the only strategy left is the bottom row, and on a
busy SBC unrelated calls routinely share an endpoint inside its window.

### `compare_dialogs`

"Why did this one work and that one not?"

**Parameters:** `call_id_a` and `call_id_b` (both string, both required) — two
Call-IDs the store holds. Either one unknown fails with `invalid_params` naming
it. No optional parameters, and passing the same Call-ID twice is legal and
answers with an empty `differences`.

Each side reports `call_id`, `state`, `final_status_code`, `msg_count`,
`methods` (sorted) and `hints`. `differences` names the fields that differ, so
you are not diffing two objects by eye. The example compares the two calls in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// compare_dialogs { "call_id_a": "1-1966@10.0.2.20", "call_id_b": "1-1968@10.0.2.20" }
{
  "schema_version": 1,
  "a": { "call_id": "1-1966@10.0.2.20", "state": "Completed", "final_status_code": 200,
         "msg_count": 6, "methods": ["ACK", "BYE", "INVITE"], "hints": [] },
  "b": { "call_id": "1-1968@10.0.2.20", "state": "InCall", "final_status_code": 200,
         "msg_count": 4, "methods": ["ACK", "INVITE"], "hints": [] },
  "differences": ["state", "msg_count", "methods"]
}
```

`final_status_code` matches on both sides here and so stays out of
`differences` — the second call simply never sent a `BYE`.

### `get_sdp_timeline`

The offer/answer exchanges in order — codecs, media address, port and mode per
negotiation, including re-INVITEs. Use it when audio changed mid-call, or when
the two ends disagree about the codec.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters.

Every exchange carries `direction` (`offer` or `answer`), `codecs`,
`media_addr`, `media_port`, `mode` (`sendrecv`, `sendonly`, `recvonly` or
`inactive`), `timestamp`, and `event` — `null` unless sipnab classified the
exchange, as with the `MediaAnchorChange` below. A call carrying no SDP answers
with an empty `exchanges` array rather than an error.

```jsonc
// get_sdp_timeline { "call_id": "1-1966@10.0.2.20" }
{
  "call_id": "1-1966@10.0.2.20",
  "exchanges": [
    {
      "codecs": [
        "PCMU"
      ],
      "direction": "offer",
      "event": null,
      "media_addr": "10.0.2.20",
      "media_port": 6000,
      "mode": "recvonly",
      "timestamp": "2016-11-26T14:52:59.666393+00:00"
    },
    {
      "codecs": [
        "PCMU",
        "telephone-event"
      ],
      "direction": "answer",
      "event": "MediaAnchorChange",
      "media_addr": "10.0.2.15",
      "media_port": 27942,
      "mode": "sendonly",
      "timestamp": "2016-11-26T14:52:59.670743+00:00"
    }
  ],
  "schema_version": 1
}
```

The offer promises `recvonly` on `10.0.2.20:6000` and the answer replies
`sendonly` from `10.0.2.15:27942`, which is why
[`triage_call`](#triage_call) calls this capture one-way media rather than a
fault.

### `search_by_time`

Returns dialogs whose first message falls in the window, oldest first.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `start` | string | An inclusive RFC 3339 instant, such as `"2026-07-31T14:00:00Z"`. A malformed one fails with `start 'x' is not RFC 3339`. | Required — the call fails. |
| `end` | string? | An exclusive RFC 3339 instant after `start`. At or before `start` fails with `invalid_params` (-32602). | Everything from `start` onward. |
| `filter` | string? | An alias name or a raw [DSL](filter-dsl.md) expression, ANDed with the window. | The window alone decides the page. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest dialog in the window. |

**Returns** `{ dialogs, returned, total_matched, truncated, next_cursor,
capture_identity, schema_version }`.
Each row carries `call_id`, `created_at`, `state` and `final_status_code` —
**a narrower row than [`list_dialogs`](#list_dialogs) returns**, with no
`msg_count`, no `from_user`, no `timing` and no `frame`. No markers appear
here either, because none of those four fields is free text. Feed a `call_id` to another
tool when you need the rest.

`total_matched` counts every dialog in the window before `limit` applies, so a
small answer from a quiet window reads differently from a truncated one.

`filter` turns "failed calls between 14:00 and 14:05" into a single call. The
window narrows first and the filter runs over what survives.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng). The
same window without a filter answers `total_matched: 247`:

```jsonc
// search_by_time { "start": "2016-11-17T21:52:35Z", "end": "2016-11-17T21:53:00Z",
//                  "filter": "problems", "limit": 2 }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-10-synth@192.0.2.10",
      "created_at": "2016-11-17T21:52:36.203349+00:00",
      "final_status_code": 403,
      "state": "Failed"
    },
    {
      "call_id": "call-25-synth@192.0.2.10",
      "created_at": "2016-11-17T21:52:37.703349+00:00",
      "final_status_code": 403,
      "state": "Failed"
    }
  ],
  "returned": 2,
  "total_matched": 16,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:37.703349+00:00|call-25-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "12100b18cb6971cf461cff-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

**`truncated: true` is not a dead end.** Pass `next_cursor` back to
continue through the window. `total_matched` keeps counting the whole window
rather than the remainder, so it does not shrink as you page — without a
cursor the only way past a truncated window would be to narrow it, putting
every row past the 1000-row ceiling out of reach. The cursor is
the same compound form [`list_dialogs`](#list_dialogs) issues, and it is opaque:
pass it back exactly as it arrived.

### File tools — the shared rule

`list_captures`, `export_capture` and `export_audio` all require
`--mcp-file-root <DIR>` and refuse to run without it. They take a **bare
filename, never a path**.

sipnab refuses `../x`, `/etc/passwd` and `sub/dir.pcap` before any filesystem
call. That is the whole security model and it is deliberately absolute: a tool
accepting an agent-supplied path is an arbitrary file write, not an export.

Name checking alone does not finish the job, so sipnab does one more thing. A
symlink already sitting in the root is a single bare component — it passes every
check above, and the kernel follows it when the file opens. sipnab therefore
compares the resolved path against the root in its fully resolved form and refuses a name by
where it points rather than by how someone spelled it. Each tool returns the
resolved path, so a caller learns where the bytes actually went.

That escape needed prior write access inside the root, so it never amounted to a
remote break. sipnab closes it because this page calls the boundary absolute, and
a boundary described that way ought to be.

> **The boundary stops an escape, and an overwrite.** Inside the root,
> `export_capture`, `export_audio` and `shutdown_server`'s `save_to` refuse a
> filename that already exists, name the file, and ask for one that is free.
> sipnab declines to write over a file it did not create, because that file may
> hold the only copy of a capture. Call
> [`list_captures`](#list_captures) to see which names a directory already
> uses.
>
> The guard covers every capture in the root, not only the one the run is
> reading. Narrowed to the current capture it would miss the others staged
> there for [`open_capture`](#open_capture), and every earlier export, which
> then fall to a name collision on a call that reports success.

### `list_captures`

Capture files in the configured root, with sizes.

**Parameters:** none.

**It lists `.pcap` and `.pcapng` only**, matched case-insensitively, and skips
directories. That is narrower than what [`open_capture`](#open_capture) accepts,
which is any readable capture the name resolves to — a `.cap` file sitting in
the root opens fine and never appears here, so an agent that treats this listing
as the whole set it may open misses it. Ask the operator, or try the name.

```jsonc
list_captures {}
```

Without `--mcp-file-root` the whole file-tool group is off, and this answers
with a refusal rather than an empty list — "no directory configured" and "the
directory is empty" are different facts:

```jsonc
{ "code": -32602,
  "message": "file tools are disabled: start sipnab with --mcp-file-root <DIR>" }
```

Otherwise it answers with `captures` sorted by filename, plus
`schema_version`. Running it against `tests/pcap-samples` returns 29 of the
directory's 35 entries. The six it leaves out are five `.cap` captures and one
directory:

```jsonc
// list_captures {}
{
  "schema_version": 1,
  "captures": [
    { "filename": "Asterisk_ZFONE_XLITE.pcap", "bytes": 255581 },
    { "filename": "DTMFsipinfo.pcap", "bytes": 25429 },
    { "filename": "b2bua-asterisk.pcapng", "bytes": 114952 }
    // ... 26 more
  ]
}
```

### `export_capture`

Writes the SIP signaling sipnab is holding to a pcap. Use it to preserve
signaling **before** stopping a live capture — otherwise the messages end with
the process.

> **The file is not a copy of the capture.** sipnab keeps parsed messages, not
> the frames that arrived, so the export rebuilds one Ethernet/IP/UDP frame
> around each message. The SIP layer is faithful. Everything under it is
> reconstructed from the addresses and ports sipnab recorded.
>
> Concretely, the file holds **no RTP, no RTCP and no non-SIP traffic**, and
> writes a SIP-over-TCP message as UDP. On one measured export, 4,875 of the
> 5,000 packets that had been on the wire were absent.
>
> That matters beyond the analysis, because the output is a pcap and people
> forward pcaps. If the file is going to a carrier, a regulator or a court, say
> what it is — nothing inside it announces that the frames were rebuilt.

**Parameters:** `filename` (string, required) — a bare filename inside
`--mcp-file-root`. A path component of any kind fails with `'../escape.pcap' is
not a bare filename`. sipnab does **not** require a `.pcap` extension and does
not add one, so `notes.txt` writes a pcap under that name, which
[`list_captures`](#list_captures) then never lists. No optional parameters.

Returns `path` (the resolved absolute path, so you learn where the bytes went),
`messages`, `bytes` and `schema_version`:

```jsonc
// export_capture { "filename": "sig.pcap" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/sig.pcap",
  "messages": 10,
  "bytes": 5673
}
```

### `export_audio`

Writes one call's RTP audio to a WAV in the configured root. Fails when the
call carries no audio it can decode, rather than writing an empty file.

Requires `--retain-audio` on the server command line: call audio is
content, not signaling, so holding it in memory is an operator decision
rather than a side effect of enabling MCP. Without the flag the tool refuses,
and its refusal reports the media it measured and names the flag — a capture
setting, not a finding that the call was silent.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID whose streams carry audio sipnab can decode. | Required — the call fails. |
| `filename` | string | A bare filename inside `--mcp-file-root`, under the same rule `export_capture` applies. sipnab writes a WAV whatever extension you give it. | Required — the call fails. |

Returns `path`, `summary` and `schema_version`:

```jsonc
// export_audio { "call_id": "1-1966@10.0.2.20", "filename": "call.wav" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/call.wav",
  "summary": "Exported 8.5s of mu-law audio (425 frames, PCMU/8000Hz) to /var/spool/sipnab-exports/call.wav"
}
```

Without `--retain-audio` the refusal arrives as `internal_error` (-32603) rather
than `invalid_params`, and it reports what sipnab measured so the answer cannot
read as a silent call:

```text
No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1
decodable stream, but kept none of their payload, so there is nothing to
decode. Audio payload retention was off for this run — that is a capture
setting, not a finding that the call was silent. Start the server with
--retain-audio to hold payload for export.
```

### `export_vcon`

One observed dialog as a **vCon** conversation container
([`draft-ietf-vcon-vcon-core`](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/),
syntax `0.4.0`) — the interchange format a conversation travels in once it
leaves the system that captured it. Backed by
[`output::vcon`](https://github.com/NormB/sipnab/blob/main/src/output/vcon.rs).
`--export-vcon` writes the same container from the CLI.

Unlike its file-writing neighbors this tool writes nothing and needs no
`--mcp-file-root`. It returns the container inline, so `read_only_hint` is
`true` and the agent decides what to do with it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `invalid_params` (-32602) naming the value. | Required — the call fails. |

There is no `format`. A vCon IS a JSON container defined by the draft, so a
markdown arm would render a document whose whole purpose is to travel between
machines — and an agent offered one would eventually hand the prose to
something expecting a container.

**What sipnab claims, and what it refuses to claim.** The container is an
**observer** vCon and says so in its own parties. sipnab read a mirror port: it
did not place the call, record it, or obtain anyone's permission to keep it. So
four things are absent by design, and their absence is the message:

- **No signature and no encryption.** A JWS over this container reads as *the
  domain that constructed this vouches for it*. What sipnab could truthfully
  sign is *these bytes are what sipnab observed*, and no signature algorithm
  carries that distinction. A verifier would check it, get back "authentic",
  and draw the wrong conclusion.
- **No party `name`, ever, and `validation` is always `"none"`.** `From` and
  `To` are a claim the sender made about itself. The display name travels under
  `sip_display_name` instead, so a reader sees it as what a header said.
- **No consent and no lawful-basis attachment.** An empty consent field reads
  as "nobody recorded consent", a statement about the CALL. The truth is a
  statement about the producer: sipnab was never in a position to record one.
- **No `url`, ever.** Media travels INLINE or not at all, because sipnab hosts
  nothing a URL could reach and a dead link inside a record is
  indistinguishable from evidence somebody removed.

**What happens to the audio.** `dialog.type: "recording"` is a FORMAT term for
a Dialog Object carrying media. A consumer's `recordings` table is a PROVENANCE
term for containers from an in-path recorder. sipnab emits the first and is
never the second: it reconstructed the audio from a mirror port, and every WAV
it writes says "not a recording made by the endpoints".

So audio the run RETAINED travels inline -- base64url, `mediatype:
"audio/x-wav"`, and a `content_hash` of `sha512-` plus the base64url SHA-512 of
the DECODED bytes, which `sha512sum` on the exported `.wav` reproduces. The
`duration` on that object is the FILE's, never the call's. When a payload ring
dropped frames, a `recording-set` wraps it carrying the CALL's media window, so
the two clocks stand side by side -- that is the only way the format can say
"this file is a fragment of that call".

`capture_completeness.media` says which of four things happened, so nobody has
to read a missing `recording` object as an answer:

| `media` | What it means |
|---|---|
| `carried` | The audio is inline in a `recording` Dialog Object |
| `refused-over-budget` | sipnab decoded audio and REFUSED to inline it. One probed store answers 204 and drops a payload over 10485760 bytes without telling the producer, so the emitter enforces a 5 MiB budget itself. The audio exists and was not truncated |
| `none-decodable` | The run decoded no audio. `media_note` reports the measurement -- never that the call was silent |
| `not-considered` | Nobody asked this export for media. A fact about the export, not about the call |

**What the capture MISSED travels with the container, in two places.** vCon has
no field meaning "this record is incomplete" — `dialog.type: "incomplete"` says
the CALL did not complete, which accuses the traffic rather than the tap. So the
caveat rides in the `analysis` object AND in a `sipnab-capture-completeness`
attachment, both built from ONE value so the two cannot contradict each other.
Read `capture_completeness.note` before the contents: every clause in it is a
measurement of what this run READ and dropped.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// export_vcon { "call_id": "1-1966@10.0.2.20" }
{
  "vcon": "0.4.0",
  "uuid": "0158a120-0392-86a4-a667-78f1c5213800",
  "created_at": "2026-08-24T22:13:31.238368261+00:00",
  "extensions": ["sip-signaling", "CC"],
  "parties": [
    {
      "sip": "sip:sipp@10.0.2.20:5060",
      "sip_contact": "sip:sipp@10.0.2.20:5060",
      "sip_display_name": "PCMU/8000",
      "validation": "none"
    },
    {
      "sip": "sip:test@10.0.2.15:5060",
      "sip_display_name": "test",
      "sip_user_agent": "FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit",
      "validation": "none"
    },
    {
      "role": "observer",
      "sip_user_agent": "sipnab/0.5.124 (observer; node capture-01)",
      "validation": "none"
    }
  ],
  "dialog": [ { "sip_call_id": "1-1966@10.0.2.20" } ],
  "attachments": [
    {
      "purpose": "sip-message-trace",
      "party": 2,
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "sip_call_id": "1-1966@10.0.2.20", "messages": [ /* the same objects --json emits, one per message */ ] }
    },
    {
      "purpose": "sipnab-capture-completeness",
      "party": 2,
      "mediatype": "application/json",
      "encoding": "json",
      "body": {
        "note": "Produced by sipnab 0.5.125 on node capture-01. sipnab OBSERVED this dialog and took no part in it: ... sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
        "node": "capture-01",
        "sipnab_version": "0.5.124",
        "frames_read": 852,
        "undecodable_frames": 0,
        "sip_discarded_by_port_gate": 0,
        "sip_discarded_by_websocket_gate": 0,
        "messages_evicted": 0,
        "dialogs_refused": 0,
        "dialogs_rotated": 0,
        "blind_spots": [],
        "media": "none-decodable",
        "media_note": "No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1 decodable stream, but kept none of their payload, so there is nothing to decode. This is a statement about what this run kept, not a finding that the call was silent. ..."
      }
    }
  ],
  "analysis": [
    {
      "type": "report",
      "dialog": 0,
      "vendor": "sipnab",
      "product": "sipnab 0.5.125 (passive observer; not a recording system)",
      "schema": "sipnab-dialog-diagnosis/1",
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "sip_call_id": "1-1966@10.0.2.20", "final_status_code": 200, "capture_completeness": { /* the same object the attachment carries */ } }
    }
  ]
}
```

An unknown Call-ID answers with an error, never an empty container:

```jsonc
// export_vcon { "call_id": "no-such@nowhere" }
{ "code": -32602, "message": "call_id 'no-such@nowhere' not found" }
```

**Three things a reader must not conclude.**

`blind_spots: []` is not the same answer as an absent `blind_spots`. The empty
array means a capture analysis ran and ranked nothing. The absent field means
nobody looked. Both doors here always run the analysis, so an absent field on a
container from this tool would be a defect rather than a clean bill.

The observer party is always the LAST entry, and every attachment's `party`
index points at it. Do not hard-code `2`: the count changes the day a container
carries a party the two observed headers did not name.

`uuid` is a UUIDv8 whose timestamp half is the DIALOG's, not the export's, so
re-exporting one dialog out of one capture keeps one identifier and a consumer
can deduplicate on it. Two dialogs that opened in the same millisecond on the
same node have only 12 bits separating them — that is inherent in the draft's
layout, which spends a v7's entropy on a host-derived `rand_b`.

A binary built without the `vcon` Cargo feature refuses this tool with
`invalid_params` and names the feature, rather than the tool being absent.
[`server_capabilities`](#server_capabilities) lists what a given binary carries.

### `shutdown_server`

**Destructive.** Requires `--mcp-allow-shutdown`, which is off by default.
Without it every call fails, whatever the arguments say:

```text
shutdown is disabled: start sipnab with --mcp-allow-shutdown to permit it.
A stock server cannot be stopped by an agent.
```

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `dry_run` | bool? | `true` reports what would happen. `false` stops the process. | **`true`** — the safe value is the default, so stopping takes a deliberate second call. |
| `save_to` | string? | A bare filename inside `--mcp-file-root` to write the capture to before stopping. | sipnab writes nothing. On a live capture holding unsaved packets, the call then refuses unless `discard_unsaved` is `true`. |
| `discard_unsaved` | bool? | `true` accepts losing the packets a live capture holds in memory. | `false` — a live capture with unsaved packets refuses to stop. |

Returns `dry_run`, `would_stop`, `live`, `unsaved`, `dialogs`, `streams`,
`saved_to`, `note` and `schema_version`. Read `would_stop` rather than assuming:
it is `false` on a dry run and on a refusal alike, and `note` says which.

```jsonc
// shutdown_server {}   — no arguments means DRY RUN
{
  "schema_version": 1,
  "dry_run": true,
  "would_stop": false,
  "live": false,
  "unsaved": false,
  "dialogs": 13,
  "streams": 2,
  "saved_to": null,
  "note": "dry run — nothing stopped. Call again with dry_run=false to stop."
}
```

Stopping takes a deliberate second call with `dry_run: false`. On a **live**
capture holding packets written nowhere, it refuses outright unless you pass
`save_to` or `discard_unsaved: true` — losing a capture to a misread sentence
is the failure worth engineering against.

### `open_capture`

**Destructive.** Requires `--mcp-allow-open-capture`, which is off by default.
It loads another capture from `--mcp-file-root` and throws away every dialog and
stream the server holds.

Use it on a long-lived HTTP server working through a corpus, where a restart
costs an operator their session. In either stdio shape, starting sipnab again
with a different `-I` does the same job and leaves a clean store behind, so
prefer that.

**Parameters:** `filename` (string, required) — a bare filename inside
`--mcp-file-root`, under the rule every file tool applies. Unlike
[`list_captures`](#list_captures), any capture format libpcap reads is fine,
`.cap` included. No optional parameters, and no way to ask for a merge: this
replaces the stores rather than adding to them.

Returns `status` (`"loading"`), `filename`, `path`, the **new**
`capture_identity`, `discarded_dialogs`, `note` and `schema_version`.

```jsonc
// open_capture { "filename": "outage-0722.pcap" }
{
  "schema_version": 1,
  "status": "loading",
  "filename": "outage-0722.pcap",
  "path": "/var/spool/sipnab-captures/outage-0722.pcap",
  "capture_identity": {
    "node": "capture01",
    "instance": "1f4a17c8e2b91d40-2",
    "dialog_generation": 1,
    "stream_generation": 1
  },
  "discarded_dialogs": 128,
  "note": "the previous capture is gone; poll capture_status until load.done is true, and treat every answer carrying a different capture_identity.instance as a different capture"
}
```

The call returns as soon as the background read starts, not when it finishes.
That is deliberate: the REST API and the MCP server share one runtime thread, so
a multi-gigabyte read inside the handler stops every other client for its
duration. Poll `capture_status` and watch `load.packets` climb until
`load.done` turns true.

**Every answer afterwards carries a new `capture_identity.instance`.** Treat any
cursor, message index or Call-ID from before the swap as void — they addressed a
different capture. `discarded_dialogs` says how much analysis the call threw
away, so an agent can report the cost rather than discover it.

Four refusals, each naming what to do instead:

| Refusal | Why |
|---|---|
| `--mcp-allow-open-capture` missing | The operator did not enable it. The tool is still listed, because "not permitted here" and "this build cannot" are different answers |
| The source is a live interface | A live capture's writer never stops, so a second writer would race it for the life of the process. No opt-out |
| The source has not drained | The original reader is still filling the stores. Poll `capture_status` until `source_exhausted` is true |
| A load is already running | Poll `capture_status` until `load.done` is true |

A filename must be a bare name inside the root, under the same rule every file
tool applies. sipnab also refuses a capture that belongs to this run's own `-I`
set, with the output guard's wording about overwriting — that file is already
loaded, and reading it again under a new identity would duplicate what the store
holds.

### `save_findings`

**The only write verb on sipnab's network surface.** Requires
`--mcp-allow-save-findings`, which is off by default.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `summary` | string | A one-line conclusion. sipnab clips it at 500 characters and reports the original length. | Required — the call fails. |
| `call_id` | string? | Any string. **Not checked against the store**, deliberately: a note about a call the store has since dropped is still the note that mattered. | The finding records no call. |
| `detail` | string? | Supporting text, clipped at 4096 characters. | The finding carries a summary alone. |

```jsonc
// save_findings { "summary": "audit probe", "call_id": "1-1966@10.0.2.20", "detail": "x" }
{
  "schema_version": 1,
  "seq": 0,
  "written_at": "2026-08-13T12:12:17.976455577+00:00",
  "summary_chars_submitted": 11,
  "detail_chars_submitted": 1,
  "truncated": false,
  "recorded_total": 1,
  "remaining": 999,
  "readable_over_mcp": false,
  "delivered_to": "sipnab log (tracing/journald/stderr)",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

`readable_over_mcp: false` is a constant, not a state. It appears on every
response so a client never has to infer the dead end from the absence of a
reader.

It records what the agent concluded, and that is all it does. **The finding goes
to sipnab's log and nowhere else**: no tool reads it back, it appears in no query
result, and no analysis consumes it. There is no `list_findings`, deliberately.

That dead end is the entire safety argument. Every response on this surface
carries attacker-controlled text — `From` display names, `User-Agent` strings,
raw message snippets — so a write verb reachable from that text must not be able
to change what an operator is reading, or to come back later as evidence the
agent then cites. The compiler enforces this rather than convention: the
annotation types stay private to the MCP module, so no analysis code can name
them.

Read your findings where operational facts already live — `journalctl -u sipnab`,
syslog, or stderr. Each line records the agent's claim as the agent's claim,
never as a measurement of sipnab's own.

Two bounds, both reported rather than silent. sipnab clips text at 500
characters of `summary` and 4096 of `detail`, setting `truncated` and
`*_chars_submitted` giving the original length. And one process accepts 1000
findings, after which writes are **refused** with an error naming the limit —
never accepted and discarded, because an agent told "recorded" about something
the server threw away is worse off than one told plainly that it was not.
`remaining` counts down so the bound is visible before it bites.

### `capture_status`

**Ask this first.** It answers what the server is actually attached to — a live
interface or a replayed file — which nothing else on this surface reveals.

No parameters. Returns:

```jsonc
{
  "schema_version": 2,           // 2 absorbed the counters the old stats tool returned
  "source": "live",              // "live" | "file" | "unknown"
  "name": "eth0",                // interface, or file path
  "uptime_sec": 3612,
  "dialog_count": 128,
  "stream_count": 64,
  "orphaned_stream_count": 3,    // streams no dialog claims
  "active_dialog_count": 12,     // any non-terminal state
  "active_call_count": 9,        // InCall only — narrower, hence the version bump
  "capture_quality": {
    "kernel_dropped_packets": 0,
    "interface_dropped_packets": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 0,
    "degraded": false
  },
  "caveats": {
    "media_creating_commands": 0  // relay commands seen and NOT attributed
  },
  "source_exhausted": false,     // true once a file is read to the end
  "writing_to": null,            // path packets are being saved to, if any
  "unsaved": true,               // stopping now would lose packets
  "capture_identity": {
    "node": "capture01",
    "instance": "1f4a17c8e2b91d40-1",
    "dialog_generation": 412,
    "stream_generation": 96
  },
  "unanalysed_sip_messages": 0,  // SIP that --portrange excluded
  "unanalysed_busiest_ports": [],
  "unanalysed_websocket_messages": 0,  // SIP-over-WebSocket the WS port set excluded
  "unanalysed_websocket_ports": [],    // pass these to --ws-portrange
  "load": null                   // an open_capture load in flight, if any
}
```

`unsaved` is the field that matters. It is `true` only for a **live** capture
with no output file — packets held in memory and nowhere else. A file replay is
already on disk, so it is never unsaved.

`source: "unknown"` means nobody gave the server capture context. It
reports that rather than guessing, because a wrong `"live"` would be worse than
an admission of ignorance.

`capture_identity` says which capture this is and how many times its stores have
changed. Compare it across calls: a higher generation on the same instance means
the capture grew, and a different instance means `open_capture` loaded a
different file and every cursor you hold is void. The same object appears on
`capture_status`, `list_dialogs`, `find_problems`, `tail_dialogs`, `find_correlated`,
`save_findings`, `open_capture` and the capture-wide `rtp_stats` sweep. `node` names
the box that answered, which decides whose capture a fact came from once an agent
holds several servers at once.

`load` is null except while an `open_capture` read runs. During one:

```jsonc
"load": {
  "filename": "outage-0722.pcap",
  "instance": "1f4a17c8e2b91d40-2",
  "packets": 184320,             // climbing
  "elapsed_sec": 4,
  "done": false,
  "error": null                  // set when a load stopped early
}
```

The stores fill as the read goes, so dialogs appear before `done`. Wait for
`done` before concluding anything about how many calls the capture holds — a
partial answer looks exactly like a complete one.

Read the two `unanalysed_` pairs before reading anything into `dialog_count`.
They report SIP that sipnab recognized and did not analyze, and they are the
only way to tell a capture that holds no calls from one whose calls fell
outside a port setting. They count different losses with different
remedies, so a non-zero figure names its own flag:

- `unanalysed_sip_messages` / `unanalysed_busiest_ports` — plain SIP signaling
  with both ports outside `--portrange`. Re-run with a range that covers the
  ports listed.
- `unanalysed_websocket_messages` / `unanalysed_websocket_ports` —
  SIP-over-WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118)) on a
  port outside the WebSocket set. Re-run with `--ws-portrange` covering the
  ports listed; widening `--portrange` recovers none of it. This is the common
  case on a WSS listener behind a reverse proxy, and on Kamailio, OpenSIPS and
  Janus, which all default outside sipnab's shipped 80/443/8080/8443.

Both are zero on a live capture, where BPF filtered before the pipeline saw
anything and there is nothing to under-report.

#### What the capture DECLINED — `caveats`

`capture_quality` above counts what the capture **lost**. `caveats` counts what
sipnab **chose not to do**, which is a different thing and is not a defect.

| Key | What it counts |
|-----|----------------|
| `media_creating_commands` | rtpengine `subscribe`, `publish` and `start recording` commands seen and deliberately not attributed |
| `tls` | TLS decryption state — **absent** unless a decryptor ran |

Those commands create media belonging to a call without being one of its two
legs. Decoding one as an ordinary leg would make a two-party call report three
streams, after which the analysis that judges one-way audio and asymmetry
answers a question nobody asked — so sipnab counts them instead.

**Read this before reasoning about a stream count.** A call with a recording
fork has media on the wire that no `rtp_stats` row explains, and this number is
how you know that is a decision rather than a gap. Zero is a real
answer and the key is always present.

##### `caveats.tls` — is decryption working?

Absent when nobody supplied keys, which is not a decryption failure. When a
decryptor ran, the block carries `keylog_entries`, `sessions_with_keys`,
`app_data_records`, `decrypted_records`, `undecrypted_records`,
`late_recovered`, `late_evicted` and `read_nothing`.

**Act on `read_nothing`, never on the arithmetic.** A TLS handshake carries
records sipnab never loads keys for, so `app_data_records > decrypted_records`
is not by itself a failure — an agent deriving a verdict from the two counts
reports a working capture as broken and sends an operator after keys that
already work. `read_nothing` is `true` only when application data arrived and
none of it opened.

That case is why the block exists. A capture holding ciphertext nobody can open
produces a dialog listing identical to one from a quiet network. If you are
about to answer "there was no SIP on this capture", check this field first:
`server_capabilities.can_decrypt` says whether the BUILD can decrypt, and this
says whether this RUN did.

`GET /v1/stats` carries the same block under the same name.

### `server_capabilities`

What this binary can do and what this server permits. Ask before requesting
decryption, HEP, a file export or a capture swap: a build without the feature,
or a server without the flag, fails confusingly otherwise.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "version": "0.5.125",
  "features": ["api", "hep", "mcp", "native", "tls", "tui"],
  "can_decrypt": true,           // tls
  "can_hep": true,               // hep
  "can_plugins": false,          // plugins
  "runtime": {
    "mcp_file_root": "/var/spool/sipnab-captures",  // null when unset
    "mcp_allow_shutdown": false,
    "mcp_allow_open_capture": true,
    "mcp_allow_save_findings": false
  }
}
```

`features` comes from `cfg!` at compile time, so it cannot claim a feature the
binary does not have. `runtime` is a different question — what the **operator**
turned on — and no compile-time check can answer it. Without it an agent
discovers the setup by calling a tool and collecting a refusal, and a refusal
mid-investigation reads as a dead end rather than as a server it was never
allowed to use that way.

### `list_tls_libraries`

Which TLS libraries processes on this host are **actually mapping**, and
whether sipnab could attach a uprobe to read their plaintext. Ask before
concluding that reading SIP over TLS needs keys — and read
`privileged` and `probe_path` before concluding it can.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "supported": true,          // false off Linux, or without the `native` feature
  "privileged": true,         // running as root
  "libraries": [
    {
      "flavor": "OpenSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libssl.so.3",
      "inode": 21143,         // the identity; the PATH is not unique
      "process_count": 12,
      "symbol": "SSL_write",
      "probe_path": "/proc/954/root/usr/lib/aarch64-linux-gnu/libssl.so.3"
    },
    {
      "flavor": "wolfSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libwolfssl.so.42.2.0",
      "inode": 17433084,
      "process_count": 1,
      "symbol": "wolfSSL_write",
      "probe_path": null      // in use, but NOT capturable from here
    }
  ],
  "unreachable_count": 1,
  "summary": "1 of 2 TLS libraries could be read with `sipnab --uprobe-tls`, without any key or certificate. 1 cannot be reached from this server's mount namespace and would be missed."
}
```

**Read `privileged` before believing an empty list.** Unprivileged,
`/proc/<pid>/maps` is readable only for the server's own processes, so a short
list is evidence about privilege rather than about the host. `summary` says
which of the two situations produced the answer, so a relayed conclusion does
not lose it.

**`probe_path: null` is a finding, not a blank.** That library is carrying
traffic sipnab cannot capture — usually a containerised process whose
`/proc/<pid>/root` this server cannot read. sipnab reports it rather than
dropping it, because the alternative is a capture that looks complete and is
not.

`inode` is there because `path` is **not** unique: the same string names
different files in different mount namespaces, and on an ordinary host with
containers several distinct `libssl.so.3` files coexist.

### `start_tls_capture`

Installs kernel uprobes on this host's TLS libraries and reads SIP plaintext
from them — no key, no certificate, and no restart of the process observed.

**Needs `--mcp-allow-tls-capture`.** It is off by default and separate from
`--mcp-allow-open-capture`, because it is a different act: that one reads a
file an operator placed in a directory, this one attaches probes to a running
process's TLS library and reads its plaintext.

Call [`list_tls_libraries`](#list_tls_libraries) first.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `flavors` | array of string | every one found | `openssl`, `wolfssl` |
| `libraries` | array of string | discover | probe these paths instead of discovering |

```jsonc
// start_tls_capture { }                                  // every library found
// start_tls_capture { "flavors": ["openssl"] }          // one flavor only
// start_tls_capture { "libraries": ["/proc/954/root/usr/lib/libssl.so.3"] }
{
  "schema_version": 1,
  "running": true,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 0,
  "lost": null,
  "uptime_sec": 0,
  "error": null,
  "summary": "Probing 1 TLS library. ..."
}
```

**Three refusals, each before any kernel state exists**, and each says which
one it is rather than a bare failure:

- **not root** — sipnab drops privileges after opening its capture devices, so
  a server started with `--user` cannot attach probes later;
- **a live source is already running** — sipnab's stores have one writer, so a
  uprobe capture cannot run beside one;
- **a capture is still loading** — poll `capture_status` until `load.done`.

**An attach failure arrives later, not here.** A background thread installs
the probes, so the call returns as soon as that thread starts. Poll
[`stop_tls_capture`](#stop_tls_capture) or `capture_status` to see whether
messages actually arrive.

### `stop_tls_capture`

Stops the running capture and removes its kernel probes. Safe to call when
nothing is running — it says so rather than failing.

No parameters. Returns:

```jsonc
// stop_tls_capture { }
{
  "schema_version": 1,
  "running": false,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 412,
  "lost": 0,          // records the kernel DROPPED: messages that existed and are missing
  "uptime_sec": 96,
  "error": null,
  "summary": "The TLS capture has stopped and its probes are removed."
}
```

**Keep calling until `running` is false.** The stop is a request: the worker
owns the probes and removes them on its way out, which is a kernel round trip
per probe. Probes left installed cost every process that maps the library, and
they outlive sipnab.

`lost` is worth reading. It counts records the kernel dropped because the
reader fell behind — messages that existed and are missing, which is a
different fact from a quiet trunk and the only one you cannot discover any
other way. The dialogs already collected stay in the store after the stop.

### `capture_health`

Reads the capture counters, waits, and reads them again. The response carries
the run totals **and** the change across that window, which turns a pile of
monotonic counters into a rate.

`sample_seconds` is **required** — this tool has no default window, because a
rate without a stated interval is not a rate. The call blocks for that long:

```jsonc
capture_health { "sample_seconds": 1 }
```

`capture_status` tells you what the counters say right now. `capture_health` tells you
what they did over a window you chose, which is the difference between "this
process has dropped 4 million packets since Tuesday" and "this process is
dropping packets **now**".

Three questions it answers on a busy production server:

1. **Does the capture path drop packets under load?** Read
   `in_window.kernel_dropped` and `in_window.interface_dropped`. They stay
   apart because their fixes disagree — a bigger ring buffer cures the first
   and does nothing for the second.
2. **What is on this wire that sipnab cannot decode?** Read
   `undecodable_by_reason`. Each entry names the reason as a code and carries
   the number that identifies it: the link type, the EtherType, or the IP
   protocol.
3. **What does the encapsulation-aware capture filter cost?** Run the same
   window twice, once with `--capture-tunnels` and once without, and compare
   `in_window.packets` against the two drop counters.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `sample_seconds` | u32 | 1 to 30. A larger value clamps to 30, and `window.requested_seconds` beside `window.applied_seconds` reports both. Zero fails with `sample_seconds must be at least 1`. | Required — the call fails. This tool is the one place with no default, because a rate without a stated interval is not a rate. |

**The call blocks for the whole window**, so a client with a short request
timeout should ask for a few seconds rather than 30.

Returns:

```jsonc
{
  "schema_version": 1,
  "attachment": 2,
  "window": {
    "requested_seconds": 10,
    "applied_seconds": 10,
    "observed_ms": 10003
  },
  "totals": {
    "packets": 8412990,
    "kernel_dropped": 1204,
    "interface_dropped": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 2103247
  },
  "in_window": {
    "packets": 94318,
    "kernel_dropped": 17,
    "interface_dropped": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 23610
  },
  "undecoded_fraction": 0.24999999,
  "undecoded_fraction_in_window": 0.2503,
  "undecodable_by_reason": [
    { "reason": 2, "number": 34887, "frames": 2061109, "frames_in_window": 23140 },
    { "reason": 3, "number": 47,    "frames": 41022,   "frames_in_window": 465 },
    { "reason": 4, "number": null,  "frames": 1116,    "frames_in_window": 5 }
  ],
  "undecodable_reasons_dropped": 0,
  "dialogs_tracked": 2411,
  "streams_tracked": 4802,
  "clock": {
    "synchronized": true,
    "max_error_us": 238000,
    "est_error_us": 0,
    "available": true
  }
}
```

> **This tool starts no capture.** With `--mcp` attached to a live interface,
> the counters already accumulate, so a rate costs two reads and a wait. That
> is not only the cheap design, it is the safe one: the handler opens no
> device, names no interface, and writes no file, so no path leads from an MCP
> call to a capture that transmits or records anything.

> **No value in this response is a string.** The response type holds integers,
> codes, two proportions and the clock's booleans, and it has no string field
> anywhere in it or in anything nested inside it. A type that cannot represent packet
> content cannot leak packet content, which is why the reasons below travel as
> codes and their labels live on this page instead of on the wire. The test
> `a_populated_capture_health_response_carries_no_string_value_anywhere`
> serializes a full response and fails on any string value at any depth.

#### `attachment` — what this server has packets from

| Code | Meaning |
|---|---|
| `1` | Nothing attached. No capture context reached this server. |
| `2` | A live interface. |
| `3` | A capture file replaying. |

Code `1` exists so that a server with nothing to read says so. A row of zeros
from a tool that never had a capture looks exactly like a healthy quiet wire,
and no code is `0`, so a defaulted or truncated response can never pass for a
real answer.

#### `undecodable_by_reason` — the reason codes

| `reason` | Meaning | What `number` carries | Where to start |
|---|---|---|---|
| `1` | The pcap link type has no decoder here | The DLT number | `editcap -T ether` converts a `DLT_NULL` (0) or `DLT_LINUX_SLL` (113) file |
| `2` | The link layer named a payload that is not IP | The EtherType, or `null` when the link layer records none | `34887` is `0x8847`, so the mirror carries MPLS. `2054` is ARP, which every Ethernet capture carries and nothing needs to decode |
| `3` | An IP header decoded, and its payload is no transport sipnab handles | The outermost IP protocol, or `null` when the decoder recorded none | `47` is GRE and `4`/`41` are IP-in-IP. `--capture-tunnels` widens the filter to reach inside them |
| `4` | The frame is shorter than a header it claims | `null` | Raise `--snaplen`. A cut frame is a capture setting, not a parser gap |
| `5` | A decoder rejected the bytes | `null` | Save a sample and open an issue |

The number is the whole point of the entry. "Unsupported link type" names no
action, and "unsupported link type 0" names three. `frames` counts the whole
run, `frames_in_window` counts the sample, and an entry whose `frames_in_window`
is `0` describes a problem that has already stopped.

`undecodable_reasons_dropped` counts frames whose specific number did not fit
the fixed-slot tables behind these counters. A non-zero value means the
breakdown adds up to less than `totals.undecodable_frames`, and the field
exists so that nobody has to discover the shortfall by subtracting.

#### Why 30 seconds is the ceiling

An MCP tool call blocks the agent that made it. The handler holds a request
slot for the whole window, and clients cancel a call that has not answered —
60 seconds is the common default. A window that can run for minutes turns a
diagnostic into a denial of service against the agent that asked for it.

Thirty seconds keeps the whole call inside half of that budget and still buys
a window worth having. A trunk at 10,000 packets per second puts 300,000
packets through it, which is enough for a drop rate to mean something. For a
longer view, call the tool repeatedly and read `totals`.

Divide by `window.observed_ms`, never by `sample_seconds`. A loaded runtime
wakes the handler late, and the response reports the wall clock precisely so
that a rate does not inherit that error.

**Clock discipline.** The response carries a `clock` object — `synchronized`,
`max_error_us`, `est_error_us`, `available` — read from `adjtimex(2)` at report
time rather than cached at startup, since a host can lose its time source while
sipnab runs.

It is irrelevant to a single capture, where one clock stamped every packet and a
constant offset cancels out of every interval. It matters the moment you
correlate across NODES: `find_correlated`'s `timing_heuristic` matches dialogs
that started within the leg-correlation window of each other — two seconds
unless `--leg-correlation-window` says otherwise — and that is smaller than the
skew an undisciplined host accumulates in a day. A clock three seconds fast
fails to correlate legs that belong together, and a slow one pulls unrelated
legs inside the window. Widening the window to reach a B2BUA that dips a
database before placing the outbound leg widens this exposure with it. Read `clock` from both servers before trusting a time-based
match, and prefer any of the six identifier strategies — `session_id`,
`x_call_id`, `charging_vector_related_icid`, `sdp_origin`,
`charging_vector_icid` or `via_branch` — none of which care what time anyone
thinks it is.

`available: false` means the platform gave no answer — NOT that the clock is
bad. The two are different facts and only one of them is a problem.


### Tool argument enums

**`find_problems.kinds`** — diagnostic alias names, OR-ed together.
Defaults to `["problems"]`. The full vocabulary:

`problems` · `slow-setup` · `short-calls` · `one-way` · `nat-issues` ·
`codec-asym` · `ptime-asym` · `payload-asym` · `duration-asym` ·
`late-media`

An unknown alias returns a JSON-RPC *invalid params* error naming the
bad alias. The same names work as the `list_dialogs` `filter` aliases
(and as `sipnab --filter` aliases on the CLI).

**`security_findings.kinds`** — matches the rule names sipnab records
findings under: `scanner`, `fraud`, `digest`, `reg_flood` (note the
underscore — the `--alert` rule grammar spells it `reg-flood`, but
sipnab records and filters findings as `reg_flood`). Omitted or empty
`kinds` returns findings of every kind.

Both enums **refuse** a name they do not know, and name the vocabulary in the
refusal. `security_findings.kinds` used to accept anything and match nothing,
so a name outside those four answered `[]` — the same bytes a quiet capture
returns. `reg-flood` was the case that bit, and its refusal now suggests the
underscore spelling by name.

### Error model

All tools return MCP errors via the JSON-RPC `error` object. The codes
sipnab uses:

| Code | Meaning |
|---|---|
| -32602 (`invalid_params`) | Unknown Call-ID, out-of-range index, malformed filter, unknown format, unknown alias, a path where a bare filename belongs, and every "this tool is not enabled" refusal. The common case by far. |
| -32603 (`internal_error`) | A read or write that reached the filesystem or the decoder and failed there — `export_audio` with no retained payload, a capture file sipnab cannot open. Not only for bugs. |
| -32000 (server error) | Capacity, not correctness: `--mcp-max-concurrent` or `--mcp-rate-limit-per-peer` turned this call away, and the same call succeeds once the server has room. The only code here worth a retry — treat -32602 as a bug in the request. |

Tools never panic. An unknown Call-ID always produces a structured error
rather than an empty result.

### Response bounding

| Limit | Default | Set by |
|---|---|---|
| Default `limit` for list-style tools | 50 | the per-call `limit` |
| Ceiling on `limit` (clamps higher requests) | 1000 | `--mcp-max-rows` |
| SIP body / snippet bytes | 4096 | `--mcp-max-body-bytes` |
| Messages per `get_dialog` page | 1000 | `--mcp-max-rows` |

**These are defaults, not laws.** The right ceiling belongs to the CONSUMER
rather than to sipnab: an agent with a small context window wants far fewer
than a thousand rows and a batch consumer piping to a file wants far more, so
no single number serves both. Raise or lower them with `--mcp-max-rows` and
`--mcp-max-body-bytes`, or the matching `[limits]` keys in the config file.
The per-call `limit` narrows an answer below the ceiling, and cannot exceed
it.

A bound is not a loss. `list_dialogs`, `find_problems`, `search_by_time`,
`search_messages`, `security_findings` and the capture-wide `rtp_stats` sweep
each report `total_matched` beside their page, so a caller sees how much of the
answer it holds. All of those except `security_findings` carry a cursor to the
rest, as do `tail_dialogs` and `get_dialog`. Asking for a `limit` above the
ceiling does nothing — the ceiling clamps it — so either raise the ceiling with
`--mcp-max-rows` or page.

**Two tools remain exceptions, and a caller has to know which:**

| Tool | Reports a total | Carries a cursor | How to reach the rest |
|---|---|---|---|
| `security_findings` | Yes | No | Raise `limit`, and narrow with `since` |
| `tail_dialogs` | No | Yes | Follow `next_cursor` until the page comes back empty |

`security_findings` has no cursor because its source is a ring buffer whose
default depth is 1000 — the same as the maximum `limit`, so one call reaches
all of it. Raise `--findings-history` above 1000 and `total_matched` is what
tells you a page is short, and `since` is the way through. `tail_dialogs` reports
no total because a tail cannot have one: the store keeps changing underneath
it, so any number it gave would describe a moment that has passed.

