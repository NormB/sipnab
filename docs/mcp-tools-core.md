# MCP tool reference: core bundle

The `core` bundle is the smallest set of tools that answers what happened on
one call, and whether the fault was in signaling or media, from listing the
calls to the bytes that prove it.

Load only these tools with `--mcp-tools core`, or combine bundles as [Choosing
which tools load](mcp-tools.md#choosing-which-tools-load) describes. Every
tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

| Tool | Parameters | Returns |
|---|---|---|
| [`capture_status`](#capture_status) | -- | What this server captures: live or file, uptime, and whether stopping loses unsaved packets |
| [`get_capture_report`](#get_capture_report) | `format?` | Whole-capture analysis: findings, orphaned media, STUN/ICMP evidence, what the caps shed |
| [`list_dialogs`](#list_dialogs) | `filter?`, `limit?`, `cursor?`, `fields?`, `max_response_bytes?` | A page of dialog summaries, with the total behind it |
| [`aggregate_dialogs`](#aggregate_dialogs) | `group_by`, `filter?`, `top_n?` | Counts dialogs grouped by ONE field, in the store rather than in the model |
| [`find_problems`](#find_problems) | `kinds?`, `filter?`, `limit?`, `cursor?`, `fields?`, `max_response_bytes?` | A page of dialogs matching one or more diagnostic alias names |
| [`search_messages`](#search_messages) | `query`, `limit?`, `cursor?`, `max_response_bytes?` | A page of substring matches across method/From/To/UA/body, with the total behind it |
| [`triage_call`](#triage_call) | `call_id` | First-pass verdict: signaling problem, media problem, both, or none, with evidence |
| [`get_dialog`](#get_dialog) | `call_id`, `max_messages?`, `cursor?`, `max_response_bytes?` | Paginated dialog with full SIP messages |
| [`rtp_stats`](#rtp_stats) | `call_id?`, `min_mos?`, `max_mos?`, `orphaned?`, `limit?`, `cursor?`, `max_response_bytes?` | One call's RTP quality and diagnosis, or a capture-wide stream sweep |


## Survey — what is in this capture

Start here when you have a capture and no particular suspect. These answer "what is in it", "how much", and "is the server even seeing traffic".

### `capture_status`

**Ask this first.** It says what the server reads: a live interface
or a capture file. No other tool reports that.

No parameters. Against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap) it returns:

```jsonc
// capture_status { }
{
  "active_call_count": 1,          // InCall only
  "active_dialog_count": 1,        // any non-terminal state
  "ami_cleartext": [],             // see "ami_cleartext" below
  "capture_identity": {
    "dialog_generation": 13,
    "instance": "11dc6818df00304129ea0e-2",
    "node": "capture-01",
    "stream_generation": 2
  },
  "capture_quality": {
    "degraded": false,
    "ice_role_conflicts": 0,
    "interface_dropped_packets": 0,
    "invalid_timestamps": 0,
    "kernel_dropped_packets": 0,
    "lapsed_turn_allocation_streams": 0,
    "lapsed_turn_allocations": 0,
    "snapped_frames": 0,
    "unanswered_nat_requests": 0,
    "undecodable_frames": 0
  },
  "caveats": {
    "media_creating_commands": 0   // relay commands seen and not attributed
  },
  "dialog_count": 2,
  "load": null,                    // an open_capture load in progress, if any
  "name": "tests/pcap-samples/sip-rtp-g711.pcap",   // interface, or file path
  "orphaned_stream_count": 0,      // streams no dialog claims
  "schema_version": 2,
  "source": "file",                // "live" | "file" | "unknown"
  "source_exhausted": true,        // true once a file is read to the end
  "source_stopped_early": false,   // true when a read ended before the file did
  "stream_count": 2,
  "unanalysed_busiest_ports": [],
  "unanalysed_sip_messages": 0,    // SIP that --portrange excluded
  "unanalysed_websocket_messages": 0,  // SIP-over-WebSocket the WS port set excluded
  "unanalysed_websocket_ports": [],    // pass these to --ws-portrange
  "unsaved": false,                // stopping now would lose packets
  "uptime_sec": 0,
  "writing_to": null               // path packets are being saved to, if any
}
```

Read `unsaved` before you stop a server. It is `true` only for a **live**
capture with no output file, where the packets exist only in memory. A capture
file is already on disk, so a file source is never unsaved.

`source: "unknown"` means the server has no capture context. It
reports `unknown` rather than a guess.

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
  SIP-over-WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118.html)) on a
  port outside the WebSocket set. Re-run with `--ws-portrange` covering the
  ports listed. Widening `--portrange` recovers none of it. This is the common
  case on a WSS listener behind a reverse proxy, and on Kamailio, OpenSIPS and
  Janus, which all default outside sipnab's shipped 80/443/8080/8443.

Both are zero on a live capture, because the capture filter discards
out-of-range traffic before sipnab can count it.

#### `ami_cleartext` — a manager password on the wire

Asterisk's Manager Interface (AMI) speaks a line protocol on TCP/5038, and a
login sends `Action: login`, `Username:` and `Secret:` as plain text. AMI can
originate calls, read configuration and run shell commands, so a password seen
here is a more serious exposure than the SIP digest `--digest-leak` reports.

`ami_cleartext` lists each AMI greeting or cleartext login sipnab saw. AMI is
not SIP, so this traffic never appears in `unanalysed_sip_messages`. Read this
field to find it.

| Field | Type | Description |
|---|---|---|
| `observation` | object | One key: `banner` (the server greeted a client) or `cleartext-login` |
| `observation.cleartext-login.username` | string? | Always `null` in this list, because sipnab counts sightings per address pair and not per account |
| `observation.cleartext-login.secret_present` | bool | Whether a `Secret:` line was there. **A boolean, never the value** |
| `src` / `dst` / `dst_port` | string / string / u16 | Sender, receiver and receiver's port of the payload. For a `banner` the sender is the AMI server, so `dst_port` is the client's port |
| `default_port` | bool | Whether `dst_port` is 5038 |
| `count` | u64 | Payloads carrying this observation between this pair |

A capture holding one AMI greeting and one login reports:

```json
[
  {
    "count": 1,
    "default_port": true,
    "dst": "192.0.2.20",
    "dst_port": 5038,
    "observation": {
      "cleartext-login": {
        "secret_present": true,
        "username": null
      }
    },
    "src": "192.0.2.10"
  },
  {
    "count": 1,
    "default_port": false,
    "dst": "192.0.2.10",
    "dst_port": 40000,
    "observation": {
      "banner": {
        "version": null
      }
    },
    "src": "192.0.2.20"
  }
]
```

**The secret is never recorded.** A finding reports only that a `Secret:` line
was present (`secret_present`), never its value.

sipnab matches the AMI greeting and the login lines and records where they
were. It does not follow AMI sessions or decode other AMI messages.

**A login to AMI on another port is still reported**, with
`default_port: false`.

**This check needs no flag**, unlike the detectors behind
[`security_findings`](mcp-tools-security.md#security_findings). sipnab checks
every capture. A login with an `AuthType: MD5` challenge and no `Secret:` line
reports `secret_present: false`, so it never counts as a cleartext password.

sipnab counts sightings per address pair and observation kind, so a client that
reconnects in a loop is one row with a `count`, whatever username each attempt
sent.

**The field is always present.** `[]` means sipnab checked and found no AMI
traffic.

#### What the capture DECLINED — `caveats`

`capture_quality` above counts what the capture **lost**. `caveats` counts
traffic sipnab saw and, by design, did not analyze.

| Key | What it counts |
|-----|----------------|
| `media_creating_commands` | rtpengine `subscribe`, `publish` and `start recording` commands seen and not attributed to a call leg |
| `tls` | TLS decryption state — **absent** unless a decryptor ran |

Those commands create media for a call that is not one of its two legs, such
as a recording fork. sipnab counts them and does not attribute their media to
the call, so a two-party call still reports two streams.

**Read this before reasoning about a stream count.** When it is non-zero, the
capture holds media that no `rtp_stats` row explains. The key is always
present, and `0` means the capture held no such command.

##### `caveats.tls` — is decryption working?

Absent when nobody supplied keys, which is not a decryption failure. When a
decryptor ran, the block carries `keylog_entries`, `sessions_with_keys`,
`app_data_records`, `decrypted_records`, `undecrypted_records`,
`late_recovered`, `late_evicted` and `read_nothing`.

**Act on `read_nothing`, not on the counts.** Some TLS records are never
decrypted even when the keys are right, so `app_data_records >
decrypted_records` is not by itself a failure. `read_nothing` is `true` only
when application data arrived and none of it decrypted.

A capture of ciphertext sipnab cannot open lists no dialogs, the same as a
quiet network. Before you conclude that a capture held no SIP, check
`read_nothing`. `server_capabilities.can_decrypt` says whether the build can
decrypt, and this block says whether this run did.

`GET /v1/stats` carries the same block under the same name.

### `get_capture_report`

The whole-capture analysis that `--analyze` prints. Use it for what concerns
the capture as a whole: orphaned media, STUN, ICMP errors quoting SIP or RTP,
and what the retention caps discarded.
[`get_dialog_report`](mcp-tools-signaling.md#get_dialog_report) and
[`render_ladder`](mcp-tools-signaling.md#render_ladder) answer for one Call-ID.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `format?` | string? | `"json"`, `"yang-json"`, `"markdown"` or `"text"`. Anything else fails with `unknown format 'x', expected json\|yang-json\|markdown\|text`. | `"json"`. |

`frames_read` is the same count the Prometheus metric
`sipnab_capture_packets_total` reports.

**`yang-json`** answers the same analysis as `json`, encoded per
[RFC 7951](https://www.rfc-editor.org/rfc/rfc7951.html) against the YANG module
`sipnab-diagnosis`, which `sipnab --print-yang-module` prints. The document is
the first content block, and its one top-level member is
`sipnab-diagnosis:capture-analysis`. RFC 7951 allows no other member there, so
`source_exhausted` and `source_stopped_early` arrive in a second block instead
of inside the document. `complete` inside the document still reads `false`
while the capture loads, as it does in `json`.
The YANG section of [Output formats](output-formats.md) lists every difference
between the two encodings.

The `text` rendering opens with a summary line. Against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```text
Capture analysis: 1 finding(s) across 2 dialog(s), 2 stream(s), 852 frame(s) read.
```

A capture with no findings returns a statement that sipnab found nothing, not an
empty body. Against [`tests/fixtures/sip_call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/sip_call.pcap):

```text
No problems found in 1 dialog(s) and 0 stream(s) across 7 frame(s). Every frame decoded, no port gate discarded SIP, and no retention cap was reached — so this is a statement about the capture, not only about what sipnab could read of it.
```

**`json` is the default and returns an OBJECT**, serialized from the analysis
itself — `schema_version`, `findings`, `dialogs_examined`, `streams_examined`,
`frames_read` and `complete`. It is the object `--json-analyze` prints and
`GET /v1/report` answers, described by
[`tests/schemas/capture_analysis.schema.json`](https://github.com/NormB/sipnab/blob/main/tests/schemas/capture_analysis.schema.json).
It never carries `filter`, because this tool analyzes every dialog in the
store.

Each `findings` row is one ranked problem, worst first:

| Field | Type | Description |
|---|---|---|
| `kind` | string | Which problem this is, such as `one_way_audio`. |
| `severity` | string | How bad it is, carried on the row so a consumer sorts without a second table. |
| `occurrences` | u64 | How many times sipnab saw it, in `unit`s. **Exact, and not the length of `evidence`**, which a cap bounds. |
| `unit` | string | What one occurrence is — `call`, `stream`, `frame`. |
| `evidence` | object[] | Up to a fixed cap of verifiable instances. |
| `evidence_omitted` | u64 | Evidence rows the cap kept out. One evidence row can stand for several occurrences, so this is not `occurrences` minus the length of `evidence`. |

An `evidence` row carries `call_id`, `endpoints` (most specific first), `at`,
`counts` (named integers such as `rtp_packets` and `streams`) and `note`.
**sipnab leaves out any of the five that does not apply rather than sending
`null`.** A capture-level finding that belongs to no call, such as a STUN probe
or an undecodable frame, simply has no `call_id`.

```jsonc
// get_capture_report { "format": "json" } — one findings row, against
// tests/pcap-samples/sip-rtp-g711.pcap
{
  "kind": "one_way_audio",
  "severity": "critical",
  "occurrences": 2,
  "unit": "call",
  "evidence": [
    {
      "call_id": "1-1966@10.0.2.20",
      "endpoints": ["10.0.2.20:5060 -> 10.0.2.15", "SDP 10.0.2.20"],
      "at": "2016-11-26T14:52:59.666393Z",
      "counts": { "rtp_packets": 425, "streams": 1 },
      "note": "10.0.2.15:27942 -> 10.0.2.20:6000 carried 425 packet(s); nothing came back the other way"
    }
  ],
  "evidence_omitted": 0
}
```

Read `complete` before the findings: it is `false` when the capture
lost packets, hit a retention cap, or held frames no decoder could read, and a
findings list from such a capture is a **floor, not a total**.

`complete` also reads `false` while the capture is still loading, and for a
source whose read stopped before its end. `source_exhausted` and
`source_stopped_early` arrive beside it and say which.

`markdown` and `text` return a rendered document. A report drawn while the
capture is still loading, or over one whose read stopped before its end, ends
with an `INCOMPLETE RUN` block naming each reason, the same block `--report`
appends. A capture read in full adds no block. Ask for `json` when you want the
two booleans as fields.

`GET /v1/report` answers the same question over REST.

### `list_dialogs`

Returns one page of dialog summaries from the live capture store.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `filter?` | string? | A diagnostic alias name — `problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`, `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media` — **or** a raw [filter DSL](filter-dsl.md) expression, which may use a [named filter](filter-dsl.md#named-filters) as `@name`. A value may be bare or quoted: `method == INVITE` and `method == 'INVITE'` are the same filter. Anything else fails with `invalid_params` naming the position it stopped parsing at, or, for an undefined `@name`, listing the names the run defines. | Every dialog in the store matches. |
| `limit?` | u32? | Ceiling is `--mcp-max-rows` (1000 unless the operator changed it). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor?` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest dialog. |
| `fields?` | string[]? | Field names to keep on each row, plus `call_id`, which survives whether or not you list it. An unknown name fails with `invalid_params` naming both the typo and the fields a row carries. See [Narrowing a row with `fields`](mcp-tools.md#narrowing-a-row-with-fields). | The whole row. |
| `max_response_bytes?` | u64? | Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole row with `truncated_by: "bytes"` — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). | The ceiling. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `dialogs` | `DialogSummary[]` | This page, oldest first (ties broken by Call-ID). |
| `returned` | usize | Rows in `dialogs`, so counting the array is never necessary. |
| `total_matched` | usize | Dialogs matching the filter across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `by_method` | `{method, count}[]` | `total_matched` split by the method that opened each dialog, dominant class first. Covers the whole match set, not this page. |
| `truncated` | bool | `true` when matches remain after this page. Absent while the answer is not whole — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). |
| `truncated_by` | string? | `rows` when the row limit cut the page, `bytes` when the byte budget did. Absent when neither bound cut the page. |
| `source_exhausted` | bool | `true` once sipnab has read the capture source to its end. |
| `source_stopped_early` | bool | `true` when a source's read ended before the source did. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered — see [`capture_status`](#capture_status). A changed `instance` voids every cursor you hold. |

Each `DialogSummary` row carries `call_id`, `state`, `method`, `from_user`,
`to_user`, `msg_count`, `duration_sec`, `created_at`, `updated_at`, a `timing`
object (`pdd_ms`, `setup_ms`, `retransmits`, `duration_ms`, each `null` when the
capture never showed it) and a `frame` pointer for
[`show_evidence`](mcp-tools-captures.md#show_evidence). `from_user` and `to_user` arrive fenced,
because an endpoint chose them.

Two more keys appear when sipnab knows them, and are **left out rather than sent
as null** when it does not, so an absent key means "not known here":

- `final_status_code` — the final response the call reached. `state` collapses
  every release cause into one word, so 403, 404, 408, 486, 503 and 603 all read
  as `Failed`, and this is the field that tells them apart. Absent while a call
  is still in progress, never `0`.
- `input_origin` — which capture source delivered the message that OPENED the
  dialog: `wire`, `hep` or `uprobe`. Read it before you follow `frame`: a
  uprobe pointer (`uprobe:opensips/954#3`) has the same shape as a capture
  offset, and only a `wire` pointer leads to bytes in a capture file.
- `tags` — the labels `--tag` gave this run's dialogs. Absent when the run set
  none. `get_dialog`'s `dialog` carries it too.

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
      "final_status_code": 403,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.303349+00:00",
      "updated_at": "2016-11-17T21:52:35.339349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#0@0f039ad14545671e",
      "input_origin": "wire"
    },
    {
      "call_id": "call-2-synth@192.0.2.10",
      "state": "Registered",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 7,
      "final_status_code": 403,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.403349+00:00",
      "updated_at": "2016-11-17T21:52:35.439349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#7@f7951dd197e419b9",
      "input_origin": "wire"
    }
  ],
  "returned": 2,
  "total_matched": 1334,
  "by_method": [
    { "method": "REGISTER", "count": 1334 }
  ],
  "truncated": true,
  "truncated_by": "rows",
  "next_cursor": "2016-11-17T21:52:35.403349Z|call-2-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1ae7318cb5c11b1a306dd-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

The page holds two dialogs, and `by_method` shows that all 1334 matches are
REGISTER. The rows alone cannot tell you that.

Two fields matter when you write a client. `from_user` reads
`⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧`, not `ua-a`, so a
comparison against the bare name never matches: strip the markers, or match
inside them. `capture_identity.node` names the host that answered, which tells
you whose capture a fact came from when an agent queries several servers.

#### Read every dialog, page by page

Count from `total_matched`, never from the rows you hold: a page is at most
`limit` rows, and `--mcp-max-rows` caps `limit`. To read every
matching dialog:

1. Call `list_dialogs` with the `filter` and `limit` you want.
2. If `truncated` is `true`, call again with `cursor` set to the response's
   `next_cursor`, unchanged.
3. Stop when `next_cursor` is `null`.

`next_cursor` pairs a `created_at` timestamp with a Call-ID, because many
dialogs can share one timestamp. **Pass the value back unmodified.** A bare
[RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html) timestamp also parses,
so a cursor rebuilt by hand without the Call-ID returns no error and can skip
or repeat the dialogs that share that timestamp.

`list_dialogs` pages on `created_at`, which does not change, so a dialog that
receives another message during the sweep keeps its place.
[`tail_dialogs`](mcp-tools-signaling.md#tail_dialogs) pages on `updated_at`
instead, because it reports changes.

### `aggregate_dialogs`

Counts dialogs grouped by one field, inside the store. Use it instead of
fetching pages and counting rows.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `group_by` | string | One of `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip`, `rtp.codec`. Anything else fails with `invalid_params` naming the legal set. | Required. |
| `filter?` | string? | Alias or DSL, applied before grouping. | No filter — the whole store. |
| `top_n?` | integer? | Bounded by `--mcp-max-rows`, the same setting that bounds dialog rows. `other_count` counts the groups past it. | The same default as any row limit. |

**Returns** `group_by` (echoed), `buckets` (each `{ value, count }`, largest
first), `other_count`, `distinct_values`, `total_matched`, `capture_identity`
and `schema_version`.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng),
whose 1334 dialogs land in two states, with `top_n: 1` asking for only the
larger one:

```jsonc
// aggregate_dialogs { "group_by": "state", "top_n": 1 }
{
  "schema_version": 1,
  "group_by": "state",
  "buckets": [ { "value": "Registered", "count": 1207 } ],
  "other_count": 127,
  "distinct_values": 2,
  "total_matched": 1334,
  "capture_identity": {
    "node": "capture-01",
    "instance": "f078218d2bfca5995cf37-2",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

**The buckets plus `other_count` always equal `total_matched`.** A dialog with
no value for the field lands in a bucket whose value is the literal
`(none)`, so `{"group_by": "ua"}` also answers how many dialogs carry no
User-Agent.

**One field per call, and no time buckets.** To count within a time window,
narrow it with `filter`.

**Grouping by `from.user`, `to.user`, `ua` or `rtp.codec` returns fenced
values**, because the packet's sender wrote that text (the codec name comes
from the SDP). A state, a method, a status code or an IP address is sipnab's
own value and comes back unfenced.


## Find — narrow to the calls that matter

You know something is wrong but not which call. These cut a capture down to the dialogs worth reading: by symptom, by text, by time, or by relationship to a call you already have.

### `find_problems`

Convenience wrapper over `list_dialogs` that ORs each named alias, then ANDs
the optional `filter`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds?` | string[]? | One or more of the ten diagnostic aliases listed under [`list_dialogs`](#list_dialogs), OR-ed together. An unknown name fails with `invalid_params`. An empty array behaves as omitted. | `["problems"]`. |
| `filter?` | string? | An alias name or a raw [DSL](filter-dsl.md) expression, **ANDed** with the alias match. | The alias match alone decides the page. |
| `limit?` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor?` | string? | The previous response's `next_cursor`, verbatim. | Starts at the oldest match. |
| `fields?` | string[]? | Field names to keep on each row, plus `call_id`. Same rules as [`list_dialogs`](#list_dialogs) — see [Narrowing a row with `fields`](mcp-tools.md#narrowing-a-row-with-fields). | The whole row. |
| `max_response_bytes?` | u64? | Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole row with `truncated_by: "bytes"` — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). | The ceiling. |

Returns the same page object as [`list_dialogs`](#list_dialogs) — `dialogs`,
`returned`, `total_matched`, `by_method`, `truncated`, `next_cursor`,
`schema_version` and `capture_identity` — with the same meanings and the same
fenced `from_user` and `to_user`.

**Read `by_method` first.** The traffic a deployment sends most often can fill
a problems page. OPTIONS keepalives to unreachable peers, for example, match an
alias on retransmissions alone. When `by_method` shows that, exclude them with
`filter`, for example `"filter": "method != OPTIONS"`.

Use `filter` to restrict the aliases to your own traffic:
`{"kinds": ["problems"], "filter": "dst.ip == '203.0.113.9'"}` returns the
problem dialogs sent to that address. The alias match and the filter are
ANDed.

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
      "final_status_code": 403,
      "duration_sec": 0.03,
      "created_at": "2016-11-17T21:54:34.903349+00:00",
      "updated_at": "2016-11-17T21:54:34.933349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#8028@42ba0f02341ca2f7",
      "input_origin": "wire"
    }
  ],
  "returned": 1,
  "total_matched": 6,
  "by_method": [
    { "method": "REGISTER", "count": 6 }
  ],
  "truncated": true,
  "truncated_by": "rows",
  "next_cursor": "2016-11-17T21:54:34.903349Z|call-1197-synth@192.0.2.10",
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

### `search_messages`

Case-insensitive substring search over method, status, From, To,
User-Agent, and body across all dialogs.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `query` | string | Any substring. Matching ignores case. | Required — the call fails. |
| `limit?` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 hits. |
| `cursor?` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>#<zero-padded message index>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest match. |
| `max_response_bytes?` | u64? | Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole row with `truncated_by: "bytes"` — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). | The ceiling. |

**Returns** — the same page shape [`list_dialogs`](#list_dialogs) returns, not
a bare array, plus the provenance note as a second content block:

| Field | Type | Description |
|---|---|---|
| `hits` | object[] | This page of `{ call_id, message_index, snippet }`, ordered by the dialog's `created_at`, then Call-ID, then message index. |
| `returned` | usize | Rows in `hits`. |
| `total_matched` | usize | Messages matching the query across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `truncated` | bool | `true` when matches remain after this page. Absent while the answer is not whole — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). |
| `truncated_by` | string? | `rows` when the row limit cut the page, `bytes` when the byte budget did. Absent when neither bound cut the page. |
| `source_exhausted` | bool | `true` once sipnab has read the capture source to its end. |
| `source_stopped_early` | bool | `true` when a source's read ended before the source did. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered. A changed `instance` voids the cursor. |

`snippet` holds the whole raw message, fenced, and stops at 4 KB. Pass `call_id`
and `message_index` straight to [`get_message`](mcp-tools-signaling.md#get_message) for the parsed
form.

> **Count from the fields, never from the rows.** A capped result and a
> complete one hold the same shape, so the row count cannot tell them apart:
> on the sample capture below, `{ "query": "REGISTER" }` returns 50 rows and
> `limit: 1000` returns 1000, while 2668 messages match. `total_matched` is
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
      "snippet": "⟦untrusted-capture-data⟧REGISTER sip:example.net SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.10:5061…⟦/untrusted-capture-data⟧"
    }
  ],
  "returned": 1,
  "total_matched": 2668,
  "truncated": true,
  "truncated_by": "rows",
  "next_cursor": "2016-11-17T21:52:35.303349Z|call-1-synth@192.0.2.10#0000000000",
  "capture_identity": {
    "node": "capture-01",
    "instance": "12100b18cb6971cf461cff-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

Passing that `next_cursor` back returns message 1 of `call-1-synth@192.0.2.10`
and reports the same `total_matched: 2668`: the total describes the store, not
the page.
The message index in the cursor carries leading zeros, because the server
compares cursors as text. A cursor rebuilt by hand without them can skip
messages. Pass it back exactly as it arrived.


## Diagnose one call

You have a call-id. These explain what happened to that one call -- its signaling, its media, and the specific negotiations that tend to break.

### `triage_call`

**Start here.** It answers which half of the call failed. Signaling decides
whether a call connects, and RTP decides whether the parties hear each other. The
two have different causes and different fixes.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds, as
returned by [`list_dialogs`](#list_dialogs). An unknown one fails with
`invalid_params` (-32602) naming the value. There are no optional parameters.

```jsonc
// triage_call { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "verdict": "media",              // "signaling" | "media" | "both" | "none"
  "state": "Completed",
  "final_status_code": 200,
  "signaling": { "problem": false, "hints": [] },
  "media": {
    "problem": true,
    "one_way_audio": true,
    "nat_mismatch": false,
    "no_media": false,
    "stream_count": 1,
    "hints": ["RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."]
  },
  "termination": {                 // absent when nothing said why the call ended
    "cause_code": 16,
    "cause_text": "NORMAL_CLEARING",
    "frame_ref": 4,
    "protocol": "Q.850",
    "source_header": "Reason"
  },
  "source_exhausted": true,
  "source_stopped_early": false
}
```

A clean `200 OK` with one-way audio is a **media** problem. Nothing in the SIP
exchange is wrong, and time spent reading it is time lost.

Where to go next, by verdict:

| Verdict | Next tool |
|---|---|
| `signaling` | [`explain_response_code`](mcp-tools-signaling.md#explain_response_code) on the final code, then [`get_dialog`](#get_dialog) |
| `media` | [`rtp_stats`](#rtp_stats), and [`check_codec_negotiation`](mcp-tools-signaling.md#check_codec_negotiation) if the call failed |
| `both` | Signaling first — media symptoms are often downstream of a failed negotiation |
| `none` | The call is fine. Check you have the right Call-ID |

#### Why the call ended

`termination` is a **fact about the call, not a fault**, so it never moves
`verdict`. A call that cleared normally reports `verdict: "none"` and a
`Q.850` cause of 16 at the same time, and both are true.

It says why the call ended, which the verdict does not.

| Field | Type | Description |
|---|---|---|
| `cause_code` | u16? | The cause number, on the scale `protocol` names. Absent when the message named a protocol and no cause — never zero for a missing value, because `0` is itself a Q.850 cause |
| `cause_text` | string? | The human-readable cause, with control characters removed and cut to the first 200 characters |
| `protocol` | string? | Which scale `cause_code` is on. `16` is normal clearing in Q.850 and is not a SIP status code at all, so a code without this is not interpretable |
| `source_header` | string | Which header carried the cause: `Reason` ([RFC 3326](https://www.rfc-editor.org/rfc/rfc3326.html)) or `X-Asterisk-HangupCauseCode` |
| `frame_ref` | usize | Index into the dialog's message list of the message that carried it |

sipnab reads the **last** message in the dialog that names a cause, including
a `Reason` header on a `BYE` or a `CANCEL`. When one message carries both a
`SIP` and a `Q.850` cause, sipnab reports the `Q.850` one, because the `SIP`
cause repeats `final_status_code`.

The same block appears on [`get_dialog_report`](mcp-tools-signaling.md#get_dialog_report) and on
`GET /v1/dialogs/{call_id}/report`.

### `get_dialog`

Paginated dialog with full SIP messages.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `call_id 'x' not found`. | Required — the call fails. |
| `max_messages?` | u32? | At least 1; `0` fails with `invalid_params`. Ceiling is `--mcp-max-rows` (1000 by default), and higher clamps to it. | 100 messages. |
| `cursor?` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>#<zero-padded message index>`, the shape [`search_messages`](#search_messages) uses). A malformed cursor, or one issued for a different dialog, fails with `invalid_params`. A cursor past the last message returns an empty page. | Starts at message 0. |
| `max_response_bytes?` | u64? | Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole message with `truncated_by: "bytes"` — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). | The ceiling. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `dialog` | object | The same summary [`list_dialogs`](#list_dialogs) returns, with `from_user` and `to_user` fenced. |
| `messages` | object[] | This page of full messages, in dialog order. |
| `returned` | usize | Messages in `messages`. |
| `first_index` | usize | The index of `messages[0]` in the dialog, so row N of the page is [`get_message`](mcp-tools-signaling.md#get_message) `index: first_index + N`. |
| `total_messages` | usize | Messages in the whole dialog. |
| `truncated` | bool | `true` when messages remain after this page. Absent while the answer is not whole — see [Rules every tool follows](mcp-tools.md#rules-every-tool-follows). |
| `truncated_by` | string? | `rows` when `max_messages` cut the page, `bytes` when the byte budget did. Absent when neither bound cut the page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `complete` | bool | `true` when this page reaches the end of the dialog. Never `true` over a partial read of the capture. |
| `schema_version` | u32 | `2` for this shape. |

Every `messages` row carries `call_id`, `is_request`, `cseq` (`method` and
`number`), `from`, `to`, `src`, `src_port`, `dst`, `dst_port`, `transport`,
`timestamp`, `frame` and `schema_version`. Two more appear when sipnab observed
them and are **left out rather than sent as null** when it did not:

- `dscp` — the [RFC 2474](https://www.rfc-editor.org/rfc/rfc2474.html) marking on
  the frame that carried this message, 0 to 63. Absent means no IP header was
  read, which is what a HEP-delivered message looks like. `0` means sipnab saw
  the frame and the frame said best effort. Unmarked signaling is itself a
  common fault, so the two must not collapse into one value.
- `input_origin` — `wire`, `hep` or `uprobe`, the source that delivered this
  message.

The rest depends on the direction, so branch on `is_request` rather than
expecting one shape:

- **A request** adds `method`, and `contact` and `sdp` when it carried them.
- **A response** adds `status_code`, `reason`, `response_context` and `ua`, and
  carries no `method` — read `cseq.method` for the transaction it answers.

> **This tool returns more capture text than any other, and fences it.**
> `reason`, `from`, `to`, `contact`, `ua`, `sdp` and `malformed` in `messages[]`
> come back wrapped in `⟦untrusted-capture-data⟧` markers, as
> [`get_message`](mcp-tools-signaling.md#get_message) returns them. The SDP
> body keeps its line structure and `--mcp-max-body-bytes` bounds it. Header
> values arrive capped, with every control character removed.
>
> Treat every string in `messages[]` as written by an attacker: the markers
> say where the text came from, not that it is safe.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_dialog { "call_id": "1-1966@10.0.2.20", "max_messages": 1 }
{
  "schema_version": 2,
  "complete": false,
  "returned": 1,
  "first_index": 0,
  "total_messages": 6,
  "truncated": true,
  "truncated_by": "rows",
  "next_cursor": "2016-11-26T14:52:59.666393Z|1-1966@10.0.2.20#0000000000",
  "dialog": {
    "call_id": "1-1966@10.0.2.20",
    "state": "Completed",
    "method": "INVITE",
    "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
    "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
    "msg_count": 6,
    "final_status_code": 200,
    "duration_sec": 8.504,
    "created_at": "2016-11-26T14:52:59.666393+00:00",
    "updated_at": "2016-11-26T14:53:08.170676+00:00",
    "timing": { "pdd_ms": null, "setup_ms": 4, "retransmits": 0, "duration_ms": 8499 },
    "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
    "input_origin": "wire"
  },
  "messages": [
    {
      "call_id": "1-1966@10.0.2.20",
      "method": "INVITE",
      "is_request": true,
      "cseq": { "method": "INVITE", "number": 1 },
      "from": "⟦untrusted-capture-data⟧\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1⟦/untrusted-capture-data⟧",
      "to": "⟦untrusted-capture-data⟧test <sip:test@10.0.2.15:5060>⟦/untrusted-capture-data⟧",
      "contact": "⟦untrusted-capture-data⟧sip:sipp@10.0.2.20:5060⟦/untrusted-capture-data⟧",
      "src": "10.0.2.20",
      "src_port": 5060,
      "dst": "10.0.2.15",
      "dst_port": 5060,
      "transport": "UDP",
      "timestamp": "2016-11-26T14:52:59.666393+00:00",
      "sdp": "⟦untrusted-capture-data⟧v=0\no=- 42 42 IN IP4 10.0.2.20\ns=-\nc=IN IP4 10.0.2.20\nt=0 0\nm=audio 6000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\na=recvonly\n⟦/untrusted-capture-data⟧",
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
      "dscp": 0,
      "input_origin": "wire",
      "schema_version": 1
    }
  ]
}
```

The SDP above arrives with `\n` line endings, not the `\r\n` the wire carried:
fencing removes every control character except `\n` and `\t`. Compare it as
text, not byte for byte against the packet. Use
[`show_evidence`](mcp-tools-captures.md#show_evidence) when you need the
original bytes.

`total_messages` is 6 and `returned` is 1, so five messages remain. Call again
with `cursor` set to that `next_cursor` to continue, and stop when `complete`
turns `true`.

`cursor` is a string, passed back unchanged. An integer cursor fails with
`invalid_params` (-32602) and `data.reason` `"invalid_arguments"`:
`` failed to deserialize parameters: invalid type: integer `1`, expected a string ``. To address one message by position, use `first_index` with
[`get_message`](mcp-tools-signaling.md#get_message).

### `rtp_stats`

Per-stream RTP quality for one call, or across the whole capture.

This tool has **two modes**, and `call_id` is the switch. Pass it for one
dialog's streams. Omit it to sweep the whole capture. Six parameters belong to
the sweep alone:

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id?` | string? | A Call-ID a dialog carries, or one a media relay named for its streams. | **Switches modes** — the tool sweeps every stream in the capture, orphans included. |
| `min_mos?` | f64? | Sweep only. Keeps streams scoring at or above this. Rejected alongside `call_id`. | No lower bound. |
| `max_mos?` | f64? | Sweep only. Keeps streams scoring strictly below this. Rejected alongside `call_id`. | No upper bound. |
| `orphaned?` | bool? | Sweep only. `true` keeps only streams no dialog claims, `false` keeps only streams a dialog claimed. Independent of the MOS bounds. | Both kinds sweep. |
| `limit?` | u32? | Sweep only. Ceiling is `--mcp-max-rows` (1000 by default), higher clamps to it, `0` means the default. | 50 streams. |
| `cursor?` | string? | Sweep only. The previous response's `next_cursor`, verbatim (`<RFC 3339>\|0xSSRC@src>dst`). | Starts at the earliest stream. |
| `max_response_bytes?` | u64? | Sweep only. Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole row with `truncated_by: "bytes"`. | The ceiling. |

**Only the two MOS bounds fail alongside a `call_id`.** They ask a question
about the whole capture, so sending one with a Call-ID is a misunderstanding of
the tool, and sipnab answers `invalid_params` (-32602) rather than quietly
doing nothing. Per-call mode simply skips `orphaned`, `limit` and `cursor`: a
call holds every stream it holds, so there is nothing there to page or to
filter.

**With `call_id`** the answer keeps its existing shape — `{ call_id, streams, diagnosis }`,
where `streams` is an array of stream JSON objects (codec, MOS, jitter, loss%,
packets, SSRC, quality intervals) and `diagnosis` carries the standard one-way /
NAT-mismatch flags plus the asymmetry signals (`codec_asymmetry`,
`ptime_asymmetry`, `payload_type_asymmetry`, `duration_asymmetry`,
`late_media`). A MOS bound alongside a `call_id` returns invalid_params
(-32602) rather than quietly doing nothing. `dialog_seen` says whether this
capture holds the call's SIP dialog.

**On a media-relay host** the dialog is not required. A relay sees the RTP and
its own control traffic, never the SIP, so its dialog store is empty while its
streams carry the Call-ID the relay named. `rtp_stats` answers from those
streams: `dialog_seen` is `false`, and `dialog_absent` says why no dialog
explains the media, with the same `reason` and `note` that
[`reconcile_orphans`](mcp-tools-media.md#reconcile_orphans) gives it. The diagnosis still runs,
without the SDP checks (`nat_mismatch`, `no_media`, the [RFC 4961](https://www.rfc-editor.org/rfc/rfc4961.html) port hints), which
need the dialog. [`media_diagnostics`](mcp-tools-media.md#media_diagnostics),
[`explain_attribution`](mcp-tools-media.md#explain_attribution) and
[`export_audio`](mcp-tools-media.md#export_audio) follow the same rule.

```jsonc
// rtp_stats { "call_id": "B2B.201.6748799.1790773715.1438467624" }, on the relay host
{
  "call_id": "B2B.201.6748799.1790773715.1438467624",
  "dialog_seen": false,
  "dialog_absent": {
    "reason": "relay-asserted-but-no-dialog",
    "note": "a relay named this endpoint but no captured dialog claims it -- the signaling is missing, not the media"
  },
  "streams": [
    { "associated_dialog": "B2B.201.6748799.1790773715.1438467624", "dialog_assertion": "media-relay", "src": "192.0.2.70:41004", "dst": "192.0.2.71:31004", "codec": "PCMU", "mos": 4.36 /* ... */ },
    { "associated_dialog": "B2B.201.6748799.1790773715.1438467624", "dialog_assertion": "media-relay", "src": "192.0.2.71:31004", "dst": "192.0.2.70:41004", "codec": "PCMU", "mos": 4.36 /* ... */ }
  ],
  "diagnosis": { "one_way_audio": false, "nat_mismatch": false, "no_media": false, "sdp_media": null /* ... */ }
}
```

sipnab refuses a Call-ID that neither a dialog nor any stream carries, with
invalid_params (-32602) and a message naming both searches: `no SIP dialog and
no RTP stream associated with call_id '…' in this capture`. On a relay host that
means the call never crossed this relay, not that the lookup failed.

```jsonc
// rtp_stats { "call_id": "1-1966@10.0.2.20" }
{
  "call_id": "1-1966@10.0.2.20",
  "streams": [
    {
      "associated_dialog": "1-1966@10.0.2.20",
      "dialog_assertion": "signaled",
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
      "r_factor": 90.79987028835296,
      "orphaned": false,
      "dscp": 0,
      "input_origin": "wire",
      "first_seen": "2016-11-26T14:52:59.689083+00:00",
      "last_seen": "2016-11-26T14:53:08.169060+00:00",
      "round_trip_note": "Not measured. No endpoint reported a round trip for this stream, so latency is unknown rather than good — a stream with clean jitter and no loss can still be unusable on delay alone (ITU-T G.114).",
      "quality_intervals": [
        {
          "jitter_ms": 0.0063823922199494915,
          "loss_pct": 0.0,
          "mos": 4.358100053908192,
          "mos_grounded": true,
          "packets": 252,
          "r_factor": 90.79984682258672,
          "timestamp": "2016-11-26T14:53:04.709076+00:00",
          "verdict": "acceptable"
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
    "private_media_address": false,
    "sdp_media": "10.0.2.20"
  },
  "dialog_seen": true
}
```

`diagnosis` always carries `one_way_audio`, `nat_mismatch`, `no_media`,
`private_media_address`, `sdp_media`, `actual_media` and `hints`. The asymmetry
signals named above appear **only when sipnab found one**, so an absent
`codec_asymmetry` means the legs agreed rather than that the check did not run.

Per-call mode returns no `total_matched`, `truncated` or `next_cursor`, because
it returns every stream of the call. `quality_intervals` holds one entry per
completed sampling window, so a call shorter than one window returns an empty
array, and this eight-second call returns one row. The window is five seconds
by default. `--quality-interval` narrows it, down to one second, without
shortening the hour of call time the trend covers.

Each interval carries its own **`mos`**, **`r_factor`** and **`verdict`**.
Read them to find short bursts of loss or jitter that the stream-level MOS, a
mean over the whole call, hides. sipnab scores an interval on its own jitter
and loss and on the stream's path delay, so the interval figures and the
stream figure use the same delay.

`verdict` has three states:

| `verdict` | What it means |
|---|---|
| `acceptable` | R at or above 70, where ITU-T G.107's worst user-satisfaction category is still "some users dissatisfied". |
| `degraded` | R below 70, where that category becomes "many users dissatisfied". |
| `not_scorable` | The codec has no published or declared impairment value, so sipnab refuses to judge the interval. The `mos` beside it is a placeholder, and `mos_grounded` is `false`. |

`not_scorable` means neither good nor bad. When you count degraded intervals,
count `degraded` only, and report `not_scorable` intervals separately as not
judged.

Each stream carries **`mos_grounded`** and **`mos_grounding`**. sipnab has
published ITU-T G.113 impairment values only for G.711, G.729 and Opus. For
AMR, AMR-WB, EVS, G.722 and a stream whose codec was never identified, the MOS
is the same placeholder figure for every codec. When `mos_grounded` is `false`
the MOS means **unknown**, and a `mos_note` says so.

`mos_grounding` names what the number rests on:

| `mos_grounding` | `mos_grounded` | What the number rests on |
|---|---|---|
| `published` | `true` | An ITU-T G.113 impairment value sipnab implements. |
| `operator_declared` | `true` | An `Ie` this deployment supplied in `[media.codec_ie]`. A `mos_note` says so, so an agent citing the figure cites the operator rather than a standard. |
| `unpublished` | `false` | Nothing published and nothing declared. Placeholder. |

For AMR-WB specifically the placeholder is wrong by roughly a full MOS point in
either direction: its nine modes genuinely span about 4.49 down to 3.51. Do not
report a MOS to a human without checking this field. See
[MOS and codecs](mos-and-codecs.md) for the full picture.

An AMR-WB stream whose mode sipnab read also carries the wideband score, the
same three fields `GET /v1/streams` returns:

| Field | Meaning |
|---|---|
| `mos_wideband` | `MOS_CQEW` on the ITU-T G.107.1 wideband scale |
| `mos_wideband_context` | The listening context sipnab scored the stream in: `monotic` or `diotic` |
| `mos_wideband_unavailable` | Why there is no wideband score: `unpublished_mode` or `loss_not_computable` |

`mos_wideband` and `mos` are different scales. Do not compare them. A stream
that is not AMR-WB carries none of the three. See
[Where the wideband score appears](mos-and-codecs.md#where-the-wideband-score-appears).

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

#### Find poor streams across the whole capture

Omit `call_id` to sweep every stream. `{ "max_mos": 3.5 }` returns every stream
scoring below 3.5 in one call, without a call per dialog. The sweep also
returns streams no dialog claims, which per-call mode cannot reach because they
have no Call-ID.

| Field | Type | Description |
|---|---|---|
| `streams` | object[] | This page, oldest `first_seen` first. |
| `returned` | usize | Rows in `streams`. |
| `total_matched` | usize | Streams matching across the whole store. |
| `ungrounded_excluded` | usize | Streams a MOS bound could not judge. |
| `truncated` | bool | `true` when matches remain after this page. |
| `truncated_by` | string? | `rows` when the row limit cut the page, `bytes` when the byte budget did. Absent when neither bound cut the page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `capture_identity` | object | Which capture answered — see [`capture_status`](#capture_status). A changed `instance` voids every cursor you hold. |
| `schema_version` | u32 | `1` for this shape. |

**A MOS bound only judges codecs sipnab has a real impairment value for** —
one G.113 publishes, or one this deployment declared in `[media.codec_ie]`.
`min_mos` and `max_mos` skip every ungrounded stream and count it in
`ungrounded_excluded`. Report that count beside the result: on a network
carrying AMR-WB, EVS or G.722, "2 streams below 3.5" omits every stream sipnab
could not score.

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
      "dscp": 0,
      "dst": "127.0.0.1:5084",
      "first_seen": "2026-07-08T18:35:27.407583+00:00",
      "frame": "tests/pcap-samples/codec-negotiation.pcap#5@5d4c3e3d970a836b",
      "input_origin": "wire",
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
  "truncated_by": "rows",
  "next_cursor": "2026-07-08T18:35:27.407583Z|0x0e330af3@127.0.0.1:5094>127.0.0.1:5084",
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
`true` exactly when `associated_dialog` is absent, from the stream's first
packet. Every stream above reports `orphaned: true`, because the capture holds
four streams and no dialogs. A short unclaimed stream is what a NAT or
one-way-audio fault often looks like from the media side, so filter with
`orphaned: true` to find one.

`total_matched: 2` and `ungrounded_excluded: 2` account for all four streams.
The two G722 streams carry the placeholder MOS, so the `max_mos` bound skips
them and counts them in `ungrounded_excluded`.
