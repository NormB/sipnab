# MCP tool reference: vcon bundle

The `vcon` bundle exports, validates and analyzes vCon conversation
containers, reports a directory of them, reads one from the operator's vCon store, counts the vCon export
spool, and reports the SIPREC recording metadata a call carried.

Load only these tools with `--mcp-tools vcon`, or combine bundles as [Choosing
which tools load](mcp-tools.md#choosing-which-tools-load) describes. Every
tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

| Tool | Parameters | Returns |
|---|---|---|
| [`siprec_metadata`](#siprec_metadata) | `call_id` | The SIPREC ([RFC 7866](https://www.rfc-editor.org/rfc/rfc7866.html)) recording metadata a call carried: session id, mode, participants with AOR and display name, and the recorded streams, each naming its `m=` line label and the participant that sends it |
| [`export_vcon`](#export_vcon) | `call_id?`, `filter?`, `limit?`, `cursor?`, `media?` | Dialogs as vCon conversation containers, structured JSON, each with its SHA-256. One `call_id` or a whole filtered set, paged with `cursor`. Unsigned, retained audio inline unless `media` is `omit`, and every omission stated in the response |
| [`validate_vcon`](#validate_vcon) | `call_id?`, `container?` | Checks a container against the working group's draft-ietf-vcon-vcon-core-04 schema and names every finding |
| [`analyze_vcon`](#analyze_vcon) | `container?`, `container_base64?`, `limit?` (one of the first two) | Rebuilds the SIP messages a stored container holds and analyzes them apart from the loaded capture: per dialog the `--json-dialogs` object, the signaling diagnosis and the ladder, plus the capture analysis and what a container cannot reproduce |
| [`fetch_vcon`](#fetch_vcon) | `uuid` | **Connects, off by default.** One container from the operator's `[vcon_fetch]` store by uuid, returned inline with the checks it passed. Needs `--mcp-allow-vcon-fetch`; the store and its keys come from operator configuration only |
| [`vcon_directory_report`](#vcon_directory_report) | `directory`, `limit?`, `cursor?`, `max_response_bytes?` | Every stored container in a directory of the file root: per container its status, form, schema finding count, calls, dispositions and duration, or why sipnab skipped it, then the totals. The report `-I <dir> --report` prints |
| [`vcon_spool_status`](#vcon_spool_status) | `limit?`, `cursor?`, `rule?` | Counts the `--export-vcon-dir` spool: containers pending, delivered and failed, with the store's answer from each failed container's record. A snapshot of files; sends, moves and deletes nothing |


## Diagnose one call

You have a call-id. These explain what happened to that one call -- its signaling, its media, and the specific negotiations that tend to break.

### `siprec_metadata`

"Was this call recorded, and who is on the recording?" A session recording
client (SRC) — OpenSIPS's `siprec` module, an SBC — sends the recording server
an INVITE whose body carries an `application/rs-metadata+xml` part describing
what it is about to record. sipnab reads that part off the wire and returns it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |

**Read `recorded` first.** It is `false` when the dialog carried no SIPREC
metadata, and the response then holds only `call_id`, `reason`,
`capture_identity` and `schema_version`. The reason says what that does and
does not mean: sipnab reports what reached the capture point, so a recorder
signaling on a path it cannot see is indistinguishable here from a call nobody
recorded. It is not a statement that the call went unrecorded.

Otherwise `siprec` carries:

| Field | Answers |
|---|---|
| `session_id` | The recording session the SRC opened, which ties two legs of one recording together |
| `mode` | What the SRC declared it is recording, from `<datamode>` — `complete` for the whole session |
| `participants` | Each party, with `participant_id`, `aor` and `name` when the SRC sent one. A missing `name` is absent, not empty: an SRC that has no display name writes a self-closing `<nameID>` |
| `streams` | Each recorded stream, with `stream_id`, `label` and `participant_id` |

**Use `label` and `participant_id` to tie a recorded stream to a person.**
The label is the SDP `a=label` naming the `m=` line the SRC cut the recorded
stream from, so on a call with audio and video it says which is which. The
`participant_id` is the party that **sends** that stream. The stream element
itself names no party. sipnab reads it from `<participantstreamassoc>`, taking
the `<send>` children and not the `<recv>` children.

The example runs against
[`tests/pcap-samples/siprec-opensips-invite.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/siprec-opensips-invite.pcap):

```jsonc
// siprec_metadata { "call_id": "4f1c0a2e-siprec@172.28.0.31" }
{
  "schema_version": 1,
  "call_id": "4f1c0a2e-siprec@172.28.0.31",
  "recorded": true,
  "siprec": {
    "session_id": "4f1c0a2e",
    "mode": "complete",
    "participants": [
      { "participant_id": "9b2d1f00", "aor": "sip:alice@example.invalid", "name": "Alice" },
      { "participant_id": "c7e40a13", "aor": "sip:bob@example.invalid" }
    ],
    "streams": [
      { "stream_id": "1a2b3c4d", "label": "0", "participant_id": "9b2d1f00" },
      { "stream_id": "2b3c4d5e", "label": "1", "participant_id": "9b2d1f00" },
      { "stream_id": "3c4d5e6f", "label": "2", "participant_id": "c7e40a13" }
    ]
  },
  "capture_identity": { /* which capture, and which revision of its stores */ },
  "source_exhausted": true,
  "source_stopped_early": false
}
```

Against a call with no SIPREC body, such as `1-1966@10.0.2.20` in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap), the answer is:

```jsonc
// siprec_metadata { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "recorded": false,
  "reason": "this dialog carried no SIPREC metadata. That means none reached the capture point -- a recorder signaled on a path sipnab does not see looks the same here as a call nobody recorded.",
  "capture_identity": { … },
  "source_exhausted": true,
  "source_stopped_early": false
}
```

sipnab reads SIPREC and does not take part in it: it is neither a session
recording client nor a recording server.


## Export and handoff

Getting the result out of sipnab and into the next tool, the next team, or a bug report someone else can reproduce.

### `export_vcon`

One observed dialog as a **vCon** conversation container
([`draft-ietf-vcon-vcon-core`](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/),
syntax `0.4.0`), the interchange format for a conversation record.
`--export-vcon` writes the same container from the CLI.

This tool writes no file and needs no `--mcp-file-root`. It returns the
container inline and is `readOnlyHint: true`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id?` | string | A Call-ID the store holds. An unknown one fails with `invalid_params` (-32602) naming the value. | Give `filter` instead. |
| `filter?` | string | A filter alias or a raw DSL expression, the vocabulary [`list_dialogs`](mcp-tools-core.md#list_dialogs) takes. The `--export-vcon-when` flag takes the same vocabulary, aliases included. Every matching dialog comes back. | Give `call_id` instead. |
| `limit?` | integer | 1 to `--mcp-max-rows` (1000 by default). | 50. |
| `cursor?` | string | The previous response's `next_cursor`, passed back verbatim. It is the `<RFC 3339 created_at>\|<Call-ID>` cursor [`list_dialogs`](mcp-tools-core.md#list_dialogs) uses. A cursor whose time half is not [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html) fails with `invalid_params` (-32602). | The first page. |
| `media?` | string | `inline`: audio the run retained travels inline in a `recording` Dialog Object. `omit`: the exporter considers no audio, and each container records `media: "not-considered"`. sipnab refuses any other value before the tool runs, with an error result that names `inline` and `omit`. | `inline`. |

Give `call_id` or `filter`, never both. The CLI refuses the same pair. Both
fail with `invalid_params`:

```text
`call_id` and `filter` are alternatives, not a pair: one names a dialog, the
other names a rule for choosing them. Give one
```

Neither fails with `invalid_params` too:

```text
give `call_id` for one dialog, or `filter` for every dialog it selects -- for
example "response_code >= 400"
```

**Export a set in one call.** To export every failed call, pass a `filter`
instead of calling the tool once per Call-ID. `limit` bounds the set, and
`total_matched` counts every matching dialog in the store, so page against
it.

**The tool withholds a dialog the run denies.** On a run started with
`--content-deny-header NAME`, the tool does not export a dialog whose messages
carry that header, as the batch export does not write it. Asked for that
dialog by `call_id`, the tool refuses with `not_enabled` and names the header.
Under a filter, the tool leaves such dialogs out, and `withheld_by_deny` says
how many it left out.

**Page through a large set.** Containers come back ordered by the dialog's
`created_at`, then Call-ID. When more match than `limit` allows, `truncated`
is `true` and `next_cursor` names the last container returned. Pass it back as
`cursor` for the next page. The last page has `truncated: false` and a null
`next_cursor`. The cursor is a position within one capture: compare
`capture_identity.instance` between pages, as with every paged tool, because
[`open_capture`](mcp-tools-captures.md#open_capture) replaces the dialogs a cursor points into.

**Leave the audio out.** A container that carries audio is up to the
inline-media budget (5 MiB by default) larger than one that does not. With
`media: "omit"` the exporter considers no audio, and each container says so in
its own completeness carrier with `media: "not-considered"` and a caveat that
names the omission as a fact about the export, not about the call. The
containers stay valid against the core-04 schema.

**Read one container as a resource.** `resources/read` on
`sipnab://vcon/{call_id}` returns the container this tool builds for that
dialog, with audio inline, and `completion/complete` fills in `call_id` from
the Call-IDs the capture holds. sipnab refuses a container over the 8 MiB
resource limit with `invalid_params`. Call this tool for it instead, with
`media: "omit"` if the audio is what makes it large. Only a build with the
`vcon` feature lists the template.

A filter matching nothing answers with an empty set (`returned: 0`,
`total_matched: 0`), not an error.

There is no `format` parameter: the answer is always the JSON container the
draft defines.

**What the container contains, and what it leaves out.** The container is an
**observer** vCon and says so in its own parties: sipnab read the traffic, and
did not place the call, record it, or obtain anyone's permission to keep it.
The design record, [vCon design](design/vcon.md), gives the reasons. As a
result:

- **The container is neither signed nor encrypted.**
- **Every party carries `validation: "none"`.** `From` and `To` are what the
  sender wrote. sipnab writes a `name` when the wire carried a display name,
  beside `sip_display_name`. Treat the name as personal data: a redaction step
  must cover `name` as well as `sip_display_name`.
- **There is no consent or lawful-basis attachment.** sipnab was not in a
  position to record consent, so the absence says nothing about the call.
- **There is no `url`.** Media travels inline or not at all.

**How the container carries audio.** `dialog.type: "recording"` marks a Dialog
Object that carries media. sipnab reconstructed that audio from RTP at the
capture point. It is not a recording made by the endpoints, and every WAV
sipnab writes says so. Audio the run retained (`--retain-audio`) travels
inline: base64url, `mediatype:
"audio/x-wav"`, and a `content_hash` of `sha512-` plus the base64url SHA-512 of
the DECODED bytes, which `sha512sum` on the exported `.wav` reproduces. The
`duration` on that object is the FILE's, never the call's. sipnab keeps whole
calls by default. When frames are missing from the start of the file (an
explicit `[limits] max_audio_frames` cap dropped them, or the
`[limits] max_audio_bytes` budget released them), a `recording-set` wraps it,
carrying the call's media window beside the file's duration.

`capture_completeness.media` says which of five things happened to the audio:

| `media` | What it means |
|---|---|
| `carried` | The audio is inline in a `recording` Dialog Object |
| `refused-over-budget` | sipnab decoded audio and did not inline it, because the encoded body is over the inline-media budget (`--vcon-max-inline-media`, 5 MiB by default). The audio exists and was not truncated. Export it with [`export_audio`](mcp-tools-media.md#export_audio) |
| `none-decodable` | The run decoded no audio. `media_note` reports the measurement -- never that the call was silent |
| `not-considered` | Nobody asked this export for media: the call to `export_vcon` gave `media: "omit"`. A fact about the export, not about the call |
| `withheld-by-redaction` | The export ran with `--redact`, and redaction deletes audio rather than replacing it with a token, so the exporter considered none. The Dialog Object is the signaling one. A fact about the export, not about the call. The MCP tools do not redact, so they never write it |

**What the capture missed travels with the container, in two places**: the
`capture_completeness` object in the `analysis` entry, and the
`sipnab-capture-completeness` attachment. Both carry the same value. Read
`capture_completeness.note` before the contents: each clause in it is a
measurement of what this run read and dropped.

**Every container comes back with its SHA-256**, computed as `--vcon-digest`
computes it over the container's serialized bytes, so it compares directly
against a `SHA256SUMS` line or a store's ledger entry.

The digest identifies the document, not the dialog. `created_at` records when
sipnab wrote the container, so re-exporting one call produces a new digest and
the same `uuid`. Deduplicate on the `uuid`.

**The response repeats what each container omits**, in `completeness`, so a
caller does not have to open the container's attachments to learn it.
`completeness.note` is the container's own caveat, verbatim.
`completeness.max_inline_media_bytes` is the budget this run enforced. `completeness.omissions` carries one row per loss, each
naming the counter it came from, how many, and in what unit. An empty list and
`complete: true` say the container lost nothing.

The response is an envelope, so one dialog and a filtered set arrive in one
shape. The example runs against
[`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap),
which holds four failed calls:

```jsonc
// export_vcon { "filter": "response_code >= 400", "limit": 2 }
{
  "schema_version": 1,
  "returned": 2,
  "total_matched": 4,
  "truncated": true,
  "next_cursor": "2023-11-14T22:13:26Z|decline-7c6d5e@198.51.100.30",
  "withheld_by_deny": 0,
  "capture_identity": { /* which capture, and which revision of its stores */ },
  "source_exhausted": true,
  "source_stopped_early": false,
  "containers": [
    {
      "call_id": "busy-3a2b1c@192.0.2.30",
      "digest": "1c9e5fcfe825f9e90477c1d4fc49c23de6ceaeb8fcf6a60b141cfd563ed1bce6",
      "completeness": {
        "note": "Produced by sipnab 0.5.222 on node capture-01. sipnab OBSERVED this dialog and took no part in it: … sipnab read 23 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
        "media": "none-decodable",
        "media_note": "No RTP streams to export",
        "max_inline_media_bytes": 5242880,
        "complete": true,
        "omissions": []
      },
      "container": { /* the vCon itself; one is shown in full below */ }
    },
    …
  ]
}
```

A container that lost something fills the same block differently. With
`--retain-audio --vcon-max-inline-media 0`, `export_vcon { "call_id":
"1-1966@10.0.2.20" }` against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap) returns:

```jsonc
"completeness": {
  "note": "Produced by sipnab 0.5.222 on node capture-01. … No media is in this container because sipnab REFUSED to inline it: it decoded audio and the encoded body was over the budget below. The audio exists and was not truncated. sipnab read 852 frame(s) for this capture. — INCOMPLETE: sipnab decoded 8.5 second(s) of audio for this dialog and REFUSED to carry it: base64url of the 136516 byte WAV is 182022 bytes, over the 0 byte budget this emitter enforces because one probed vCon store answers 204 and drops the payload without telling the producer. The audio was NOT truncated and is not in this container; export it beside this file with the export_audio MCP tool. A capture-level analysis ran and ranked no blind spots.",
  "media": "refused-over-budget",
  "media_note": "Produced by sipnab 0.5.222 via mechanism sipnab-capture. …",
  "max_inline_media_bytes": 0,
  "complete": false,
  "omissions": [
    { "kind": "media_refused_over_budget", "count": 1, "unit": "recording" }
  ]
}
```

`omissions` has one row per `— INCOMPLETE:` clause in the note. The same
counters produce both, so either one gives the whole account.

The container example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
on a server started with `--node-name capture-01` and without
`--retain-audio`:

```jsonc
// the "container" member of export_vcon { "call_id": "1-1966@10.0.2.20" }
{
  "vcon": "0.4.0",
  "uuid": "0158a120-0392-8940-a7b4-dd42980ec66e",
  "created_at": "2026-10-16T12:03:45.845914820+00:00",
  "subject": "SIP call 1-1966@10.0.2.20",
  "extensions": ["sip-signaling", "CC"],
  "parties": [
    {
      "name": "PCMU/8000",
      "sip": "sip:sipp@10.0.2.20:5060",
      "sip_contact": "sip:sipp@10.0.2.20:5060",
      "sip_display_name": "PCMU/8000",
      "validation": "none"
    },
    {
      "name": "test",
      "sip": "sip:test@10.0.2.15:5060",
      "sip_contact": "<sip:test@10.0.2.15:5060;transport=udp>",
      "sip_display_name": "test",
      "sip_user_agent": "FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit",
      "validation": "none"
    },
    {
      "role": "observer",
      "sip_user_agent": "sipnab/0.5.222 (observer; node capture-01)",
      "validation": "none"
    }
  ],
  "dialog": [
    {
      "type": "recording",
      "start": "2016-11-26T14:52:59.666393+00:00",
      "duration": 8.499,
      "parties": [0, 1],
      "party_history": [
        { "event": "join", "party": 0, "time": "2016-11-26T14:52:59.670743+00:00" },
        …
      ],
      "sip_call_id": "1-1966@10.0.2.20",
      "sip_cseq": 1,
      "sip_from_tag": "1",
      "sip_to_tag": "QvN92t713vSZK"
    }
  ],
  "attachments": [
    {
      "purpose": "sip-message-trace",
      "dialog": 0,
      "party": 2,
      "start": "2016-11-26T14:52:59.666393+00:00",
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "version": "1.0", "call_id": "1-1966@10.0.2.20", "sip_call_id": "1-1966@10.0.2.20", "messages": [ /* the same objects --json emits, one per message */ ] }
    },
    {
      "purpose": "sipnab-capture-completeness",
      "dialog": 0,
      "party": 2,
      "start": "2016-11-26T14:52:59.666393+00:00",
      "mediatype": "application/json",
      "encoding": "json",
      "body": {
        "note": "Produced by sipnab 0.5.222 on node capture-01. sipnab OBSERVED this dialog and took no part in it: … sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
        "node": "capture-01",
        "sipnab_version": "0.5.222",
        "frames_read": 852,
        "undecodable_frames": 0,
        "sip_discarded_by_port_gate": 0,
        "sip_discarded_by_websocket_gate": 0,
        "messages_evicted": 0,
        "headers_dropped_oversize": 0,
        "dialogs_refused": 0,
        "dialogs_rotated": 0,
        "dialogs_suppressed_by_deny": 0,
        "gate_closed_during_run": false,
        "call_ended": true,
        "blind_spots": [],
        "media": "none-decodable",
        "media_note": "No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1 decodable stream, but kept none of their payload, so there is nothing to decode. This is a statement about what this run kept, not a finding that the call was silent. …"
      }
    },
    {
      "purpose": "sipnab-related-legs",
      "dialog": 0,
      "party": 2,
      "start": "2016-11-26T14:52:59.666393+00:00",
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "legs": [ { "uuid": "0158a120-253e-8217-9d04-6a2a4a9edef7", "strategy": "sdp_origin", "score": 90, "identifier_match": true } ] }
    }
  ],
  "analysis": [
    {
      "type": "report",
      "dialog": 0,
      "vendor": "sipnab",
      "product": "sipnab 0.5.222 (passive observer; not a recording system)",
      "schema": "sipnab-dialog-diagnosis/1",
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "sip_call_id": "1-1966@10.0.2.20", "final_status_code": 200, "media_quality": [ /* one row per stream: codec, packets, jitter_ms, loss_pct, mos, r_factor */ ], "capture_completeness": { /* the same object the attachment carries */ } }
    }
  ]
}
```

An unknown Call-ID answers with an error, never an empty container:

```jsonc
// export_vcon { "call_id": "no-such@nowhere" }
{ "code": -32602, "message": "call_id 'no-such@nowhere' not found" }
```

A filter that selects nothing answers with an empty set instead.

**How to read three fields.**

`blind_spots: []` means a capture analysis ran and ranked nothing. An absent
`blind_spots` means no analysis ran. This tool always runs it.

The observer party is always the last entry in `parties`, and every
attachment's `party` index points at it. Find it by position from the end or
by `role: "observer"`, not by a fixed index: a container that names more
parties moves it.

`uuid` is a UUIDv8 whose timestamp half is the dialog's start, not the
export's, so re-exporting one dialog out of one capture keeps one identifier.
Its other 74 bits are digests keyed on the Call-ID, the capture identity and
the node name, so two dialogs that opened in the same millisecond on the same
node still differ.

A binary built without the `vcon` Cargo feature does not offer this tool:
it is absent from `tools/list`.
[`server_capabilities`](mcp-tools-server.md#server_capabilities) lists what a given binary carries.

### `validate_vcon`

Checks a vCon container against the working group's
[draft-ietf-vcon-vcon-core-04 schema](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B), vendored unchanged
([`tests/schemas/vcon.schema.json`](https://github.com/NormB/sipnab/blob/main/tests/schemas/vcon.schema.json)).

Run it before handing containers to a store: a store that refuses a container
reports the refusal to the client that sent it, not to the producer.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id?` | string | A Call-ID the store holds. sipnab exports its container, then checks it. | Give `container` instead. |
| `container?` | object | A container you already hold — one sipnab wrote, one another producer wrote, one a store rejected. It must be the object itself, not a string holding it. | Give `call_id` instead. |

Give one, never both.

**Two verdicts.**

| `verdict` | What it means |
|---|---|
| `valid` | Nothing disagrees with the schema |
| `invalid` | At least one finding. `errors` carries each one |

Each finding names the JSON Pointer of the offending value
(`instance_path`), the schema keyword that refused it (`keyword`) and what was
wrong (`detail`). The response is `schema_version` 2. With `call_id` it also
carries `capture_identity`, naming the capture the container was exported
from. With `container` it does not, because that container did not come from
this capture. An empty Dialog Object
`{}` is an ordinary error:
[section 4.3 of core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3)
requires a placeholder that names its type.

```jsonc
// validate_vcon { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 2,
  "verdict": "valid",
  "schema_path": "tests/schemas/vcon.schema.json",
  "schema_id": "https://ietf.org/vcon/schemas/unsigned-vcon.json",
  "errors": [],
  "call_id": "1-1966@10.0.2.20",
  "capture_identity": { "node": "capture-01", "instance": "cc2cb18df0ea68adfb9c9-2",
                        "dialog_generation": 13, "stream_generation": 2 },
  "source_exhausted": true,
  "source_stopped_early": false
}
```

A rule core-04 added: `parties` MUST NOT be present on a `transfer` Dialog
Object ([section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4)):

```jsonc
// validate_vcon { "container": { "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde", "created_at": "2026-09-01T12:00:00Z", "dialog": [ { "type": "transfer", "parties": [0, 1] } ] } }
{
  "schema_version": 2,
  "verdict": "invalid",
  "schema_path": "tests/schemas/vcon.schema.json",
  "schema_id": "https://ietf.org/vcon/schemas/unsigned-vcon.json",
  "errors": [
    {
      "instance_path": "/dialog/0",
      "keyword": "not",
      "detail": "carries `parties`, which the schema forbids here"
    }
  ],
  "source_exhausted": true,
  "source_stopped_early": false
}
```

A container that disagrees with the schema is an ANSWER, not a tool error. The
call fails with `invalid_params` when the REQUEST is wrong: neither
argument, both arguments, an unknown `call_id`, or a `container` that is not a
JSON object. It also fails with `invalid_params` (`reason: invalid_value`,
`param: container`) for a container whose `critical` lists an extension sipnab
does not support, naming each one:
[section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4) says a reader "MUST NOT attempt to process or operate on the
vCon, except to reject it or report unsupported content". sipnab supports
`sip-signaling` and `CC`. With `"critical": ["foo"]` the message reads:

```text
sipnab must not validate this vCon container: its critical parameter lists
foo, which sipnab does not support, and draft-ietf-vcon-vcon-core-04 section
4.1.4 forbids processing a vCon that lists an unsupported critical extension.
sipnab supports sip-signaling and CC
```

The validator reads the vendored schema file and implements the draft-07
subset that file uses. A schema keyword outside that subset makes every
validation report `invalid`, naming the keyword.

A binary built without the `vcon` Cargo feature does not offer this tool:
it is absent from `tools/list`.
[`server_capabilities`](mcp-tools-server.md#server_capabilities) lists what a given binary carries.

### `analyze_vcon`

Analyzes a stored vCon container you hand over: one sipnab exported, or one
another producer wrote. [`POST /v1/vcon/analyze`](rest-api.md#post-v1vconanalyze)
gives the same answer for the same container.

sipnab rebuilds the container's SIP messages and analyzes them in stores of
their own. The tool leaves the loaded capture untouched, records nothing, and
connects nowhere. It reads two stored forms: a `sip-message-trace` attachment (sipnab's,
and the trace form of draft-howe-vcon-sip-signaling-00) and `message/sip`
attachments, one whole message each. It opens a signed, encrypted or gzip
format container first, with the server's `--vcon-key`, `--vcon-signer-ca` and
`--vcon-signer-sha256`: see
[A signed, encrypted or compressed container](vcon.md#a-signed-encrypted-or-compressed-container).
To analyze a container on the command
line, give it to `-I` instead: see
[Analyze a stored vCon](vcon.md#analyze-a-stored-vcon).

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `container?` | object | The container itself, not a string holding it, in the unsigned, signed or encrypted form. | Give this or `container_base64`. With neither, the call fails with `invalid_params`. |
| `container_base64?` | string | The container's bytes in standard base64, in any form, the gzip format included. | Give this or `container`. With both, the call fails with `invalid_params`. |
| `limit?` | integer | The most dialogs to return. Ceiling `--mcp-max-rows`. | 50. `total_dialogs` counts every dialog the container holds, and `truncated` says whether the limit cut the list. |

**Two verdicts.**

| `verdict` | What it means |
|---|---|
| `analyzed` | sipnab rebuilt at least one SIP message, and the answer holds the analysis |
| `unreadable` | The container does not open (an encrypted container and no `--vcon-key`, a signature that does not verify, a signer the checks refuse), stores no SIP message sipnab can rebuild, is not a vCon at all, or lists in `critical` an extension sipnab does not support (sipnab supports only `sip-signaling` and `CC`; [section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4)). `reason` says which, and the answer holds no analysis. For an unsupported critical extension it holds no schema findings either |

**A schema finding does not stop the analysis.** `schema_findings` lists every
place the container disagrees with the vendored draft-ietf-vcon-vcon-core-04
schema, in the shape [`validate_vcon`](#validate_vcon) reports them, beside
either verdict. A container that went through vcon.store, which hands
`extensions` back as an object, draws one finding and an analysis.

**The answer lists what a container cannot reproduce, and fills none of it in.**
`not_recomputed` holds one sentence per gap. A vCon stores no RTP, so sipnab
computes no stream, MOS, jitter or loss. The producer's own `media_quality`
rows come back verbatim in `stored_media_quality`, as its numbers. The trace
stores no request-URI, so a rebuilt request carries
`sip:request-uri-not-stored.invalid`. It keys headers by name, so header order
across names does not survive. A body other than SDP, and headers the producer did not
store, are absent. The capture analysis in `analysis` opens with a
`rebuilt_from_vcon` finding that says the same, beside the producer's own
caveat (`producer_note`).

Each rebuilt message carries `input_origin: "vcon"` and no `frame` pointer,
because it did not come from a capture frame.

Real output for the container `--export-vcon 1-1966@10.0.2.20 --node-name tap-a`
writes from [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// analyze_vcon { "container": <the contents of call.vcon.json> }
{
  "analysis": {
    "complete": false,
    "dialogs_examined": 1,
    "findings": [
      {
        "evidence": [
          {
            "counts": {
              "messages": 6
            },
            "endpoints": [
              "inline",
              "vcon 0158a120-0392-8940-8117-7af10a0d166e"
            ],
            "note": "6 SIP message(s) rebuilt from this container. Not recomputed or not stored: media: a vCon carries no RTP, so no stream, MOS, jitter or loss was computed from it; the producer's analysis holds 1 media_quality row(s), its own numbers, not recomputed; request-URI: not stored for 3 request(s), which carry sip:request-uri-not-stored.invalid; header order: the trace keys headers by name, so their order across names is the container's, not the wire's, and headers the producer did not store (credential headers, when sipnab produced it) are absent. The producer's caveat: Produced by sipnab 0.5.222 on node tap-a. sipnab OBSERVED this dialog and took no part in it: the parties below are what the From and To headers said, not identities anyone established, and nothing here is signed. No media is in this container because this run decoded none for the dialog; the capture_completeness media_note says what was measured. That is a statement about what this run kept, not a finding that the call was silent. sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots."
          }
        ],
        "evidence_omitted": 0,
        "kind": "rebuilt_from_vcon",
        "occurrences": 1,
        "severity": "blind",
        "unit": "container"
      }
    ],
    "frames_read": 6,
    "schema_version": 1,
    "streams_examined": 0
  },
  "dialogs": [
    {
      "call_id": "1-1966@10.0.2.20",
      "dialog": {
        "call_id": "1-1966@10.0.2.20",
        "diagnosis": {
          "hints": [],
          "nat_mismatch": false,
          "no_media": false,
          "one_way_audio": false,
          "private_media_address": false
        },
        "duration_sec": 8.504,
        "final_status_code": 200,
        "final_status_reason": "OK",
        "from": "sipp",
        "from_display": "PCMU/8000",
        "input_origin": "vcon",
        "method": "INVITE",
        "msg_count": 6,
        "schema_version": 1,
        "sdp_timeline": [
          {
            "codecs": [
              "PCMU"
            ],
            "direction": "offer",
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
        "state": "Completed",
        "streams": [],
        "termination": {
          "cause_code": 16,
          "cause_text": "NORMAL_CLEARING",
          "frame_ref": 4,
          "protocol": "Q.850",
          "source_header": "Reason"
        },
        "timing": {
          "retransmits": 0,
          "setup_ms": 4,
          "teardown_ms": 0,
          "trying_delay_ms": 0
        },
        "to": "test",
        "to_display": "test"
      },
      "ladder": [
        {
          "dst": "10.0.2.15:5060",
          "label": "INVITE",
          "src": "10.0.2.20:5060",
          "timestamp": "2016-11-26T14:52:59.666393+00:00",
          "transport": "UDP"
        },
        {
          "dst": "10.0.2.20:5060",
          "label": "100 Trying",
          "src": "10.0.2.15:5060",
          "timestamp": "2016-11-26T14:52:59.666545+00:00",
          "transport": "UDP"
        },
        {
          "dst": "10.0.2.20:5060",
          "label": "200 OK",
          "src": "10.0.2.15:5060",
          "timestamp": "2016-11-26T14:52:59.670743+00:00",
          "transport": "UDP"
        },
        {
          "dst": "10.0.2.15:5060",
          "label": "ACK",
          "src": "10.0.2.20:5060",
          "timestamp": "2016-11-26T14:52:59.670837+00:00",
          "transport": "UDP"
        },
        {
          "dst": "10.0.2.20:5060",
          "label": "BYE",
          "src": "10.0.2.15:5060",
          "timestamp": "2016-11-26T14:53:08.170086+00:00",
          "transport": "UDP"
        },
        {
          "dst": "10.0.2.15:5060",
          "label": "200 OK",
          "src": "10.0.2.20:5060",
          "timestamp": "2016-11-26T14:53:08.170676+00:00",
          "transport": "UDP"
        }
      ],
      "signaling": {
        "abandoned": null,
        "ack_missing": null,
        "auth_loop": null,
        "final_failure": null,
        "hints": [],
        "post_dial_delay": null,
        "registration_failure": null,
        "retransmissions": null
      }
    }
  ],
  "messages_rebuilt": 6,
  "not_recomputed": [
    "media: a vCon carries no RTP, so no stream, MOS, jitter or loss was computed from it",
    "the producer's analysis holds 1 media_quality row(s), its own numbers, not recomputed",
    "request-URI: not stored for 3 request(s), which carry sip:request-uri-not-stored.invalid",
    "header order: the trace keys headers by name, so their order across names is the container's, not the wire's, and headers the producer did not store (credential headers, when sipnab produced it) are absent"
  ],
  "producer_note": "Produced by sipnab 0.5.222 on node tap-a. sipnab OBSERVED this dialog and took no part in it: the parties below are what the From and To headers said, not identities anyone established. No media is in this container because this run decoded none for the dialog; the capture_completeness media_note says what was measured. That is a statement about what this run kept, not a finding that the call was silent. sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
  "schema_findings": [],
  "schema_version": 1,
  "stored_media_quality": [
    {
      "codec": "PCMU",
      "jitter_ms": 0.0054046519599899685,
      "loss_pct": 0.0,
      "mos": 4.358100599599484,
      "mos_grounded": true,
      "mos_grounding": "published",
      "packets": 425,
      "r_factor": 90.79987028835296,
      "ssrc": "0x343da99b"
    }
  ],
  "total_dialogs": 1,
  "truncated": false,
  "uuid": "0158a120-0392-8940-8117-7af10a0d166e",
  "verdict": "analyzed"
}
```

A container with no readable SIP is an answer with `verdict: unreadable`, not a
tool error. The call fails with `invalid_params` (-32602) only when
`container` is missing (`reason: missing_param`) or is not a JSON object
(`reason: invalid_value`), with `param: container` in both
[error data](mcp-tools.md#error-data) objects.

### `fetch_vcon`

Reads one container from the operator's vCon store by uuid and returns it in
the answer. It writes no file. The request, the credential, the CA, the size
limit, the decryption and the signer checks are the same as for
`sipnab --vcon-fetch` ([Fetch a stored vCon](vcon.md#fetch-a-stored-vcon)).
[`GET /v1/vcon/fetch/{uuid}`](rest-api.md#get-v1vconfetchuuid) gives the same
answer.

**It connects to the store, so it is off by default.** It needs
`--mcp-allow-vcon-fetch` and a store in the `[vcon_fetch]` section of the
config file (`url`, `kind`, `auth_file`, and `decrypt_key` for encrypted
containers). The store, its kind, the credential and the key come from
operator configuration only: the tool takes a uuid and nothing that picks a
destination, and the answer never holds a key or the credential. The tool is
`readOnlyHint: true` and `openWorldHint: true`.

`auth_file` holds one `Header-Name: value` line, such as
`Authorization: Bearer <token>`. A file without a colon stops the run at
startup with exit status 2.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `uuid` | string | The vCon's uuid: 1 to 64 characters, each a letter, a digit or `-`. Anything else fails with `invalid_params` (-32602), `the uuid is not one (1 to 64 characters, each a letter, a digit or '-')`, before sipnab sends anything. | Required. |

Returns:

| Field | Type | Description |
|---|---|---|
| `uuid` | string | The uuid asked for |
| `stored_form` | string | The form the store held the container in: `unsigned`, `signed` or `encrypted` |
| `decrypted` | boolean | `true` when sipnab decrypted an encrypted container with `[vcon_fetch] decrypt_key` |
| `signature_verified` | boolean | `true` when the container's signature verified, and passed `[vcon_fetch] signer_ca` and `signer_sha256` when the operator sets them: the signed form inside a decrypted container, or a signed container that is not encrypted, which needs no key. sipnab refuses a signature that does not verify, as the readers do. `false` for an unsigned container and for one left encrypted |
| `signer_sha256` | string or null | The SHA-256 fingerprint of the certificate the signature verified against, as `openssl x509 -noout -fingerprint -sha256` prints it |
| `schema_findings` | array | Where the container fails the draft-ietf-vcon-vcon-core-04 schema, one line each. Empty for a valid container and for one left encrypted |
| `container` | object | The vCon: the unsigned container when sipnab decrypted it, else as the store holds it, a signed container with its signature, without the store kind's envelope |

A second content block is the untrusted-content note: the container holds
whatever its producer stored.

Refusals, each `invalid_params` (-32602) unless it says otherwise:

| Cause | Message |
|---|---|
| No `--mcp-allow-vcon-fetch` | `fetching a vCon from the store is off on this server: start sipnab with --mcp-allow-vcon-fetch, and configure the store in [vcon_fetch]` |
| The flag, and no `[vcon_fetch] url` | `--mcp-allow-vcon-fetch is set, but no vCon store is configured: set [vcon_fetch] url and [vcon_fetch] auth_file in the config file` |
| The store answered `404` | `the store holds no such vCon (404)`, with `data.reason: "not_found"` |
| Anything else the fetcher refuses: another status, a timeout, an answer over `[vcon_fetch] max_size`, another uuid inside, a key that does not decrypt, a signer that fails a check | `internal_error` (-32603), the fetcher's reason fenced as untrusted text, with the credential removed |

A `[vcon_fetch]` store whose credential or key file sipnab cannot read stops
the run at startup, naming the flag.

The example reads from a `generic` store on the local host, with this
`[vcon_fetch]` section in the file given to `-f`:

```toml
[vcon_fetch]
kind = "generic"
url = "http://127.0.0.1:8080/v/{uuid}"
auth_file = "/etc/sipnab/vcon-store.key"
```

```bash
sipnab -N --mcp -I tests/pcap-samples/sip-rtp-g711.pcap -f sipnab.toml --mcp-allow-vcon-fetch
```

```jsonc
// fetch_vcon { "uuid": "0158a120-0392-8940-bcd9-b35008fdf5f9" }
{
  "schema_version": 1,
  "uuid": "0158a120-0392-8940-bcd9-b35008fdf5f9",
  "stored_form": "unsigned",
  "decrypted": false,
  "signature_verified": false,
  "signer_sha256": null,
  "schema_findings": [],
  "container": { "vcon": "0.4.0", "uuid": "0158a120-0392-8940-bcd9-b35008fdf5f9", … }
}
```

### `vcon_directory_report`

Reports every stored vCon container in one directory of `--mcp-file-root`:
which ones sipnab read, what each one held, which ones it skipped and why, and
the totals. It is the report `sipnab -N -I <dir> --report` prints after the
dialog table: see
[Read many containers at once](vcon.md#read-many-containers-at-once).

sipnab reads each container with the reader `-I` uses, and rebuilds the calls
into stores of their own. The tool leaves the loaded capture untouched,
changes no file, and connects nowhere. It opens a signed, encrypted or gzip
format container with the server's `--vcon-key`, `--vcon-signer-ca` and
`--vcon-signer-sha256`.

- It reads the files directly in the directory. It does not descend into
  subdirectories.
- It does not follow a symbolic link.
- A file is a container when its content says so, as for `-I`: the first
  character other than whitespace is `{`, or the file is gzip that inflates to
  one. A capture or a README in the directory is not a row.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `directory` | string | A directory directly inside `--mcp-file-root`, by bare name, or `.` for the root itself. | Required. A path, or a name that leads outside the root, fails with `invalid_params`. |
| `limit?` | integer | The most rows to return. Ceiling `--mcp-max-rows`. | 50. |
| `cursor?` | string | The `next_cursor` of the previous page: the file name it ended at. | The first page. |
| `max_response_bytes?` | integer | The byte budget for this page. Ceiling `--mcp-max-response-bytes`. | The ceiling. The budget cuts rows whole, and `truncated_by` says `bytes`. |

**Rows, then totals.** One row per container file, in file-name order.

| Field | What it holds |
|---|---|
| `status` | `read` or `skipped` |
| `file` | The file name, relative to `directory` |
| `uuid` | The container's `uuid`, or null when it did not open far enough to show one |
| `form` | The outermost form the file arrived in: `unsigned`, `signed`, `encrypted`, `gzip`, or `unknown` for bytes that are not a JSON object |
| `validation_findings` | Places the container disagrees with the vendored draft-ietf-vcon-vcon-core-04 schema. Null when the schema check did not run: the file did not open, or is not JSON |
| `calls_rebuilt`, `call_ids` | The calls (dialogs, by Call-ID) rebuilt from it |
| `dispositions` | Those calls counted by state, the word the `--report` dialog table's State column prints |
| `duration_secs` | Those calls' durations added up, each as the dialog table's Duration column computes it |
| `skip_reason` | On a skipped row only: `no_key`, `no_sip_signaling`, `not_json`, `not_a_vcon`, `not_opened`, `unsupported_critical` or `unreadable` |
| `skip_detail` | On a skipped row only: the same reason in full |

`totals` adds up every row of the directory, whichever page this is:
`containers`, `read`, `skipped`, `skipped_by_reason`, `failed_validation`
(containers with at least one schema finding), `calls`, `dispositions` and
`duration_secs`. A call two containers both hold counts once in the totals,
and once in each of their rows.

`no_key` is an encrypted container on a server without `--vcon-key`. The row
names the flag. sipnab never reports an encrypted container as one with no SIP.

The example reads a directory `stored` holding six files: two unsigned
containers (`--export-vcon` of the two calls in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap)), the gzip format of a third (the busy
call in [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap)), the encrypted container
[`tests/fixtures/vcon-jose/ab_call_ext_rec_encrypted.vcon`](https://github.com/NormB/sipnab/blob/main/tests/fixtures/vcon-jose/ab_call_ext_rec_encrypted.vcon), a container from
the `tests/fixtures/vcon-datasets/vcon-supreme-court-arguments` dataset (which
stores no SIP), and the first 30 bytes of the first container. This is the
second page of three rows:

```jsonc
// vcon_directory_report { "directory": "stored", "limit": 3, "cursor": "c-busy.vcon.json.gz" }
{
  "containers": [
    {
      "call_ids": [],
      "calls_rebuilt": 0,
      "dispositions": {},
      "duration_secs": 0,
      "file": "d-sealed.vcon.json",
      "form": "encrypted",
      "skip_detail": "cannot open the vCon container: the container is encrypted (draft-ietf-vcon-vcon-core-04 section 5.3), and no decryption key was given: give --vcon-key, or [vcon_input] key in the config file",
      "skip_reason": "no_key",
      "status": "skipped",
      "uuid": null,
      "validation_findings": null
    },
    {
      "call_ids": [],
      "calls_rebuilt": 0,
      "dispositions": {},
      "duration_secs": 0,
      "file": "e-dataset.vcon.json",
      "form": "unsigned",
      "skip_detail": "a vCon container with no SIP signaling sipnab can read: it has no sip-message-trace or message/sip attachment",
      "skip_reason": "no_sip_signaling",
      "status": "skipped",
      "uuid": "01a0be36-e172-8a14-9dd8-dd37220d739c",
      "validation_findings": 4
    },
    {
      "call_ids": [],
      "calls_rebuilt": 0,
      "dispositions": {},
      "duration_secs": 0,
      "file": "f-malformed.vcon.json",
      "form": "unknown",
      "skip_detail": "not a vCon container: not JSON (EOF while parsing a value at line 3 column 9)",
      "skip_reason": "not_json",
      "status": "skipped",
      "uuid": null,
      "validation_findings": null
    }
  ],
  "directory": "stored",
  "next_cursor": null,
  "returned": 3,
  "schema_version": 1,
  "totals": {
    "calls": 3,
    "containers": 6,
    "dispositions": {
      "Completed": 1,
      "Failed": 1,
      "InCall": 1
    },
    "duration_secs": 9,
    "failed_validation": 1,
    "read": 3,
    "skipped": 3,
    "skipped_by_reason": {
      "no_key": 1,
      "no_sip_signaling": 1,
      "not_json": 1
    }
  },
  "truncated": false
}
```

A build without the `vcon` Cargo feature does not register this tool.

### `vcon_spool_status`

Counts the vCon export spool: the directory `--export-vcon-dir` names, which
the capture's `--export-vcon-when` writes containers into and which
[`sipnab --vcon-forward`](vcon.md#deliver-the-spool-to-a-store) delivers to a
store. For each container the store refused, it returns the record the
forwarder wrote beside it, and it counts files by the forwarder's rules.

The same answer comes from
[`GET /v1/vcon/spool`](rest-api.md#get-v1vconspool) and from
`sipnab --vcon-spool-status <SPOOL_DIR>`
([CLI reference](cli-reference.md#vcon-forwarder)). This tool also fences each
store answer as untrusted text and cuts it to `--mcp-max-body-bytes`.

The answer is a **snapshot of files on disk**, taken when `as_of` says. The
forwarder is a separate process and may move a file a moment later. This tool
reads files and does nothing else: it sends nothing, fetches nothing, and
moves, deletes or creates no file, and makes no outbound vCon connection. It
is `readOnlyHint: true`.

It needs a run started with `--export-vcon-when` and `--export-vcon-dir`.
Without them it fails with `invalid_params` (-32602) naming the flags. It
reads the forwarder's DEFAULT directories beside the spool, `delivered/` and
`failed/`. A forwarder started with `--vcon-forward-done` or
`--vcon-forward-failed` moves files to directories this tool does not read,
and does not count.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `limit?` | integer | 1 to `--mcp-max-rows` (1000 by default). Bounds the list of failed records; the three counts are never bounded. | 50. |
| `cursor?` | string | The previous response's `next_cursor`, passed back verbatim. | The first page. |
| `rule?` | string | The [export rule](vcon.md#write-calls-by-rule) whose spool to read: a `[[vcon.rule]]` name, or `--export-vcon-when` for the flags' rule. Several spools and no `rule`, or a `rule` the run does not have, fail with `invalid_params` (-32602) listing the run's rule names. | The run's only spool. |

Returns:

| Field | Type | Description |
|---|---|---|
| `as_of` | string | When this tool read the directories, RFC 3339 UTC |
| `note` | string | One sentence saying the answer is a snapshot and that this tool moves nothing |
| `spool`, `delivered_dir`, `failed_dir` | object | Each directory's `path` and whether it `exists`. A directory that does not exist counts as empty |
| `pending` | integer | Containers in the spool, by the forwarder's rule: regular files ending in `.json` whose names do not start with a dot |
| `delivered` | integer | Containers in `delivered/` |
| `failed` | integer | Containers in `failed/`, the `.error.json` records not counted |
| `failures` | array | One page of failed containers by file name: `file`, and `record`, the `<file>.error.json` record (`at`, `status`, `method`, `url`, `body`, `body_truncated`, `reason`) |
| `returned` | integer | Rows in `failures` |
| `truncated` | boolean | Whether failed containers remain after this page |
| `next_cursor` | string or null | Pass back as `cursor` for the next page; null on the last page |
| `rule` | string | The export rule whose spool this is |

`record.body` is the start of the store's answer as the forwarder kept it,
fenced as untrusted text and cut to `--mcp-max-body-bytes` (4096 by default).
`record.status`, `method`, `url` and `body` are null when the forwarder refused
the container before sending it, and `record.reason` then says why. A failed
container whose record is missing, unreadable or not in the forwarder's shape
has a null `record` and a `record_problem` saying which.

The example runs in a directory whose `vcons/` spool holds one pending
container, `delivered/sent.vcon.json` and `failed/refused.vcon.json` with its
`refused.vcon.json.error.json` record. The run itself writes the four failed
calls of [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap) into the spool, so five
are pending:

```bash
sipnab -N --mcp -I tests/pcap-samples/sip-problem-call.pcap --export-vcon-when 'state == Failed' --export-vcon-dir vcons
```

```jsonc
// vcon_spool_status {}
{
  "schema_version": 1,
  "as_of": "2026-10-16T12:04:41.217Z",
  "note": "A snapshot of files on disk at as_of. The vCon forwarder (sipnab --vcon-forward) is a separate process that moves files out of the spool; whatever produced this answer sends, fetches, moves and deletes nothing. The delivered and failed directories are the forwarder's defaults beside the spool; a forwarder started with --vcon-forward-done or --vcon-forward-failed moves files elsewhere, and those are not counted.",
  "rule": "--export-vcon-when",
  "spool": { "path": "vcons", "exists": true },
  "delivered_dir": { "path": "vcons/delivered", "exists": true },
  "failed_dir": { "path": "vcons/failed", "exists": true },
  "pending": 5,
  "delivered": 1,
  "failed": 1,
  "failures": [
    {
      "file": "refused.vcon.json",
      "record": {
        "at": "2026-10-11T11:58:02Z",
        "body": "⟦untrusted-capture-data⟧{\"error\":\"vCon already exists\"}⟦/untrusted-capture-data⟧",
        "body_truncated": false,
        "file": "refused.vcon.json",
        "method": "POST",
        "reason": null,
        "status": 409,
        "url": "https://vcon.example.com/v1/vcons"
      }
    }
  ],
  "returned": 1,
  "truncated": false,
  "next_cursor": null
}
```

A build without the `vcon` Cargo feature does not register this tool.
