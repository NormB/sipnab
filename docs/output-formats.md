# Output formats

sipnab has four output modes:

- the interactive TUI (the default),
- per-message text with `-N`,
- NDJSON with `--json`,
- the [MCP server](mcp.md) for AI agents.

The [REST API](rest-api.md) serves the same data over HTTP. This page
documents the machine-readable formats the command line writes.

## Which output do I want?

| You want | Run | Details |
|---|---|---|
| One JSON line per SIP message, to pipe into `jq` | `sipnab -N -I capture.pcap --json` | [NDJSON](#ndjson---json) |
| One readable line per call | `sipnab -N -I capture.pcap --report --no-cli-print` | [Summary-only output](#summary-only-output) |
| One call explained, as text or JSON | `--call-report "$CALL_ID"`, plus `--json` for JSON | [Summary-only output](#summary-only-output) |
| One JSON object per call | `--json-dialogs --no-cli-print` | [One object per dialog](#one-object-per-dialog) |
| Every STUN and TURN exchange | `--json-stun --no-cli-print` | [STUN / TURN JSON](#stun--turn-json---json-stun) |
| One verdict for the whole capture | `--json-analyze --no-cli-print` | [Capture analysis](#capture-analysis---json-analyze) |
| The same verdict as YANG-modeled data | `--yang-analyze --no-cli-print` | [YANG export](#yang-export---yang-analyze) |
| One call as a vCon container | `--export-vcon` | [vCon](#vcon---export-vcon) |
| The packets, for Wireshark | `-O calls.pcapng --pcapng` | [pcap / pcapng](#pcap--pcapng) |
| A Wireshark display filter for the capture | `-N --wireshark` | [CLI reference](cli-reference.md#output) |
| Log lines fail2ban reads | `-N --fail2ban` with `--kill-scanner` | [CLI reference](cli-reference.md#output) |
| A call's ladder as a Mermaid diagram, or its audio as WAV | the save dialog in the terminal UI (`F2`) | [Save popup](keybindings.md#save-popup) |

> **Prerequisites:**
>
> - `--json` requires non-interactive mode (`-N` / `--no-tui`). sipnab refuses
>   to start otherwise. Exception: `--call-report` implies non-interactive
>   output.
> - NDJSON needs no extra build feature. It is part of the default build.
> - Full flag reference: [CLI reference](cli-reference.md#output).

## NDJSON (`--json`)

`--json` emits one JSON object per SIP message. The output is
newline-delimited:

- each line is independently parseable,
- the stream is pipe-friendly.

```bash
sipnab -N -I capture.pcap --json | jq .
```

Message record (fields with no value drop out rather than reading null):

```json
{
  "schema_version": 1,
  "timestamp": "2026-06-12T14:03:21.412345+00:00",
  "src": "192.0.2.1",
  "src_port": 5060,
  "dst": "192.0.2.2",
  "dst_port": 5060,
  "transport": "UDP",
  "is_request": true,
  "method": "INVITE",
  "call_id": "abc123@192.0.2.1",
  "from": "\"Alice\" <sip:1001@192.0.2.1>;tag=1c145053",
  "to": "<sip:1002@192.0.2.2>",
  "contact": "<sip:1001@192.0.2.1:5060>",
  "ua": "FreePBX-16",
  "sdp": "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 96\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:96 telephone-event/8000\r\n",
  "cseq": { "number": 1, "method": "INVITE" }
}
```

A response record carries `is_request: false` plus `status_code`,
`reason`, and `response_context` instead of `method`:

```json
{
  "schema_version": 1,
  "timestamp": "2026-06-12T14:03:21.598204+00:00",
  "src": "192.0.2.2",
  "src_port": 5060,
  "dst": "192.0.2.1",
  "dst_port": 5060,
  "transport": "UDP",
  "is_request": false,
  "status_code": 180,
  "reason": "Ringing",
  "call_id": "abc123@192.0.2.1",
  "from": "\"Alice\" <sip:1001@192.0.2.1>;tag=1c145053",
  "to": "<sip:1002@192.0.2.2>;tag=782609",
  "cseq": { "number": 1, "method": "INVITE" },
  "response_context": "1 INVITE"
}
```

`from` and `to` are the **full** `From` / `To` header values. They include
display name, URI and tags. They are not the bare user part. (The aggregated
dialog object below is the one that carries the user part.) Match them with a
regex or a substring test, not with equality.

`cseq` is the parsed `CSeq` header — `{ number, method }`.

- It appears on **every** message, requests included.
- So re-requests within a dialog stay distinguishable (e.g. two REGISTERs with
  `CSeq` 1 and 2).
- It drops out only when the `CSeq` header is absent or unparseable.

`contact` is the `Contact` header value when present. It is routing-critical.
The field drops out otherwise.

`sdp` is the raw SDP body.

- sipnab emits it **only** when `Content-Type` is `application/sdp` and the
  body is valid UTF-8.
- It lets a consumer verify the negotiated media (connection / `m=` /
  `a=rtpmap`). Dynamic-PT decode depends on that media.
- sipnab omits it for non-SDP or non-UTF-8 bodies.

`response_context` is `"<num> <method>"`, on responses only. It says what the
response answers. It is a deprecated alias of `cseq`, retained for backward
compatibility under `schema_version` 1. Prefer `cseq`.

`malformed` is a list of structural-defect diagnostics. It is present **only**
when a message arrives malformed. A well-formed message omits the field.

It surfaces crafted or broken input rather than silently accepting it:

- missing mandatory headers (`Call-ID`/`CSeq`/`From`/`To`/`Via`),
- an unparseable `CSeq`,
- a `Content-Length` larger than the body actually present (truncated/lying
  length),
- control/NUL bytes in a header.

Example: `"malformed": ["missing mandatory header: Call-ID"]`.

`extension_headers` is every header the fields above do not already carry.

- It uses wire form (`"Name: value"`) and wire order, one entry per header line.
- `Call-ID`, `From`, `To`, `Contact`, `User-Agent` and `CSeq` never appear.
  Those are fields of their own.
- sipnab drops nothing else. So `Via`, `Max-Forwards` and `Content-Length` join
  the vendor-specific headers this exists for.

The list keeps duplicates and wire order. Three `Via` lines are three entries
in the order they arrived. A message whose every header is already a field
omits the key rather than sending an empty array.

`input_origin` names the capture source that delivered the message: `wire`,
`hep` or `uprobe`. It is what keeps `frame` honest.

A uprobe read carries a pointer of the same shape as a capture offset
(`uprobe:opensips/954#3` beside `capture.pcap#4212`). Only one of the two leads
back to bytes anyone can read:

- `wire` came from an IP header sipnab observed.
- `hep` carries addressing a remote HEP sender asserted.
- `uprobe` names plaintext sipnab lifted out of a process's TLS library. That
  plaintext was never on a wire at all.

Feeding a `uprobe:` pointer to `--show-frame` therefore gets a refusal that
names the process, not a frame.

The field drops out when the message came from no captured packet. There,
`wire` would claim an observation sipnab never made.

The `-N` text output and the TUI's raw-message viewer carry the same fact. They
add a trailing `origin=hep` or `origin=uprobe`. They leave an ordinary wire
capture unmarked:

```text
12:57:47.360 0.0.0.0:0 -> 0.0.0.0:0 REGISTER TCP origin=uprobe
```

`schema_version` increments on breaking field changes. Pin your consumers to
it.

### Pretty-printed JSON (`--json-pretty`)

`--json-pretty` emits the identical message record. It indents the record
across several lines instead of packing it onto one. Reach for it when a person reads the
output:

```bash
sipnab -N -I capture.pcap --json-pretty
```

It costs you the NDJSON property, and that matters to anything downstream:

- A line no longer holds a whole record.
- A tolerant concatenated-JSON parser still reads the stream.
- A tool that splits on newlines no longer does.

Anything a pipeline consumes wants `--json`.

- Both flags need `-N` / `--no-tui`.
- Passing both gives the indented form. `--json-pretty` wins the branch.
- Both fall silent under `--no-cli-print`. It suppresses the per-message stream
  whatever shape it takes.

### jq recipes

One recipe per question, each a complete pipeline. Run the one you want, not
the whole list.

Keep only the INVITEs:

```bash
sipnab -N -I capture.pcap --json | jq 'select(.method == "INVITE")'
```

Find the calls placed by one user. `from` carries the whole `From` header. So
test it for a substring rather than comparing it for equality:

```bash
sipnab -N -I capture.pcap --json | jq 'select(.from // "" | test("sip:1001@"))'
```

Count the messages per method, to see what a capture holds before reading
any of it:

```bash
sipnab -N -I capture.pcap --json \
  | jq -s 'group_by(.method) | map({method: .[0].method, n: length})'
```

Pull the failed responses (4xx/5xx/6xx) with the reason each one carries:

```bash
sipnab -N -I capture.pcap --json \
  | jq 'select(.status_code != null and .status_code >= 400)
        | {ts: .timestamp, code: .status_code, reason, call_id}'
```

List the distinct Call-IDs seen. This is the list you feed into
`--call-report`:

```bash
sipnab -N -I capture.pcap --json | jq -r '.call_id' | sort -u
```

Build a response-code histogram, counting how many of each status code the
capture holds:

```bash
sipnab -N -I capture.pcap --json \
  | jq -r 'select(.is_request == false) | .status_code' \
  | sort | uniq -c | sort -rn
```

## Summary-only output

`--json` prints a line per message. For end-of-run summaries instead, combine
the report flags with [`--no-cli-print`](cli-reference.md#output).
That flag suppresses the per-message stream but not the report.

For the aggregate report over the whole capture, and nothing else:

```bash
sipnab -N -I capture.pcap --report --no-cli-print
```

When the inputs include stored vCon containers (`-I` naming a directory of
them, for example), the report adds a `vCon containers:` section after the
dialog table:

- one row per container: read, or skipped with the reason;
- the totals: containers read and skipped, skips by reason, containers that
  fail the schema, calls by state, and the total duration.

With `--json` or `--json-pretty`, that section is one JSON object under the
key `sipnab_vcon_containers` instead. [Read many containers at
once](vcon.md#read-many-containers-at-once) describes every column and field.

For a deep dive into a single call, named by its Call-ID:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1' --no-cli-print
```

## Dialog / stream JSON

The richer aggregated dialog object is one shape produced by a single
serializer. It holds:

- `state`,
- `timing` (PDD / setup / ring / teardown milliseconds, retransmit counts),
- `sdp_timeline`,
- `streams` with jitter and loss,
- the four `diagnosis` flags (`one_way_audio`, `nat_mismatch`, `no_media`,
  `private_media_address`),
- `hints`.

One place documents it, with a full worked example, under
[`GET /v1/dialogs/{call_id}` in the REST API reference](rest-api.md#get-v1-dialogs-call-id).

### One object per dialog

`--json` is a per-message stream. `--json-dialogs` emits the same dialog
document the REST API returns. It writes one compact line per call, after
capture completes:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.state == "Failed") | {call_id, final_status_code, final_status_reason}'
```

Reach for it when the question is *which calls failed and why* rather than
*what did the wire carry*.

- A dialog-level filter like `state == 'Failed'` selects dialogs.
- `--json` then emits every message belonging to them. That includes the 100
  Trying and the 401 challenge alongside the 488 that actually failed the call.
  All carry the same `call_id`.
- Joining those back together is work the per-dialog form does for you.

`final_status_code` is the response that decided the outcome, with auth
challenges excluded. A call challenged and then answered reports 200, not
the 401.

`final_status_reason` is the phrase from the wire.
[RFC 3261 section 7.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.2)
leaves it as free text. `500 Service Unavailable` is legal and common, so match
on the code.

**Both fields read the transaction that decides the dialog**: its INVITE when
it holds one, otherwise the request that opened it.

- An INVITE dialog reports its INVITE's outcome, not the 200 to its BYE.
- So does a Call-ID that registered first and then called.
- A `REGISTER` rejected `403` reports 403.
- A `PUBLISH` refused `489` reports 489.
- A `SUBSCRIBE` reports the answer to the SUBSCRIBE, not to a later NOTIFY.
- Both are absent while that request has no final response.

For registrations, `signaling_diagnosis` says more than the code:

- `final_failure.code` carries the status for any dialog.
- `registration_failure` answers the registration question directly:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.state == "Failed") |
           {call_id, method,
            code: (.final_status_code // .signaling_diagnosis.final_failure.code)}'
```

A `signaling_diagnosis` object sits beside `diagnosis` when something is wrong
with the signaling rather than the media.

- It **drops out entirely** when the detections found nothing.
- So a consumer that does not read the field sees a healthy dialog unchanged.
- Nine detections run over every dialog.
- Each names the messages it drew on, as indices into the dialog's own message
  list:

| Field | Meaning |
|---|---|
| `final_failure` | The dialog ended on a `4xx`/`5xx`/`6xx`. Carries `code`, `reason_phrase`, and the `Reason:` ([RFC 3326](https://www.rfc-editor.org/rfc/rfc3326.html)) and `Warning:` headers when present, which frequently hold the real cause behind a generic status code. |
| `auth_loop` | Three or more `401`/`407` challenges with no `2xx`. `kind` is `credential_failure` when the client answers each challenge and is re-challenged, or `silent_drop` when it never sends `Authorization` at all — different faults with different fixes. |
| `retransmissions` | A request retransmitted with no response, identified by CSeq plus top-`Via` branch. Reports `method`, `count` and `span_sec`, because "7 INVITEs over 32 seconds" is diagnostic and "retransmissions detected" is not. `icmp_cause` is present only when the capture also held an ICMP error for the dialog, and carries the network's own words for the silence — see below. |
| `ack_missing` | A `2xx` answer to an `INVITE` that no `ACK` followed, once the observation window passed RFC 3261 Timer H (32 s). Carries `waited_sec` and `answer_transmissions` — a UAS retransmits its answer until Timer H, so a count above one is the peer agreeing the `ACK` never arrived. |
| `abandoned` | The dialog never reached a final response. `kind` separates the two cases, which are not the same claim: `canceled` means someone sent a `CANCEL`, `no_final_response` means the wait outlived RFC 3261 Timer C (180 s) — a statement about the capture, **not** a failed call. Carries `elapsed_sec`. |
| `post_dial_delay` | `INVITE` to first provisional response over 11 s, the ITU-T E.721 Table 2 ninety-fifth-percentile target for an international connection. Carries `delay_sec`, the `threshold_sec` it exceeded, and the `responded_with` code that ended the wait. |
| `registration_failure` | A `REGISTER` rejected (`kind: rejected`), or granted less time than it asked for (`kind: shortened_expiry`, `code: 200`). Carries `requested_expiry_sec` and `granted_expiry_sec` when the messages said. Kept separate from `final_failure` because "is this phone online?" is a different question from "why did this call fail?". |
| `icmp_unreachable` | An ICMP or ICMPv6 error quoting one of this dialog's requests. Carries `unreachable_endpoint` (the host that did not answer), `reported_by` (the router or host that sent the error — a *different* machine), `description` of the ICMP cause, the raw `icmp_type` / `icmp_code` bytes, the quoted request's `method`, an exact `errors` count, and `truncated`. |
| `source_disagreement` | Present only on a run reading from TWO capture sources at once (`-d` with `-L`), and only when they told different stories about this call. A HEP mirror reports what the proxy *believes* it did; the local capture reports what actually left the box, which is why the pair is worth having and why the disagreement is the finding. Carries `agreed` (messages both witnesses carried -- the denominator), `mirror_only` (the proxy believes it sent something that never left the box), `wire_only` (the box did something its own trace does not admit to) and `sdp_differs` (both carried it, and each advertised different media endpoints -- a rewrite). Each `sdp_differs` entry names `mirror` and `wire` side by side and neither as the truth. |

Every finding carries an `evidence` array of message indices. `hints` carries
one plain-language line per finding.

The first seven fields are always present. `null` there means "checked,
nothing found".

sipnab **omits** the last two when absent. Neither can run on every capture, and
a `null` would claim a check that never happened:

- `icmp_unreachable` needs a capture that holds ICMP at all.
- `source_disagreement` needs two capture sources that both carried the call.

`icmp_unreachable` is worth singling out. It is the only finding that reports a
**fact** rather than an inference.

- The others read the SIP and reason about what the silence means.
- This one carries a router's own statement that the far end is not reachable.

Two fields repay attention:

- `errors` is the exact number of ICMP errors the dialog drew. It is not the
  number of quotes sipnab retained.
  - A cap bounds retention. On a real capture 720 of 3,232 errors fell past it.
  - Reporting the retained count would have said "8 times" for a peer that
    failed thirty.
  - `evidence` draws on the retained quotes only. So on a heavily hit dialog it
    names fewer messages than `errors` counts.
- `unreachable_endpoint` is the socket to go and look at.
  - `reported_by` is the device that noticed and said so. That is usually a
    working router in the path.
  - Sending an engineer to the reporter wastes the finding.

`truncated` is `true` in the ordinary case.
[RFC 792](https://www.rfc-editor.org/rfc/rfc792.html) guarantees only 8 bytes
past the quoted IP header, so most quotes are a prefix. The field exists so a
reader knows the quote was partial. Otherwise a reader might assume the fields
came from a whole datagram.

The ICMP description is the network's wording, not an instruction. The
commonest codes send you to different devices. sipnab spells that out in the
hint:

- `port unreachable` means the host answered and no service holds that port.
  So the fault is the service.
- `administratively prohibited` means a firewall or router ACL refused the
  packet. The peer may be perfectly healthy, and the fix is the filter.
- `host unreachable` means nothing reached the host at all. So the capture says
  nothing about its ports.

On one real corpus a single capture held 433 host-unreachable, 262
administratively prohibited and 63 port-unreachable errors. So one sentence for
all three would have been wrong for most of them.

### STUN evidence inside the media diagnosis

`diagnosis.private_media_address` is a warning. It means:

- the SDP `c=` line names an
  [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918.html) / [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193.html) / link-local address,
- and the peer is not itself private,
- so the far end cannot route back to it.

It is correct inside one LAN. It is also correct behind an SBC, ALG or media
proxy that rewrites the SDP downstream. That is why the hint asks the reader to
check which of those they are in.

`diagnosis.stun_sdp_mismatch` is the evidence that settles it.

- sipnab **omits** it on any capture with no STUN in it. So a consumer written
  before it existed sees no change.
- It is never present without `private_media_address` also being `true`.
  - One address, one problem.
  - STUN is the corroboration rather than a second finding.

| Field | Meaning |
|---|---|
| `reason` | `ignored` — STUN told the client a public address and the SDP advertised the private one anyway. `relay_ignored` — a TURN server allocated the client a relayed address and the SDP advertised the private one anyway. `unanswered` — the client's request drew nothing, so it never learned a public address to advertise. |
| `client` | The socket the STUN request left from, `ip:port`. |
| `server` | The STUN or TURN server it went to. The box to check when the reason is `unanswered`. |
| `mapped_address` / `relayed_address` | The reachable address the server returned and the client did not use. Absent on `unanswered`, where there is none — that is the point of it. |
| `advertised` | The unroutable address the SDP named instead. |
| `request_count` | Requests sent for that transaction. Above one is a retransmission, which [RFC 5389 section 7.2.1](https://www.rfc-editor.org/rfc/rfc5389.html#section-7.2.1) sends only on timeout — so it is itself proof the earlier attempts drew silence. |
| `observed_offset_secs` | Seconds from the start of this dialog to the STUN evidence; negative when the probe came first, which is the ordinary case. Absent when either time is unknown. |

`observed_offset_secs` exists because the correlation is by **client IP
alone**. Nothing in a Binding Request names a Call-ID. So a probe from the
right address matches this dialog whether it happened during setup or an hour
earlier.

- Inside a two-minute window the finding is an observation of this call.
- Well outside it, the same finding is an inference that the client's
  NAT-discovery failure persisted. That is usually true, and not the same claim.
- Past that window the hint appends a note saying so.
- Inside it the hint says nothing, because a caveat printed every time is one
  nobody reads.

`diagnosis.media_relay` is context rather than a finding. It is likewise
**omitted** on any capture with no TURN relay in it.

It answers "where did this call's audio actually go". For a relayed call
nothing else in the capture answers that. Its fields:

- `client`,
- `server`,
- `relayed_address` (the address the far end really sends to),
- `channel`,
- `peer`,
- `lapsed`.

`lapsed: true` is the capture-level `turn_allocation_lapsed` finding narrowed
to **this** call's media. It is the only shape that also adds a hint. A relay
doing its job needs no sentence in a list an operator reads for problems.

A `relay_ignored` or `ignored` finding raises `private_media_address` on its
own, with no observed stream needed. A public mapped or relayed address is
proof the client's traffic reaches the internet.

`unanswered` does so only when the server it asked is itself public.

- Silence from a STUN server on the same LAN proves nothing.
- Flagging it would fire on every LAN-only capture.

### When ICMP and retransmissions both fire

`retransmissions` and `icmp_unreachable` frequently appear on the same dialog.
They are not two views of one thing.

- `retransmissions` measures how hard the sender tried before giving up.
- `icmp_unreachable` states why nothing came back.

So the ICMP fact **annotates** the retransmission finding rather than replacing
it.

- sipnab sets `retransmissions.icmp_cause` to the ICMP description.
- The hint stops guessing at "a one-way path or an unreachable peer".
- The `count` and `span_sec` stay as they were. Suppressing the finding would
  delete a measurement to remove a sentence.

With no ICMP in the capture, `icmp_cause` is absent. The retransmission hint
then offers the inference on its own. That is the honest answer when nothing
better is available.

The same document is what you get from:

- the REST `GET /v1/dialogs/{call_id}` and
  `GET /v1/dialogs/{call_id}/report` endpoints,
- MCP tool responses (`get_dialog_report` with `format: "json"` — see the
  [MCP tool reference](mcp-tools-signaling.md#get_dialog_report)), and
- `SIPNAB_JSON` in [`--on-dialog-exec`](cli-reference.md#event-execution)
  hooks.
  - Note the dialog hook fills `streams: []` and a default `diagnosis`.
  - It fires on a dialog event, when media analysis for that call may not be
    complete.
  - So the stream and diagnosis fields are placeholders there rather than
    populated data.

`--on-quality-exec` is separate. It passes the stream object on its own, under
its own variable name: `SIPNAB_STREAM_JSON`, **not** `SIPNAB_JSON`.

## STUN / TURN JSON (`--json-stun`)

NDJSON, emitted after capture:

- one object per STUN or TURN transaction,
- then one per TURN allocation.

Every line carries a `record` field naming its kind. So a consumer never has
to infer the shape from which keys happen to be present.

```bash
sipnab -N -I capture.pcap --json-stun --no-cli-print \
  | jq -c 'select(.record == "transaction" and .responded_at == null)
           | {client, server, method_name, request_count}'
```

A `transaction` carries:

- the hex `transaction_id`,
- `client` and `server` sockets,
- `method` and `method_name`,
- `first_request` / `last_request` / `responded_at` timestamps,
- `request_count`,
- `rtt_ms`,
- and whatever the exchange produced: `mapped_address`, `relayed_address`,
  `peer_address`, `lifetime_secs`, `channel_number`, `error_code`,
  `auth_challenge`, `software`, `ice_role`, `use_candidate` and
  `fingerprint_valid`.

- `responded_at: null` is the finding: nothing answered.
- `request_count` above one is a retransmission. That is itself proof the
  earlier attempts drew silence.
- `auth_challenge: true` says the opposite. The server was reachable and asked
  for credentials, so nothing in the network path is at fault.
- `fingerprint_valid` is three-valued on purpose:
  - `true` verified,
  - `false` present and WRONG,
  - `null` absent — sipnab did not check. Reporting that as `false` would
    accuse a message nobody examined.

A `turn_allocation` carries `client`, `server`, `relayed_address`,
`lifetime_secs`, `allocated_at`, `refreshed_at`, `refreshes`, `last_activity`,
`released`, `channels`, `unattributed_frames`, and the derived `lapsed`:

```bash
sipnab -N -I relay.pcap --json-stun --no-cli-print | jq 'select(.lapsed == true)'
```

`lapsed: true` means traffic was still crossing the relay after the lifetime
the server last granted had run out. The capture shows no Refresh in between.

- A TURN server tears an allocation down the moment its lifetime lapses.
- The media stops with it, mid-call, with **no SIP message anywhere to explain
  it**.
- The signaling shows a healthy call that went quiet.

A deliberate release (a Refresh with `LIFETIME` 0) sets `released` and is never
`lapsed`. The client asked for the teardown.

`channels` is what ties the relay to the media. Each entry carries:

- the `channel` number,
- the `peer` the ChannelBind named. It is absent when no bind appears in the
  capture. The frames still attribute, and the far side is simply not in this
  file.
- `bound`, `frames`, `bytes`, `first_seen` / `last_seen`,
- and the `ssrcs` observed inside the frames.

Those SSRCs are the join to the stream list.

- sipnab unwraps ChannelData. The RTP inside reaches the stream store as an
  ordinary stream.
- But that stream carries **phone-to-relay** addresses.
- So without this, nothing said the relay had carried it at all.
- And a lapsed allocation could say it lapsed while naming not one packet that
  died with it.

```bash
sipnab -N -I relay.pcap --json-stun --no-cli-print \
  | jq -r 'select(.lapsed == true) | .channels[].ssrcs[]'
```

`ssrcs` counts media only. RTCP relayed on the same channel raises `frames`
and `bytes` and contributes no SSRC. Its bytes 8..12 are not a stream in the
sense the stream list means.

`unattributed_frames` counts relayed frames whose channel fell outside the
per-allocation cap.

- Non-zero means `channels` holds a sample of what crossed the allocation.
- Every text surface says so when it does.
- `ssrcs_dropped` is the same statement one level down.

An `ice` record appears once, and only on a capture holding ICE connectivity
checks. These are Binding Requests carrying the `PRIORITY` and role attributes
[RFC 8445 section 7.2.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.1) requires.
Those attributes are what tell them from a plain server-reflexive probe to a
STUN server:

| Field | Meaning |
|---|---|
| `checks` / `checks_answered` | Connectivity checks seen, and how many drew an answer of either kind. `checks_answered: 0` with `checks` above zero means ICE never completed and the call has no media path — the individual transactions are already in the `transaction` records above, which is why this is a count and not a second finding. |
| `nominated` | Candidate pairs a `USE-CANDIDATE` check nominated **and** the peer confirmed. Each carries `local`, `remote`, `role`, `priority`, `nominated_at` and `rtt_ms`. This is the ICE analogue of `mapped_address`: it names the path the media actually took. |
| `role_conflicts` | Pairs where both agents claimed one role, or where one answered `487 Role Conflict`. Each carries `a`, `b`, the `role` both claimed, `role_conflict_responses`, and `resolved`. |
| `nominated_total` / `role_conflicts_total` | Exact counts, which stay right past the retention cap that bounds the two lists above. |

- `resolved: true` means the agents nominated a pair between them anyway.
  - ICE fixed the conflict itself.
  - The cost was one round trip of repeated checks.
- `resolved: false` means they never nominated anything between them.
  - That makes the conflict a candidate cause of media that never started.

## Capture analysis (`--json-analyze`)

One JSON object for the whole run, not a line per finding.

- `frames_read`, `dialogs_examined` and `streams_examined` are properties of
  the run rather than of any finding.
- A clean capture must still serialize to something that states them.

The object opens with `schema_version` (currently `1`).
[`tests/schemas/capture_analysis.schema.json`](../tests/schemas/capture_analysis.schema.json)
describes it field by field. The same object is the `GET /v1/report` body and
the MCP `get_capture_report` answer.

```bash
sipnab -N -I capture.pcap --json-analyze --no-cli-print \
  | jq '.findings[] | select(.severity == "critical") | {kind, occurrences}'
```

`findings` ranks worst first. Each carries:

- a stable `kind`,
- a `severity`,
- an exact `occurrences` count in its `unit`,
- an `evidence` array pointing back at the capture with Call-IDs, endpoints,
  timestamps and counts,
- `evidence_omitted`, the rows a cap of ten kept out.

A finding has no `summary` field. The title and the one-sentence explanation
belong to the kind. So the text report prints them, and the JSON names the
`kind`.

`filter` appears only when `--filter` or a diagnostic alias narrowed the
dialogs. It holds the expression that ran, after alias expansion. So
`--filter one-way` records `one_way == true`.

The filter narrows the dialogs and nothing else.

- STUN probes, ICMP that reached no dialog, undecodable frames and retention
  losses are capture-level.
- The analysis always reports them whole.

`complete` is the field to read first. It is `false` when the run did not
decode everything it received:

- undecodable frames,
- SIP a port gate discarded,
- records a retention cap dropped.

Then every count below it is a **floor**. The analysis refuses a clean verdict
over a capture it could not fully read:

```bash
sipnab -N -I capture.pcap --json-analyze --no-cli-print | jq '.complete'
```

`--analyze` derives nothing new. `--analyze` aggregates the per-dialog diagnosis
sipnab already computes and the capture-level evidence it already holds. It
ranks and counts them, and adds no judgement of its own.

## YANG export (`--yang-analyze`)

The capture analysis again, encoded as
[RFC 7951](https://www.rfc-editor.org/rfc/rfc7951.html) JSON against sipnab's
own YANG 1.1 module, `sipnab-diagnosis`. It is the same value `--json-analyze`
prints. A tool that speaks YANG can do these things without learning sipnab's
JSON first:

- validate it,
- draw its tree with `pyang -f tree`,
- generate code for it.

```bash
sipnab -N -I capture.pcap --yang-analyze --no-cli-print > analysis.json
```

To check it, save the module this sipnab writes against. Then hand both to
`yanglint`:

```bash
sipnab --print-yang-module > sipnab-diagnosis@2026-10-09.yang
```

```bash
yanglint -t data sipnab-diagnosis@2026-10-09.yang analysis.json
```

`--print-yang-module` prints the module this sipnab validates against. The
repository commits the same file at
[`yang/sipnab-diagnosis@2026-10-09.yang`](../yang/sipnab-diagnosis@2026-10-09.yang).

The document has one member, `sipnab-diagnosis:capture-analysis`. It differs
from the `--json-analyze` object only in how it writes the same facts:

| `--json-analyze` | `--yang-analyze` | Why |
|---|---|---|
| `frames_read` | `frames-read` | YANG names use hyphens. Every field follows the same rule. |
| `"frames_read": 1024` | `"frames-read": "1024"` | [RFC 7951 section 6.1](https://www.rfc-editor.org/rfc/rfc7951.html#section-6.1) writes every 64-bit integer as a string: `frames-read`, `dialogs-examined`, `streams-examined`, `occurrences`, `evidence-omitted`, and each count's `value`. `schema-version`, `rank` and `index` stay numbers. |
| `findings` in ranked order | `finding`, with a `rank` counting from 1 | YANG gives state data no order, so the position becomes a leaf. |
| `evidence` in order | `evidence`, each with an `index` counting from 1 | The same reason. |
| `endpoints` | `endpoint` | YANG names a leaf-list for one entry. |
| `counts: {"rtp_packets": 425}` | `count: [{"name": "rtp_packets", "value": "425"}]` | A map becomes a list keyed by `name`. |
| `[]` for no findings | no `finding` member | A YANG list has no empty form. |

`kind` keeps the same strings in both encodings, such as `one_way_audio`.

- Each finding kind and each count label is an identity in the module.
- Its description is the kind's title and one-sentence explanation.
- That makes the module a catalog of everything the analysis can report.

A string from the capture may hold a character YANG cannot carry, such as a
control character in a reason phrase. sipnab then writes U+FFFD in its place.
That substitution is the only change to the text itself.

The module does not model the per-dialog `diagnosis` and
`signaling_diagnosis`. Their "`null` means checked, absent means not run"
distinction has no RFC 7951 equivalent. So they need their own modeling pass.

The REST API serves the same document at `GET /v1/report?format=yang-json` as
`application/yang-data+json`. The MCP tool `get_capture_report` answers it for
`{"format": "yang-json"}`.

sipnab does not run a NETCONF or RESTCONF server. It writes documents that
conform to the module.

## vCon (`--export-vcon`)

A different kind of output from everything above.

- The formats on this page are sipnab's own shapes. sipnab reads them, and so
  does whatever you write around it.
- A vCon is an interchange container other people's systems already parse.
  Examples: a conversation archive, a compliance store, an agent that reasons
  over calls.

```sh
sipnab -N -I call.pcap --export-vcon 'CALL-ID' --vcon-out out.json
```

One dialog per container, never a whole capture. sipnab writes it as an
OBSERVER:

- it names itself as a party that took no part in the call,
- it carries the audio inline when the run retained the RTP payload,
- it states in two places what the capture missed.

It signs nothing.

It sits behind the non-default `vcon` feature. So a stock build refuses the
flag and says so. The [vCon page](vcon.md) covers what a consumer may and may
not conclude from one. That matters more here than the field list.

## pcap / pcapng

`-O <file>` writes captured packets, and `--pcapng` selects PCAP-NG.

With TLS decryption, `--pcap-export-mode` controls whether decryption secrets
(DSBs) travel with the file for Wireshark:

- The default `raw` mode embeds no keys.
- `encrypted+dsb` opts into key-bearing PCAP-NG.
- `decrypted` writes what sipnab decrypted as plaintext SIP and RTP, with no
  keys, and everything else as captured.

[Examples](examples.md) shows it. Rotation: `--split filesize:N` /
`--split duration:N`, or SIGUSR1 on demand.

pcapng timestamps are nanosecond-resolution. sipnab declares this via
`if_tsresol=9` in the Interface Description Block.

- Files written by sipnab <= 0.5.0 stored nanosecond ticks but omitted that
  declaration.
- So other readers inflated every time value ×1000 (`capinfos` reporting year
  58484).
- [`scripts/repair_pcapng_tsresol.py`](../scripts/repair_pcapng_tsresol.py)
  repairs such old captures in place without touching packet data.

## Operator notes file

The notes `--write-annotated` writes into a capture, one JSON object per line:

```json
{"frame":"call.pcap#0@bdb6cdb98013efe4","note":"the INVITE the SBC answered twice"}
{"frame":"call.pcap#4@0b1c8f3e5a7d2946","note":"183 here, and the SDP changed"}
```

- `frame` names the frame the note is about, as a frame pointer. It is the
  `frame` field of `--json`, copied as it is.
  - `--write-annotated` requires the `@<digest>` half. Only the digest proves a
    note lands on the frame it describes.
  - It refuses a byte-range suffix (`+start-end`). A note is about a whole
    frame.
- `note` is the text.
  - At most 4096 bytes of UTF-8.
  - No control character other than newline and tab.
  - No SDES `inline:` key, TLS key-log line or digest `response=` value. The
    capture leaves the machine, and a key pasted into a note would travel in
    clear.

sipnab accepts no other field. One bad line refuses the whole file. The error
names the line without quoting the note.

A notes file sipnab writes has mode `0600`, because it holds free text about a
call. The schema is
[`tests/schemas/notes.schema.json`](../tests/schemas/notes.schema.json).

In the annotated pcapng, each note is a packet comment that starts
`[operator note] `. The section comment says how many comments are notes typed
by a person.

sipnab writes packet comments and never reads one. `--json` over the annotated
copy is what it is over the original.

## See also

- [cli-reference.md](cli-reference.md#output) — every output flag
- [examples.md](examples.md#feed-ndjson-into-jq-and-other-tools) — NDJSON-to-jq pipeline recipes
