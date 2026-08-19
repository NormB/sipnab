# Output formats

sipnab has four output modes: interactive TUI (default), per-message CLI
text (`-N`), structured NDJSON (`--json`), and the [MCP server](mcp.md).
This page documents the machine-readable formats.

> **Prerequisites:** `--json` requires non-interactive mode (`-N` /
> `--no-tui`) — sipnab refuses to start otherwise (exception:
> `--call-report` implies non-interactive output). NDJSON needs no extra build
> feature: it is part of the default build. Full flag
> reference: [CLI reference](cli-reference.md#output).

## NDJSON (`--json`)

`--json` emits one JSON object per SIP message — newline-delimited, so
each line is independently parseable and the stream is pipe-friendly:

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

`from` and `to` are the **full** `From` / `To` header values — display
name, URI and tags included — not the bare user part. (The aggregated
dialog object below is the one that carries the user part.) Match them
with a regex or a substring test, not with equality.

`cseq` (the parsed `CSeq` header — `{ number, method }`) appears on **every**
message, requests included, so re-requests within a dialog (e.g. two REGISTERs
with `CSeq` 1 and 2) stay distinguishable. It drops out only when the `CSeq`
header is absent or unparseable.

`contact` is the `Contact` header value when present (routing-critical, omitted
otherwise). `sdp` is the raw SDP body, emitted **only** when `Content-Type` is
`application/sdp` and the body is valid UTF-8 — it lets a consumer verify the
negotiated media (connection / `m=` / `a=rtpmap`) that dynamic-PT decode depends
on. Omitted for non-SDP or non-UTF-8 bodies.

`response_context` (`"<num> <method>"`, responses only — what the response
answers) is a deprecated alias of `cseq`, retained for backward compatibility
under `schema_version` 1. Prefer `cseq`.

`malformed` is a list of structural-defect diagnostics, present **only** when a
message arrives malformed. A well-formed message omits the field. It surfaces crafted
or broken input rather than silently accepting it: missing mandatory headers
(`Call-ID`/`CSeq`/`From`/`To`/`Via`), an unparseable `CSeq`, a `Content-Length`
larger than the body actually present (truncated/lying length), and control/NUL
bytes in a header. Example: `"malformed": ["missing mandatory header: Call-ID"]`.

`schema_version` increments on breaking field changes — pin your
consumers to it.

### jq recipes

One recipe per question, each a complete pipeline — run the one you want, not
the whole list.

Keep only the INVITEs:

```bash
sipnab -N -I capture.pcap --json | jq 'select(.method == "INVITE")'
```

Find the calls placed by one user. `from` carries the whole `From` header, so
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

List the distinct Call-IDs seen — this is the list you feed into
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

`--json` prints a line per message. For end-of-run summaries instead,
combine the report flags with
[`--no-cli-print`](cli-reference.md#output) (which suppresses the
per-message stream but not the report).

For the aggregate report over the whole capture, and nothing else:

```bash
sipnab -N -I capture.pcap --report --no-cli-print
```

For a deep dive into a single call, named by its Call-ID:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1' --no-cli-print
```

## Dialog / stream JSON

The richer aggregated dialog object — `state`, `timing` (PDD / setup /
ring / teardown milliseconds, retransmit counts), `sdp_timeline`,
`streams` with jitter and loss, and the `diagnosis` flags (`one_way_audio`,
`nat_mismatch`, `no_media`) plus `hints` — is one shape produced by a single
serializer. One place documents it, with a full worked example, under
[`GET /v1/dialogs/{call_id}` in the REST API reference](rest-api.md#get-v1-dialogs-call-id).

### One object per dialog

`--json` is a per-message stream. `--json-dialogs` emits the same dialog document
the REST API returns, one compact line per call, after capture completes:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.state == "Failed") | {call_id, final_status_code, final_status_reason}'
```

Reach for it when the question is *which calls failed and why* rather than *what
did the wire carry*. A dialog-level filter like `state == 'Failed'` selects
dialogs, and `--json` then emits every message belonging to them — the 100
Trying and the 401 challenge alongside the 488 that actually failed the call, all
carrying the same `call_id`. Joining those back together is work the per-dialog
form does for you.

`final_status_code` is the response that decided the outcome, with auth
challenges excluded: a call challenged and then answered reports 200, not the
401. `final_status_reason` is the phrase from the wire, which [RFC 3261 §7.2](https://www.rfc-editor.org/rfc/rfc3261#section-7.2)
leaves as free text — `500 Service Unavailable` is legal and common, so match on
the code.

**Both fields read INVITE transactions only, and are absent from every other
dialog.** A `REGISTER` rejected `403`, an `OPTIONS` that timed out `408`, a
failed `SUBSCRIBE` — each carries `state: "Failed"` and no
`final_status_code` at all, because no INVITE CSeq exists to take a code from.
The recipe above is therefore a *call* recipe: point it at registration or
keepalive traffic and every row comes back empty. For those, read
`signaling_diagnosis` instead — `final_failure.code` carries the status for any
dialog, and `registration_failure` answers the registration question directly:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.state == "Failed") |
           {call_id, method,
            code: (.final_status_code // .signaling_diagnosis.final_failure.code)}'
```

A `signaling_diagnosis` object sits beside `diagnosis` when something is wrong
with the signaling rather than the media, and **drops out entirely** when
the detections found nothing — so a healthy dialog serializes exactly as before
the field existed. Eight detections run over every dialog, each naming the
messages it drew on as indices into the dialog's own message list:

| Field | Meaning |
|---|---|
| `final_failure` | The dialog ended on a `4xx`/`5xx`/`6xx`. Carries `code`, `reason_phrase`, and the `Reason:` ([RFC 3326](https://www.rfc-editor.org/rfc/rfc3326)) and `Warning:` headers when present, which frequently hold the real cause behind a generic status code. |
| `auth_loop` | Three or more `401`/`407` challenges with no `2xx`. `kind` is `credential_failure` when the client answers each challenge and is re-challenged, or `silent_drop` when it never sends `Authorization` at all — different faults with different fixes. |
| `retransmissions` | A request retransmitted with no response, identified by CSeq plus top-`Via` branch. Reports `method`, `count` and `span_sec`, because "7 INVITEs over 32 seconds" is diagnostic and "retransmissions detected" is not. `icmp_cause` is present only when the capture also held an ICMP error for the dialog, and carries the network's own words for the silence — see below. |
| `ack_missing` | A `2xx` answer to an `INVITE` that no `ACK` followed, once the observation window passed RFC 3261 Timer H (32 s). Carries `waited_sec` and `answer_transmissions` — a UAS retransmits its answer until Timer H, so a count above one is the peer agreeing the `ACK` never arrived. |
| `abandoned` | The dialog never reached a final response. `kind` separates the two cases, which are not the same claim: `canceled` means someone sent a `CANCEL`, `no_final_response` means the wait outlived RFC 3261 Timer C (180 s) — a statement about the capture, **not** a failed call. Carries `elapsed_sec`. |
| `post_dial_delay` | `INVITE` to first provisional response over 11 s, the ITU-T E.721 Table 2 ninety-fifth-percentile target for an international connection. Carries `delay_sec`, the `threshold_sec` it exceeded, and the `responded_with` code that ended the wait. |
| `registration_failure` | A `REGISTER` rejected (`kind: rejected`), or granted less time than it asked for (`kind: shortened_expiry`, `code: 200`). Carries `requested_expiry_sec` and `granted_expiry_sec` when the messages said. Kept separate from `final_failure` because "is this phone online?" is a different question from "why did this call fail?". |
| `icmp_unreachable` | An ICMP or ICMPv6 error quoting one of this dialog's requests. Carries `unreachable_endpoint` (the host that did not answer), `reported_by` (the router or host that sent the error — a *different* machine), `description` of the ICMP cause, the raw `icmp_type` / `icmp_code` bytes, the quoted request's `method`, an exact `errors` count, and `truncated`. |

Every finding carries an `evidence` array of message indices, and `hints`
carries one plain-language line per finding.

The first seven fields are always present: `null` there means "checked, nothing
found". `icmp_unreachable` is the exception and is **omitted** when absent,
because it is the one detection that cannot run unless the capture holds ICMP at
all — a `null` on a capture that carried none would claim a check that never
happened.

`icmp_unreachable` is worth singling out because it is the only finding that
reports a **fact** rather than an inference. The others read the SIP and reason
about what the silence means. This one carries a router's own statement that the
far end is not reachable. Two fields repay attention:

- `errors` is the exact number of ICMP errors the dialog drew, not the number of
  quotes sipnab retained — a cap bounds retention, and on a real capture 720 of
  3,232 errors fell past it. Reporting the retained count would have said "8
  times" for a peer that failed thirty. `evidence` draws on the retained quotes
  only, so on a heavily hit dialog it names fewer messages than `errors` counts.
- `unreachable_endpoint` is the socket to go and look at. `reported_by` is the
  device that noticed and said so, usually a working router in the path.
  Sending an engineer to the reporter wastes the finding.

`truncated` is `true` in the ordinary case: [RFC 792](https://www.rfc-editor.org/rfc/rfc792) guarantees only 8 bytes past
the quoted IP header, so most quotes are a prefix. The field exists so a reader
knows the quote was partial rather than assuming the fields came from a whole
datagram.

The ICMP description is the network's wording, not an instruction, and the
commonest codes send you to different devices. sipnab spells that out in the
hint: `port unreachable` means the host answered and no service holds that
port, so the fault is the service. `administratively prohibited` means a
firewall or router ACL refused the packet -- the peer may be perfectly healthy
and the fix is the filter. `host unreachable` means nothing reached the host at
all, so the capture says nothing about its ports. On one real corpus a single capture
held 433 host-unreachable, 262 administratively prohibited and 63
port-unreachable errors, so one sentence for all three would have been wrong
for most of them.

### STUN evidence inside the media diagnosis

`diagnosis.private_media_address` is a warning: the SDP `c=` line names an
[RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) / [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) / link-local address, and the peer is not itself private, so
the far end cannot route back to it. It is correct inside one LAN, and correct
behind an SBC, ALG or media proxy that rewrites the SDP downstream — which is
why the hint asks the reader to check which of those they are in.

`diagnosis.stun_sdp_mismatch` is the evidence that settles it, and it is
**omitted** on any capture with no STUN in it, so a consumer written before it
existed sees no change. It is never present without `private_media_address` also
being `true`: one address, one problem, with STUN as the corroboration rather
than as a second finding.

| Field | Meaning |
|---|---|
| `reason` | `ignored` — STUN told the client a public address and the SDP advertised the private one anyway. `relay_ignored` — a TURN server allocated the client a relayed address and the SDP advertised the private one anyway. `unanswered` — the client's request drew nothing, so it never learned a public address to advertise. |
| `client` | The socket the STUN request left from, `ip:port`. |
| `server` | The STUN or TURN server it went to. The box to check when the reason is `unanswered`. |
| `mapped_address` / `relayed_address` | The reachable address the server returned and the client did not use. Absent on `unanswered`, where there is none — that is the point of it. |
| `advertised` | The unroutable address the SDP named instead. |
| `request_count` | Requests sent for that transaction. Above one is a retransmission, which [RFC 5389 §7.2.1](https://www.rfc-editor.org/rfc/rfc5389#section-7.2.1) sends only on timeout — so it is itself proof the earlier attempts drew silence. |
| `observed_offset_secs` | Seconds from the start of this dialog to the STUN evidence; negative when the probe came first, which is the ordinary case. Absent when either time is unknown. |

`observed_offset_secs` exists because the correlation is by **client IP alone**.
Nothing in a Binding Request names a Call-ID, so a probe from the right address
matches this dialog whether it happened during setup or an hour earlier. Inside
a two-minute window the finding is an observation of this call. Well outside it,
the same finding is an inference that the client's NAT-discovery failure
persisted — usually true, and not the same claim. Past that window the hint
appends a note saying so, and inside it says nothing, because a caveat printed
every time is one nobody reads.

`diagnosis.media_relay` is context rather than a finding, and is likewise
**omitted** on any capture with no TURN relay in it. It answers "where did this
call's audio actually go", which for a relayed call previously had no answer
anywhere: `client`, `server`, `relayed_address` (the address the far end really
sends to), `channel`, `peer`, and `lapsed`. `lapsed: true` is the capture-level
`turn_allocation_lapsed` finding narrowed to **this** call's media, and is the
only shape that also adds a hint — a relay doing its job needs no sentence in a
list an operator reads for problems.

A `relay_ignored` or `ignored` finding raises `private_media_address` on its own,
with no observed stream needed: a public mapped or relayed address is proof the
client's traffic reaches the internet. `unanswered` does so only when the server
it asked is itself public — silence from a STUN server on the same LAN proves
nothing, and flagging it would fire on every LAN-only capture.

### When ICMP and retransmissions both fire

`retransmissions` and `icmp_unreachable` frequently appear on the same dialog,
and they are not two views of one thing. `retransmissions` measures how hard the
sender tried before giving up. `icmp_unreachable` states why nothing came back.
The ICMP fact therefore **annotates** the retransmission finding rather than
replacing it: sipnab sets `retransmissions.icmp_cause` to the ICMP description,
the hint stops offering "a one-way path or an unreachable peer" as a guess, and the
`count` and `span_sec` survive. Suppressing the finding would have deleted a
measurement to remove a sentence.

With no ICMP in the capture, `icmp_cause` is absent and the retransmission hint
reads exactly as it always did -- the inference is the honest answer when
nothing better is available.

The same document is what you get from:

- the REST `GET /v1/dialogs/{call_id}` and
  `GET /v1/dialogs/{call_id}/report` endpoints,
- MCP tool responses (`get_dialog_report` with `format: "json"` — see the
  [MCP server](mcp.md) reference), and
- `SIPNAB_JSON` in [`--on-dialog-exec`](cli-reference.md#event-execution)
  hooks. Note the dialog hook fills `streams: []` and a default `diagnosis`
  — it fires on a dialog event, when media analysis for that call may not be
  complete, so the stream and diagnosis fields are placeholders there rather
  than populated data.

`--on-quality-exec` is separate: it passes the stream object on its own,
under its own variable name — `SIPNAB_STREAM_JSON`, **not** `SIPNAB_JSON`.

## STUN / TURN JSON (`--json-stun`)

NDJSON, emitted after capture: one object per STUN or TURN transaction, then one
per TURN allocation. Every line carries a `record` field naming its kind, so a
consumer never has to infer the shape from which keys happen to be present.

```bash
sipnab -N -I capture.pcap --json-stun --no-cli-print \
  | jq -c 'select(.record == "transaction" and .responded_at == null)
           | {client, server, method_name, request_count}'
```

A `transaction` carries the hex `transaction_id`, `client` and `server` sockets,
`method` and `method_name`, `first_request` / `last_request` / `responded_at`
timestamps, `request_count`, `rtt_ms`, and whatever the exchange produced:
`mapped_address`, `relayed_address`, `peer_address`, `lifetime_secs`,
`channel_number`, `error_code`, `auth_challenge`, `software`, `ice_role`,
`use_candidate` and `fingerprint_valid`.

`responded_at: null` is the finding: nothing answered. `request_count` above one
is a retransmission, which is itself proof the earlier attempts drew silence.
`auth_challenge: true` says the opposite — the server was reachable and asked
for credentials, so nothing in the network path is at fault.
`fingerprint_valid` is three-valued on purpose: `true` verified, `false` present
and WRONG, `null` absent — sipnab did not check, and reporting that as `false`
would accuse a message nobody examined.

A `turn_allocation` carries `client`, `server`, `relayed_address`,
`lifetime_secs`, `allocated_at`, `refreshed_at`, `refreshes`, `last_activity`,
`released`, `channels`, `unattributed_frames`, and the derived `lapsed`:

```bash
sipnab -N -I relay.pcap --json-stun --no-cli-print | jq 'select(.lapsed == true)'
```

`lapsed: true` means traffic was still crossing the relay after the lifetime the
server last granted had run out, with no Refresh seen in between. A TURN server
tears an allocation down the moment its lifetime lapses and the media stops with
it, mid-call, with **no SIP message anywhere to explain it** — the signaling
shows a healthy call that went quiet. A deliberate release (a Refresh with
`LIFETIME` 0) sets `released` and is never `lapsed`: the client asked for the
teardown.

`channels` is what ties the relay to the media. Each entry carries the
`channel` number, the `peer` the ChannelBind named (absent when no bind appears
in the capture — the frames still attribute, and the far side is simply not in
this file), `bound`, `frames`, `bytes`, `first_seen` / `last_seen`, and the
`ssrcs` observed inside the frames. Those SSRCs are the join to the stream
list: sipnab unwraps ChannelData and the RTP inside reaches the stream store as
an ordinary stream — but that stream carries **phone-to-relay** addresses, so
without this nothing said the relay had carried it at all, and a lapsed
allocation could say it lapsed while naming not one packet that died with it.

```bash
sipnab -N -I relay.pcap --json-stun --no-cli-print \
  | jq -r 'select(.lapsed == true) | .channels[].ssrcs[]'
```

`ssrcs` counts media only: RTCP relayed on the same channel raises `frames` and
`bytes` and contributes no SSRC, because its bytes 8..12 are not a stream in the
sense the stream list means. `unattributed_frames` counts relayed frames whose
channel fell outside the per-allocation cap. Non-zero means `channels` holds a
sample of what crossed the allocation, and every text surface says so when it
does. `ssrcs_dropped` is the same statement one level down.

An `ice` record appears once, and only on a capture holding ICE connectivity
checks — Binding Requests carrying the `PRIORITY` and role attributes
[RFC 8445 §7.2.1](https://www.rfc-editor.org/rfc/rfc8445#section-7.2.1) requires,
which is what tells them from a plain server-reflexive probe to a STUN server:

| Field | Meaning |
|---|---|
| `checks` / `checks_answered` | Connectivity checks seen, and how many drew an answer of either kind. `checks_answered: 0` with `checks` above zero means ICE never completed and the call has no media path — the individual transactions are already in the `transaction` records above, which is why this is a count and not a second finding. |
| `nominated` | Candidate pairs a `USE-CANDIDATE` check nominated **and** the peer confirmed. Each carries `local`, `remote`, `role`, `priority`, `nominated_at` and `rtt_ms`. This is the ICE analogue of `mapped_address`: it names the path the media actually took. |
| `role_conflicts` | Pairs where both agents claimed one role, or where one answered `487 Role Conflict`. Each carries `a`, `b`, the `role` both claimed, `role_conflict_responses`, and `resolved`. |
| `nominated_total` / `role_conflicts_total` | Exact counts, which stay right past the retention cap that bounds the two lists above. |

`resolved: true` means the agents nominated a pair between them anyway. ICE
fixed the conflict itself, at the cost of one round trip of repeated checks.
`resolved: false` means they never nominated anything between them, which makes
the conflict a candidate cause of media that never started.

## Capture analysis (`--json-analyze`)

One JSON object for the whole run, not a line per finding: `frames_read`,
`dialogs_examined` and `streams_examined` are properties of the run rather than
of any finding, and a clean capture must still serialize to something that
states them.

```bash
sipnab -N -I capture.pcap --json-analyze --no-cli-print \
  | jq '.findings[] | select(.severity == "critical") | {kind, occurrences}'
```

`findings` ranks worst first. Each carries a stable `kind`, a `severity`, an
exact `occurrences` count, a `summary`, and an `evidence` array pointing back at
the capture with Call-IDs, endpoints, timestamps and counts.

`complete` is the field to read first. It is `false` when the run did not decode
everything it received — undecodable frames, SIP a port gate discarded, records
a retention cap dropped — and then every count below it is a **floor**. The
analysis refuses a clean verdict over a capture it could not fully read:

```bash
sipnab -N -I capture.pcap --json-analyze --no-cli-print | jq '.complete'
```

`--analyze` derives nothing new. `--analyze` aggregates the per-dialog diagnosis
sipnab already computes and the capture-level evidence it already holds. It
ranks and counts them, and adds no judgement of its own.

## pcap / pcapng

`-O <file>` writes captured packets, and `--pcapng` selects PCAP-NG. With TLS
decryption, `--pcap-export-mode` controls whether decryption secrets
(DSBs) travel with the file for Wireshark. Rotation: `--split filesize:N` /
`--split duration:N`, or SIGUSR1 on demand.

pcapng timestamps are nanosecond-resolution, declared via `if_tsresol=9`
in the Interface Description Block. Files written by sipnab <= 0.5.0
stored nanosecond ticks but omitted that declaration, so other readers
inflated every time value ×1000 (`capinfos` reporting year 58484).
[`scripts/repair_pcapng_tsresol.py`](../scripts/repair_pcapng_tsresol.py)
repairs such old captures in place without touching packet data.

## See also

- [cli-reference.md](cli-reference.md#output) — every output flag
- [examples.md](examples.md#feed-ndjson-into-jq-and-other-tools) — NDJSON-to-jq pipeline recipes
