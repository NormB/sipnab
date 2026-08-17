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
