# MCP tool reference: media bundle

The `media` bundle answers where a call's media endpoints came from, why a
stream has no dialog, and what lies under a quality score, and it exports a
call's audio.

Load only these tools with `--mcp-tools media`, or combine bundles as
[Choosing which tools load](mcp-tools.md#choosing-which-tools-load) describes.
Every tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

| Tool | Parameters | Returns |
|---|---|---|
| [`reconcile_orphans`](#reconcile_orphans) | `limit?` | Why each RTP stream with no dialog lacks one: a relay named the endpoint but no signaling arrived, SDP named it but no dialog claims it, or nothing named it at all |
| [`media_diagnostics`](#media_diagnostics) | `call_id` | The facts under the MOS: QoS marking, jitter grounding, delay provenance, silence, and what the far end reported |
| [`explain_attribution`](#explain_attribution) | `call_id` | Where each of a call's media endpoints came from and how much that path is worth — asked directly, HMAC-verified, plain secret, port-gated only, or the parties' own SDP |
| [`export_audio`](#export_audio) | `call_id`, `filename` | Writes a call's RTP audio to a WAV in `--mcp-file-root`; needs the server started with `--retain-audio` |


## Survey — what is in this capture

Start here when you have a capture and no particular suspect. These answer "what is in it", "how much", and "is the server even seeing traffic".

### `reconcile_orphans`

An orphaned stream is media with no dialog. `rtp_stats` names which streams
have none. This tool says why each one has none, which is the part an incident
needs.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default), and higher clamps to it. `0` returns one row. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339>\|0xSSRC@src>dst`, the shape the [`rtp_stats`](mcp-tools-core.md#rtp_stats) sweep uses). A malformed timestamp half fails with `invalid_params`. | Starts at the earliest orphan. |
| `max_response_bytes` | u64? | Bytes for the whole response. Ceiling is `--mcp-max-response-bytes` (1048576 unless the operator changed it). Higher clamps to it, `0` means the ceiling. Past it the page ends early at a whole row with `truncated_by: "bytes"`. | The ceiling. |

**Returns** `orphans`, `returned`, `total_orphans` (every orphan in the store,
whatever `limit` and `cursor` say), `truncated`, `truncated_by` (present only
when a bound cut the page), `next_cursor` (`null` on the final page),
`relay_was_consulted`, `relay_control`, `capture_identity` and
`schema_version`. Rows run oldest first, by first packet, ties broken by
`0xSSRC@src>dst`. Each `orphans` row carries `ssrc`, `src`, `dst`,
`named_endpoint`, `asserted_by`, `reason` and `note`.

`relay_was_consulted` reads every orphan in the store, not only the page, so a
relay assertion on a later page still counts.

`relay_control` has one row per relay control socket this capture read
(`--rtpproxy-control`), and is empty when the capture read none. It counts retried
commands, because a control channel that loses answers shows on the SIP side
only as a proxy that is sometimes slow:

| Field | Meaning |
|---|---|
| `relay` | The control socket, `address:port` |
| `implementation` | `rtpproxy` |
| `commands` | Command datagrams seen, retries included |
| `retried_commands` | Commands that repeated a cookie already seen. rtpproxy answers a repeated cookie from its reply cache, so the same cookie twice is the proxy sending the command again because it did not hear an answer in time |
| `retried_after_answer` | Of those, retries sent after the relay's answer was already on the wire: the answer got lost, or arrived late, on its way back to the proxy. The rest went out before the capture showed any answer |

sipnab remembers the 4,096 most recent cookies per socket, so a retry of an
older one does not count. A headless run prints the same counts as a warning
at the end when the proxy retried any command.

Three verdicts, and the difference between them is the point:

| verdict | what it means |
|---|---|
| `relay-asserted-but-no-dialog` | a relay named this endpoint and no captured dialog claims it — the **signaling** is missing, not the media |
| `signaled-but-no-dialog` | SDP named it and no dialog holds it — either the capture missed the dialog, or its SDP arrived before capture started |
| `never-named` | nothing in this capture named this endpoint at all |

`relay_was_consulted` rides alongside the verdict and matters more than it looks. A
`never-named` verdict with `relay_was_consulted: false` means **nobody asked** —
an absence of evidence, not evidence of absence. It is deliberately not
reported using the `Unattributed` vocabulary, which answers "sipnab asked the
relay and it said X": this server holds no live reconciler, and claiming an answer
nobody received is the failure that vocabulary exists to prevent.

The example runs against [`tests/pcap-samples/codec-negotiation.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/codec-negotiation.pcap),
which carries four streams and no dialogs at all:

```jsonc
// reconcile_orphans { "limit": 2 }
{
  "schema_version": 1,
  "orphans": [
    {
      "ssrc": 238226163,
      "src": "127.0.0.1:5094",
      "dst": "127.0.0.1:5084",
      "named_endpoint": null,
      "asserted_by": null,
      "reason": "never-named",
      "note": "nothing in this capture named this endpoint. A relay could answer it and none was asked: that is an absence of evidence, not evidence of absence"
    },
    {
      "ssrc": 238226163,
      "src": "127.0.0.1:5084",
      "dst": "127.0.0.1:5094",
      "named_endpoint": null,
      "asserted_by": null,
      "reason": "never-named",
      "note": "nothing in this capture named this endpoint. A relay could answer it and none was asked: that is an absence of evidence, not evidence of absence"
    }
  ],
  "returned": 2,
  "total_orphans": 4,
  "truncated": true,
  "truncated_by": "rows",
  "next_cursor": "2026-07-08T18:35:27.408614Z|0x0e330af3@127.0.0.1:5084>127.0.0.1:5094",
  "relay_was_consulted": false,
  "relay_control": [],
  "capture_identity": {
    "node": "capture-01",
    "instance": "ece9518d2bf67680750b4-2",
    "dialog_generation": 1,
    "stream_generation": 4
  }
}
```


## Diagnose one call

You have a call-id. These explain what happened to that one call -- its signaling, its media, and the specific negotiations that tend to break.

### `media_diagnostics`

"The MOS is 3.6 — why?" `rtp_stats` gives the score. This gives the facts
underneath it, and each one says what kind of number it is.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID a dialog carries, or one a media relay named for its streams. | Required — the call fails. |

**Read `applicable` first.** It is `false` when no RTP stream belongs to the
dialog, and the response then holds only `call_id`, `reason`,
`capture_identity` and `schema_version`. An empty `streams` array would read as
"sipnab checked the media and it was fine", which is a different claim from "no
media reached the capture point".

`dialog_seen` says whether the capture holds the call's SIP dialog. On a
media-relay host it is `false` and `dialog_absent` says why, as described
under [`rtp_stats`](mcp-tools-core.md#rtp_stats).

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
because payload type 0 has a clock rate [RFC 3551](https://www.rfc-editor.org/rfc/rfc3551.html)
Table 4 fixes. And the delay behind the MOS is a default, not anything this
capture showed, so a MOS built on it is only as good as that assumption.

`clock_basis` has three values: `rfc3551` (a static payload type), `rtpmap` (a
dynamic one an SDP named), and `assumed` (neither, and the reason `grounded` is
`false`).


## Evidence and provenance

Every finding a tool reports points back at captured bytes. These retrieve those bytes, prove which frame they came from, and package them so someone else can check the work.

### `explain_attribution`

An agent that reports "media anchored at `<addr>`" cannot otherwise say whether
that came from SDP the two parties exchanged, from a relay sipnab asked, or
from a mirrored datagram anybody could have sent. Those carry very different
weight in an incident review and every other surface renders them identically.

`delivery_trust`, strongest first:

| value | meaning |
|---|---|
| `asked` | sipnab asked the relay over its control socket; no third party could answer |
| `hmac-verified` | delivered over HEP, authenticated with a token covering the datagram |
| `plain-secret` | delivered over HEP with a shared secret; the token does not cover the datagram, so anyone who captures one can replay it |
| `port-gated-only` | accepted because it arrived on the expected port and for no other reason — **the source is not authenticated** |
| `not-relay-asserted` | the parties' own claim in SDP |

The authentication answer comes from the run's configuration rather than a
per-packet record, and that is correct rather than a shortcut: ingest rejects any datagram
that fails authentication, so everything still in the store arrived under
whatever posture the run configured. With no posture configured it
reports the **weakest** reading — a tool whose job is telling you what a claim
is worth must not round up in the absence of information.

The configured posture is the HEP listener's, so it covers only what the
listener delivered (`input_origin: hep`). A relay datagram sipnab read off a
capture interface (`input_origin: wire`) never reached the listener: it is
`port-gated-only` on every run, `--hep-auth-mode hmac` included. A run with
`-d` and `-L` holds both kinds side by side.

The endpoints are the call's streams, so the tool answers on a media-relay host
that never saw the SIP dialog. `dialog_seen` is then `false` and
`dialog_absent` says why, as described under [`rtp_stats`](mcp-tools-core.md#rtp_stats).

```jsonc
// explain_attribution { "call_id": "call-2c9d47@192.0.2.10" }
{
  "call_id": "call-2c9d47@192.0.2.10",
  "endpoints": [
    {
      "address": "192.0.2.10",
      "port": 10000,
      "asserted_by": "signaled",
      "input_origin": "wire",
      "observed_at": "2023-11-14T22:13:25+00:00",
      "delivery_trust": "not-relay-asserted",
      "delivery_note": "the parties' own claim in SDP, not a relay's statement about its allocation"
    }
  ],
  "unauthenticated_endpoints": 0,
  "dialog_seen": true,
  "schema_version": 1
}
```


## Export and handoff

Getting the result out of sipnab and into the next tool, the next team, or a bug report someone else can reproduce.

### `export_audio`

Writes one call's RTP audio to a WAV in the configured root. Fails when the
call carries no audio it can decode, rather than writing an empty file.

Requires `--retain-audio` on the server command line: call audio is
content, not signaling, so holding it in memory is an operator decision
rather than a side effect of enabling MCP. The run keeps whole calls, inside
the `[limits] max_audio_bytes` budget
([Audio retention budget](config-reference.md#audio-retention-budget)). A
file missing the start of a call says PARTIAL in its `summary` with the count
and the reason. Without the flag the tool refuses,
and its refusal reports the media it measured and names the flag — a capture
setting, not a finding that the call was silent.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID whose streams carry audio sipnab can decode. The capture need not hold the dialog: a media-relay host exports the streams the relay named. | Required — the call fails. |
| `filename` | string | A bare filename inside `--mcp-file-root`, under the same rule `export_capture` applies. sipnab writes a WAV whatever extension you give it. | Required — the call fails. |

Returns `path`, `summary`, `dialog_seen` and `schema_version`, plus
`dialog_absent` when `dialog_seen` is `false` (see [`rtp_stats`](mcp-tools-core.md#rtp_stats)):

```jsonc
// export_audio { "call_id": "1-1966@10.0.2.20", "filename": "call.wav" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/call.wav",
  "summary": "Exported 8.5s of mu-law audio (425 frames, PCMU/8000Hz) to /var/spool/sipnab-exports/call.wav",
  "dialog_seen": true
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
