+++
title = "Observer vCon export and validation"
date = 2026-09-01
updated = 2026-10-11
description = "What a vCon that sipnab writes says and does not say about a call, how to export one from a capture, and how to check it against the vCon schema before you send it to a store."

[extra]
kind = "feature"
+++

## In short

A vCon is a standard file format for a recorded conversation. It records:

- who took part,
- what passed between them,
- what a machine concluded about it.

sipnab can write one vCon per call it saw in a capture. Then a conversation
store can take the call without decoding packets itself.

sipnab only watched copies of the packets. The file it writes says so:

- It names sipnab as an observer.
- It vouches for no one's identity.
- It signs nothing.
- It states what the capture did not hold.

## Who this is for

- Anyone who sends sipnab's output to a vCon store or another conversation
  system.
- Anyone who receives a vCon that sipnab produced and needs to know what it can
  and cannot tell them.

## What it does

sipnab builds one container from one dialog. A dialog is one call, from its
first SIP message to its last.

- The container follows the IETF vCon working group's
  draft-ietf-vcon-vcon-core-04.
- It has four arrays: `parties`, `dialog`, `analysis` and `attachments`.

What the container says:

- **sipnab is a party with the role `observer`.**
  - A recorder is a system that took part in the call and received its audio.
  - sipnab reads a mirror port or a tap (a copy of the traffic).
  - So it describes itself as a passive observer.
- **sipnab vouches for no identity.**
  - `name` and `sip_display_name` carry the display name from the `From` or
    `To` header.
  - Every party has `validation: "none"`. That means nobody checked that name.
  - Treat both fields as personal data. Redact both if you redact either.
- **`tel` only for a full telephone number.**
  - sipnab adds a `tel` identifier only when the SIP user part is `+` followed
    by digits.
  - A short extension such as `1001` gets none.
- **sipnab signs and encrypts nothing.** The container has no JWS signature
  and no JWE encryption.
- **Audio is inline or absent.**
  - The run may keep the audio payload (`--retain-audio`). Then the dialog
    object carries it in its body with a `sha512-` content hash.
  - When it did not, the container carries no audio and says why.
  - sipnab never writes a `url` pointing at a file elsewhere.
  - It does not embed audio larger than `--vcon-max-inline-media` (default
    5 MiB). The completeness value then reads `media: "refused-over-budget"`.
    Its note names both sizes.
- **The type of a dialog object follows what it holds.**
  - It is `recording` when it holds audio.
  - It has that type also when it holds nothing and sipnab saw no failure.
  - It is `incomplete` only when sipnab saw a final failure response for the
    call.
- **sipnab writes what the capture missed twice.**
  - vCon has no field for "this record is incomplete".
  - So sipnab writes a `capture_completeness` value into `analysis[0].body`.
  - It writes the same value into an attachment with the purpose
    `sipnab-capture-completeness`.
  - Both carry counters such as `frames_read`, `undecodable_frames`,
    `messages_evicted` and `sip_discarded_by_port_gate`.
  - Both carry a sentence explaining them.

## How to turn it on

The export is part of the `vcon` build feature.

- A default build does not include it.
- The `full` feature does.
- `sipnab --version` lists the features of the build you have.

The same container is available four ways:

- `--export-vcon CALL-ID` with `--vcon-out FILE` at the command line
- `--export-vcon-when EXPR` with `--export-vcon-dir DIR`. This writes one file
  per matching call.
- the `export_vcon` MCP tool. MCP is the Model Context Protocol, the interface
  an AI agent uses to call sipnab's tools.
- `GET /v1/dialogs/{call_id}/vcon` on the REST API

## Example run

These commands run from the root of a sipnab checkout.

- `--node-name lab` sets the node name that sipnab writes into the container.
- Without it, sipnab uses the host name.

```bash
sipnab -N -q --node-name lab -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon '1-1966@10.0.2.20' --vcon-out out.json --no-cli-print
```

The command prints nothing and exits with status 0.

The parties:

```bash
jq -c '.parties[]' out.json
```

```json
{"sip":"sip:sipp@10.0.2.20:5060","validation":"none","name":"PCMU/8000","sip_display_name":"PCMU/8000","sip_contact":"sip:sipp@10.0.2.20:5060"}
{"sip":"sip:test@10.0.2.15:5060","validation":"none","name":"test","sip_display_name":"test","sip_user_agent":"FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit"}
{"validation":"none","role":"observer","sip_user_agent":"sipnab/0.5.211 (observer; node lab)"}
```

The caller's `name` is `PCMU/8000`. The test tool that made this capture put
the codec name in its display name. The name is whatever the header said.

The dialog object, from a run without `--retain-audio`:

```bash
jq -c '.dialog' out.json
```

```json
[{"type":"recording","sip_call_id":"1-1966@10.0.2.20","sip_from_tag":"1","sip_to_tag":"QvN92t713vSZK","start":"2016-11-26T14:52:59.666393+00:00"}]
```

It holds no audio. The completeness value says why:

```bash
jq '.analysis[0].body | fromjson | .capture_completeness' out.json
```

```json
{
  "blind_spots": [],
  "dialogs_refused": 0,
  "dialogs_rotated": 0,
  "dialogs_suppressed_by_deny": 0,
  "frames_read": 852,
  "gate_closed_during_run": false,
  "headers_dropped_oversize": 0,
  "media": "none-decodable",
  "media_note": "No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1 decodable stream, but kept none of their payload, so there is nothing to decode. This is a statement about what this run kept, not a finding that the call was silent. Most often audio payload retention was off — start the server with --retain-audio to hold payload for export. With retention already on, the other causes are a --snaplen that truncated the payload away before sipnab saw it, or packets that carried no payload at all.",
  "messages_evicted": 0,
  "node": "lab",
  "note": "Produced by sipnab 0.5.211 on node lab. sipnab OBSERVED this dialog and took no part in it: the parties below are what the From and To headers said, not identities anyone established, and nothing here is signed. No media is in this container because this run decoded none for the dialog; the capture_completeness media_note says what was measured. That is a statement about what this run kept, not a finding that the call was silent. sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
  "sip_discarded_by_port_gate": 0,
  "sip_discarded_by_websocket_gate": 0,
  "sipnab_version": "0.5.211",
  "undecodable_frames": 0
}
```

`gate_closed_during_run` and `dialogs_suppressed_by_deny` are always present.

- They read `false` and `0` when sipnab withheld nothing.
- So a reader can tell "nothing withheld" from "field missing".

The attachment holds the same value:

```bash
jq '(.analysis[0].body | fromjson | .capture_completeness) == (.attachments[] | select(.purpose == "sipnab-capture-completeness") | .body | fromjson)' out.json
```

```text
true
```

With `--retain-audio`, the same call carries its audio inline:

```bash
sipnab -N -q --node-name lab -I tests/pcap-samples/sip-rtp-g711.pcap --retain-audio --export-vcon '1-1966@10.0.2.20' --vcon-out audio.json --no-cli-print
```

```bash
jq -c '.dialog[] | del(.body)' audio.json
```

```json
{"type":"recording","sip_call_id":"1-1966@10.0.2.20","sip_from_tag":"1","sip_to_tag":"QvN92t713vSZK","start":"2016-11-26T14:52:59.689060+00:00","duration":8.5,"parties":[1],"mediatype":"audio/x-wav","encoding":"base64url","content_hash":"sha512-lmhlQq1iLhg2VqL42ZyvwF-88wIZeO24m3o1Xegdycd82_3IGm_K4Qe_zhSdjXkPzoWxLZfAh698aG3gilBTJQ"}
```

The `jq` filter removes `body`, which holds the encoded audio.

## Check a container before you send it

The `validate_vcon` MCP tool checks a container against the core-04 schema.

- Its `verdict` is `valid` or `invalid`.
- `errors` names every problem.
- It takes one of two arguments:
  - `call_id`, to export a dialog and check the result,
  - `container`, to check a document you already hold.

The command below sends `out.json` to the tool over standard input. So you can
reproduce the check without an agent:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "$(jq -c '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"validate_vcon",arguments:{container:.}}}' out.json)" \
| sipnab -N --mcp --node-name lab -I tests/pcap-samples/sip-rtp-g711.pcap 2>/dev/null \
| jq -c 'select(.id==2) | .result.structuredContent | {verdict, errors}'
```

```json
{"verdict":"valid","errors":[]}
```

The same container with the dialog object's `type` removed:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "$(jq -c 'del(.dialog[0].type) | {jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"validate_vcon",arguments:{container:.}}}' out.json)" \
| sipnab -N --mcp --node-name lab -I tests/pcap-samples/sip-rtp-g711.pcap 2>/dev/null \
| jq -c 'select(.id==2) | .result.structuredContent | {verdict, errors}'
```

```json
{"verdict":"invalid","errors":[{"detail":"missing required properties: type","instance_path":"/dialog/0","keyword":"required"}]}
```

The full answer also carries these fields:

- `schema_version`
- `schema_path` (`tests/schemas/vcon.schema.json`, the schema file in the
  sipnab repository)
- `schema_id`
- `source_exhausted`
- `source_stopped_early`

A container that fails the schema is an answer, not an error. The tool returns
an error only when the request itself is wrong:

- neither argument,
- both arguments,
- a `call_id` that is not in the capture,
- a `container` that is not a JSON object.

## Limits

- An absent field describes the capture, not the call.
  - A dialog object with no audio means this export carries no audio.
  - It does not mean the call was silent.
- The container is not signed. So it is exactly as trustworthy as whoever
  handed it to you.
- Two taps that each saw one leg of a call write two containers. sipnab does not
  merge them.

## Changes since this note was first published

The first version of this note described two things that changed:

- a third verdict, `valid-except-documented-deviation`,
- an empty dialog object (`{}`) for the consultation call of an attended
  transfer.

Both followed the earlier draft core-03. Under core-04 every dialog object
needs a `type`:

- sipnab now writes `{"type": "recording"}` for that placeholder.
- `validate_vcon` reports an empty dialog object as `invalid`.

## Terms used here

- **vCon**: a file format for one conversation and the data about it. An IETF
  working group is standardizing it.
- **IETF**: the Internet Engineering Task Force, which publishes internet
  standards.
- **Capture**: a file of recorded network packets.
- **SIP**: Session Initiation Protocol, the messages that set up and end calls.
- **Dialog**: one call, from its first SIP message to its last.
- **Mirror port** and **tap**: switch features or devices that copy traffic to
  another machine.
- **Display name**: the free-text name a caller's phone puts in the `From`
  header.
- **JWS** and **JWE**: the JSON standards for signing and encrypting a document.
- **Schema**: a machine-readable description of which fields a document must
  and may have.
- **RTP**: the packets that carry the audio of a call.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **REST**: sipnab's HTTP interface.
- **jq**: a command-line program that selects fields from JSON.

## Related guides

- [What a vCon is, and what sipnab is to it](@/docs/vcon.md#what-a-vcon-is-and-what-sipnab-is-to-it)
- [Produce one](@/docs/vcon.md#produce-one)
- [The container cannot say "this is an incomplete record", so sipnab says it twice](@/docs/vcon.md#the-container-cannot-say-this-is-an-incomplete-record-so-sipnab-says-it-twice)
- [Someone handed you a sipnab vCon: what may you conclude?](@/docs/vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
- [What sipnab refuses to put in a container](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container)
- [One thing sipnab does supply, narrowly: `tel`](@/docs/vcon.md#one-thing-sipnab-does-supply-narrowly-tel)
- [The spool contract, for a bridge that consumes it](@/docs/vcon.md#the-spool-contract-for-a-bridge-that-consumes-it)
