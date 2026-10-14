+++
title = "Trace where sipnab learned a media endpoint, with three MCP tools"
date = 2026-09-01
updated = 2026-10-11
description = "Three MCP tools report how sipnab learned the address of a call's audio, whether anything authenticated the path that delivered it, and why an audio stream has no call attached."

[extra]
kind = "feature"
+++

## In short

sipnab may report that a call's audio went to a given address. That address
can come from three places:

- the phones' own call setup messages;
- a media relay that sipnab asked directly;
- a relay message sipnab picked up from the network. sipnab cannot check who
  sent it.

Three tools on sipnab's MCP server (the interface an AI agent uses) report:

- which of these applies to each address,
- how much trust the path that delivered it deserves,
- why an audio stream in the capture has no call attached to it.

## Who this is for

- Engineers who run sipnab beside an rtpengine media relay.
  - They need to know how much weight to give an address before quoting it in
    an incident review.
- Anyone writing an agent that calls these tools.

## What it does

A media relay such as rtpengine carries the audio (RTP) of a call between the
two parties. sipnab can learn which relay ports belong to which call in two
ways:

- by reading the relay's control messages (the `ng` protocol);
- by asking the relay itself with `--rtpengine-control`.

The three tools below report how each piece of that knowledge arrived.

### `explain_attribution`: where each endpoint of one call came from

Give it a Call-ID (the identifier SIP gives a call). It returns one row per
media endpoint with these fields:

- `asserted_by`:
  - `signaled` when the address came from the parties' own SDP. SDP is the
    part of a SIP message that describes the audio.
  - `media-relay` when a relay named it.
- `input_origin`:
  - which capture source carried it (`wire`, `hep` or `uprobe`);
  - nothing when sipnab asked the relay directly.
- `delivery_trust`: how much trust the delivery path deserves, as one of the
  values below.
- `delivery_note`: the same verdict as one sentence.

The response also carries `unauthenticated_endpoints`. That is the number of
rows whose `delivery_trust` is `port-gated-only`.

| `delivery_trust` | Meaning |
|---|---|
| `asked` | sipnab asked the relay over its control port, so no third party could have answered. |
| `hmac-verified` | Delivered to sipnab's HEP listener, authenticated with a per-message HMAC token. |
| `plain-secret` | Delivered to sipnab's HEP listener with a shared secret sent as-is; anyone who captures one packet can reuse the secret. |
| `port-gated-only` | Accepted because it arrived on the expected port, and for no other reason. Nothing authenticated the sender. |
| `not-relay-asserted` | The parties' own claim in SDP, not a relay's. |

The table runs from the most to the least trustworthy relay path. The
parties' own claim comes last.

A relay may deliver an endpoint over a capture path. Then `delivery_trust`
comes from how the run's HEP listener (`--hep-listen`) checks its senders:

- `hmac-verified` when the listener has a secret (`--hep-auth-file` or
  `--hep-auth`) and `--hep-auth-mode hmac`;
- `plain-secret` when it has a secret and the default `plain` mode;
- `port-gated-only` when sipnab checks no secret.
  - This includes every run that does not listen for HEP.

The listener drops a packet that fails its check.

- So every stored assertion passed the configured check.
- The `server_capabilities` tool reports the same value for the whole run in
  `runtime.hep_delivery_trust`.

### `decode_ng`: one relay control message, and how it arrived

Give it a pointer to one frame of a capture (`<file>#<ordinal>`, counting from
0). It decodes the relay control message in that frame and reports:

- `delivery`:
  - `hep` for a message wrapped in HEP. HEP is the Homer Encapsulation
    Protocol rtpengine uses to mirror its control traffic.
  - `sniffed-udp` for a bare control message read off the network.
- `delivery_trust` and `delivery_note`, on the same scale as above.
- `on_believed_mirror_port`: for a HEP-wrapped message, whether it arrived on
  UDP port 9060.
  - sipnab reads a relay mirror it picks up from the network only on that
    port.
  - The port is the only check applied to it.

### `reconcile_orphans`: why an audio stream has no call

An orphan is an audio stream that no call in the capture claims. For each
one, this tool gives a `reason`:

| `reason` | Meaning |
|---|---|
| `relay-asserted-but-no-dialog` | A relay named this endpoint and no captured call claims it: the call setup messages are missing, not the audio. |
| `signaled-but-no-dialog` | SDP named this endpoint and no call holds it. |
| `never-named` | Nothing in the capture named this endpoint. |

The response carries `relay_was_consulted`.

- A `never-named` stream with `relay_was_consulted: false` means sipnab did
  not ask a relay about it.
- It does not mean that a relay answered and did not know the stream.

## How to turn it on

The tools are part of sipnab's MCP server, in builds with the `mcp` feature.
Start the server on a capture. Call them from an MCP client:

```bash
sipnab --mcp -N --quiet -I tests/fixtures/rtpengine-ng-hep.pcap
```

You can let sipnab ask a relay directly. That is the only way to reach
`asked`.

- Add `--rtpengine-control <ADDR>` on a live capture.
- sipnab does not ask while reading a file.
- The [rtpengine guide](@/docs/rtpengine.md#name-a-call-that-was-already-up-when-you-started)
  covers that setup.

## Example run

The examples send two things to sipnab over standard input:

- an MCP client's opening handshake,
- one tool call.

They use `jq` to print the fields discussed above. Run them from the root of a
sipnab checkout.

This capture holds:

- rtpengine control messages mirrored over HEP to UDP port 9060,
- then the call's audio,
- no SIP messages.

Ask where the endpoints of the call `km-670bd208@sipnab` came from:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"explain_attribution","arguments":{"call_id":"km-670bd208@sipnab"}}}' | sipnab --mcp -N --quiet -I tests/fixtures/rtpengine-ng-hep.pcap 2>/dev/null | jq -r 'select(.id==2) | .result.structuredContent | "unauthenticated_endpoints: \(.unauthenticated_endpoints)", (.endpoints | sort_by(.address, .port) | .[] | "\(.address):\(.port) \(.asserted_by) \(.input_origin) \(.delivery_trust)")'
```

```text
unauthenticated_endpoints: 4
192.0.2.40:38156 media-relay wire port-gated-only
192.0.2.40:38664 media-relay wire port-gated-only
192.0.2.60:40001 media-relay wire port-gated-only
192.0.2.60:40002 media-relay wire port-gated-only
```

- A relay named all four endpoints.
- sipnab read them from the network (`wire`).
- So the only check was the port they arrived on.

Decode the first frame of the same capture. `decode_ng` opens the file again.
So `--mcp-file-root` must name the directory that holds it:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"decode_ng","arguments":{"frame_ref":"rtpengine-ng-hep.pcap#0"}}}' | sipnab --mcp -N --quiet -I tests/fixtures/rtpengine-ng-hep.pcap --mcp-file-root tests/fixtures 2>/dev/null | jq -c 'select(.id==2) | .result.structuredContent | {command, call_id, delivery, delivery_trust, on_believed_mirror_port}'
```

```text
{"command":"offer","call_id":"km-670bd208@sipnab","delivery":"hep","delivery_trust":"port-gated-only","on_believed_mirror_port":true}
```

This capture holds the same audio with no control messages and no SIP. Ask
why each stream has no call:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reconcile_orphans","arguments":{}}}' | sipnab --mcp -N --quiet -I tests/fixtures/rtpengine-media-only.pcap 2>/dev/null | jq -c 'select(.id==2) | .result.structuredContent | {total_orphans, relay_was_consulted, reasons: (.orphans | map(.reason) | unique)}'
```

```text
{"total_orphans":4,"relay_was_consulted":false,"reasons":["never-named"]}
```

## Limits

- sipnab decides `delivery_trust` for a relay-delivered endpoint once per run.
  - It decides from the HEP listener's settings, not per packet.
  - A run may both read an interface (`-d`) and listen for HEP with a secret.
    Then an assertion sniffed from the interface reports the listener's value.
- According to its `--help` text, only another sipnab understands
  `--hep-auth-mode hmac`.
  - A stock Homer or Kamailio peer uses the `plain` form.
- `--hep-allow` restricts the senders the HEP listener accepts.
  - It does not apply to a relay mirror sipnab reads from the network.
  - No sipnab socket receives that traffic.
- sipnab asks a relay only with `--rtpengine-control` on a live source.
  - It sends only the `list` and `query` commands.
  - It stops after 66 control transactions per run.
  - On a run reading a file it does not ask.

## Terms used here

- **SIP**: the protocol phones and servers use to set up and end calls.
- **Call-ID**: the identifier SIP gives each call.
- **SDP**: the part of a SIP message that says where and how to send audio.
- **RTP**: the protocol that carries call audio.
- **Media endpoint**: an IP address and port that sends or receives a call's
  audio.
- **Media relay**: a server, such as rtpengine, that carries audio between
  the parties.
- **ng protocol**: rtpengine's control protocol, used to open, query and close
  relay ports.
- **HEP**: Homer Encapsulation Protocol, a format for copying SIP and control
  messages to a collector such as Homer or sipnab.
- **HMAC**: a keyed checksum that proves a message came from a holder of the
  shared secret and was not altered.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **Orphan**: an audio stream that no call in the capture claims.
- **Capture**: a recording of network packets, here a pcap file.

## Related guides

- [How much a `media-relay` assertion is worth](@/docs/rtpengine.md#how-much-a-media-relay-assertion-is-worth)
  and [Telling a relay's answer from a party's](@/docs/rtpengine.md#telling-a-relay-s-answer-from-a-party-s)
  in the rtpengine guide.
- [Name a call that was already up when you started](@/docs/rtpengine.md#name-a-call-that-was-already-up-when-you-started)
  and [Read a run that attributed nothing](@/docs/rtpengine.md#read-a-run-that-attributed-nothing).
- [Let an agent ask the relay](@/docs/rtpengine.md#let-an-agent-ask-the-relay).
- The tool reference entries for [`explain_attribution`](@/docs/mcp-tools-media.md#explain-attribution),
  [`decode_ng`](@/docs/mcp-tools-relay.md#decode-ng),
  [`reconcile_orphans`](@/docs/mcp-tools-media.md#reconcile-orphans) and
  [`server_capabilities`](@/docs/mcp-tools-server.md#server-capabilities).
