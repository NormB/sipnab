+++
title = "Join the two legs of a call that crossed a B2BUA"
date = 2026-09-01
updated = 2026-10-16
description = "How to find the second Call-ID of a call that a back-to-back user agent re-originated, and how to tell an identifier match from a timing guess."

[extra]
kind = "howto"
+++

## In short

Some kinds of telephone switch split a phone call that passes through them in
two.

- The switch ends the incoming call.
- It places a new outgoing one, with a new call identifier.
- The box on each side then logs only one of the two identifiers.
- So the call looks lost between them.

sipnab can look at a recording from the switch. It can:

- name the other half of the call,
- say whether it found that half by a shared identifier or only guessed from
  timing.

## Who this is for

Operators who hold captures from an SBC, proxy or PBX. They need to follow one
call from one box to the next, either by hand or through an AI agent.

## Before you start

- A B2BUA (back-to-back user agent) is a SIP server.
  - It ends the incoming call.
  - It starts a new outgoing call, usually with a new Call-ID.
  - Many SBCs and PBXes act as one on some calls and as a plain proxy on
    others.
- The commands below talk to sipnab's MCP server over standard input.
  - MCP is the interface an AI agent uses.
  - So the commands run without an agent.
  - They need `sipnab` on your `PATH` and `jq` (a JSON command-line tool).
- The repository has one capture that holds both legs of a B2BUA call:
  `tests/pcap-samples/b2bua-asterisk.pcapng`.
  - The incoming leg has Call-ID `b2bua-caller-synth@203.0.113.1`.
  - The outgoing leg has Call-ID `b2bua-leg-synth@203.0.113.101:5060`.

## Steps

- Ask the box that re-originated the call first.
  - Only that box saw both legs.
  - So only its capture can name the Call-ID the next box knows the call by.
  - Start sipnab on its capture with a node name.
  - Call `find_correlated` with the Call-ID you already have:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_correlated","arguments":{"call_id":"b2bua-caller-synth@203.0.113.1"}}}' | sipnab --mcp -N --quiet --node-name sbc-edge-1 -I tests/pcap-samples/b2bua-asterisk.pcapng | jq 'select(.id==2) | .result.structuredContent'
   ```

   Output on sipnab 0.5.222:

   ```text
   {
     "capture_identity": {
       "dialog_generation": 64,
       "instance": "11a27d18df00183004ae34-2",
       "node": "sbc-edge-1",
       "stream_generation": 2
     },
     "heuristic_only": true,
     "legs": [
       {
         "call_id": "b2bua-leg-synth@203.0.113.101:5060",
         "identifier_match": false,
         "observed_gap_ms": 3,
         "score": 50,
         "strategy": "timing_heuristic"
       }
     ],
     "schema_version": 1,
     "source_call_id": "b2bua-caller-synth@203.0.113.1",
     "source_exhausted": true,
     "source_stopped_early": false,
     "timing_clock": {
       "available": true,
       "est_error_us": 0,
       "max_error_us": 523500,
       "synchronized": true
     },
     "total_matched": 1
   }
   ```

   `instance` and `max_error_us` differ on every run.

   The box may have acted as a proxy on this call. Then `legs` is empty and
   `total_matched` is 0. The Call-ID did not change. So ask the next box for the
   same Call-ID.

- Read `strategy` and `identifier_match` before `score`.
  - In the first step the strategy is `timing_heuristic`. `identifier_match` is
    `false`.
  - No identifier crossed the switch.
  - sipnab paired the two legs because they share an endpoint and started 3 ms
    apart (`observed_gap_ms`).
  - That is a guess.
  - `heuristic_only: true` means every returned leg is a guess. So say so in
    anything you write about the call.

   For contrast, `tests/pcap-samples/sip-rtp-g711.pcap` holds two calls that
   share an SDP origin line. That is the line in the media description that
   names the session and its creator:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_correlated","arguments":{"call_id":"1-1966@10.0.2.20"}}}' | sipnab --mcp -N --quiet --node-name sbc-edge-1 -I tests/pcap-samples/sip-rtp-g711.pcap | jq 'select(.id==2) | .result.structuredContent'
   ```

   ```text
   {
     "capture_identity": {
       "dialog_generation": 13,
       "instance": "11a4c818df00195f1a1a56-2",
       "node": "sbc-edge-1",
       "stream_generation": 2
     },
     "heuristic_only": false,
     "legs": [
       {
         "call_id": "1-1968@10.0.2.20",
         "identifier_match": true,
         "observed_gap_ms": null,
         "score": 90,
         "strategy": "sdp_origin"
       }
     ],
     "schema_version": 1,
     "source_call_id": "1-1966@10.0.2.20",
     "source_exhausted": false,
     "source_stopped_early": false,
     "timing_clock": null,
     "total_matched": 1
   }
   ```

   Here:

   - An identifier matched (`identifier_match: true`).
   - `observed_gap_ms` is `null` because sipnab used no timing.
   - `timing_clock` is `null` because no leg needed it.
   - `source_exhausted` is `false`: the call arrived before sipnab finished
     reading the file. The answer is a lower bound. More legs can match once
     sipnab has read the whole capture.

   sipnab has seven strategies.

   - Two exist by design to cross a B2BUA:
     - `session_id` (the [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989.html)
       `Session-ID` header),
     - `charging_vector_related_icid` (only when the B2BUA chose to send it).
   - `x_call_id` and `sdp_origin` cross only when the box copies the header or
     the SDP.
   - `charging_vector_icid` and `via_branch` do not cross by design.
   - `timing_heuristic` is not an identifier.
   - The full table is in the
     [`find_correlated` reference](@/docs/mcp-tools-signaling.md#find-correlated).

- Check the clock only when different hosts timestamped the two legs.
  - Inside one capture, one clock stamped every packet.
  - So a 3 ms gap between two legs in that capture is a measured interval. This
    holds even if the clock's absolute time is wrong.
  - Legs may come from captures written on two hosts. Then clock offset between
    the hosts adds to the gap. The timing match is only as good as both clocks.

   `timing_clock` describes the clock of the host answering the query.

   - sipnab reads it from the kernel at the moment of the query.
   - It does not describe the clock that stamped a capture file that sipnab
     reads.
   - `max_error_us` is the kernel's upper bound on that clock's error, in
     microseconds.
   - It changes from reading to reading on the same host.
   - The time window for a timing match is 2000 ms, unless
     `--leg-correlation-window <MS>` sets another value.
   - A `max_error_us` near that window means a timing match across hosts proves
     nothing.

- Carry the Call-ID from the first step to the next box. Ask that box for it with
  `get_dialog`.
  - The repository has no second capture of this call.
  - So this example reads the same file under the node name `pbx-1`:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_dialog","arguments":{"call_id":"b2bua-leg-synth@203.0.113.101:5060"}}}' | sipnab --mcp -N --quiet --node-name pbx-1 -I tests/pcap-samples/b2bua-asterisk.pcapng | jq -c 'select(.id==2) | .result.structuredContent.dialog | {call_id, state, final_status_code, msg_count}'
   ```

   ```text
   {"call_id":"b2bua-leg-synth@203.0.113.101:5060","state":"Completed","final_status_code":200,"msg_count":15}
   ```

- Record which box gave each answer.
  - `capture_identity.node` names the box. `--node-name` sets it.
  - Without that flag, sipnab uses the system hostname.
  - Not every answer carries `capture_identity`.
    - `find_correlated`, `capture_status` and `list_dialogs` do.
    - `get_dialog` does not.
  - Call `capture_status` once per node and keep the name.
  - `capture_identity.instance` changes whenever a different capture loads.
    The node name does not.

   An agent may reach a live box over HTTP. Then the server command takes the
   same flag:

   ```bash
   sipnab --mcp -N --mcp-transport http --mcp-bind 127.0.0.1:8731 --node-name sbc-edge-1 -d eth0
   ```

   Capturing on `eth0` needs capture privileges: root, or the capabilities
   that `--setup-caps` grants. To try the server against a file first, replace
   `-d eth0` with `-I` and a capture. This example also uses another port:

   ```bash
   sipnab --mcp -N --mcp-transport http --mcp-bind 127.0.0.1:28731 --node-name sbc-edge-1 -I tests/pcap-samples/b2bua-asterisk.pcapng
   ```

   It logs this line when it is ready, and runs until you press Ctrl-C:

   ```text
   2026-10-16T11:48:31.121350Z  INFO sipnab::mcp::transport::http: MCP HTTP server listening on 127.0.0.1:28731
   ```

   If another program holds the port, sipnab logs `MCP HTTP cannot bind` with the address
   and the operating system's reason, and exits with status 2.

## Limits

- The box may do all three of these:
  - send no `Session-ID`,
  - send no correlation header that sipnab's configuration tells it to read,
  - rewrite the SDP.

  Then only the timing guess remains. Nothing in the signaling proves the two
  legs are one call. The fix is to configure the box to insert a correlation
  header. See
  [Choose a correlation identifier](@/docs/mcp-estate.md#choose-a-correlation-identifier).
- `find_correlated` answers one hop inside one capture.
- `get_call_tree` walks every leg in one capture. It stops at a timing guess.
- Across boxes, repeat the first and fourth steps at each box.
- The REST route `GET /v1/dialogs/:call_id/correlated` returns the same legs.
  It returns no `capture_identity` and no `timing_clock`.

## Terms used here

- **SIP**: the signaling protocol that sets up and ends phone calls over IP.
- **Call-ID**: the SIP header that identifies one call between two endpoints.
- **Leg**: one SIP call between two boxes. A call through a B2BUA has two.
- **B2BUA**: back-to-back user agent. It is a SIP server that ends a call and
  places a new one in its place.
- **Proxy**: a SIP server that forwards a call without replacing its Call-ID.
- **SBC**: session border controller, a SIP server at a network edge.
- **PBX**: private branch exchange, a business phone switch.
- **SDP**: Session Description Protocol, the part of a SIP message that
  describes the audio or video session.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **Capture**: a recording of network packets, such as a pcap or pcapng file.
- **Node**: one machine running sipnab.
- **Endpoint**: an IP address and port that sends or receives SIP.
- **NTP**: Network Time Protocol, which keeps a host's clock in step with
  reference clocks.

## Related guides

- [Follow one call across an SBC and its PBXes](@/docs/mcp-estate.md#follow-one-call-across-an-sbc-and-its-pbxes)
- [Read what matched, because the topology is not fixed](@/docs/mcp-estate.md#read-what-matched-because-the-topology-is-not-fixed)
- [Check what federation cannot prove](@/docs/mcp-estate.md#check-what-federation-cannot-prove)
- [`find_correlated` reference](@/docs/mcp-tools-signaling.md#find-correlated) and [`get_call_tree`](@/docs/mcp-tools-signaling.md#get-call-tree)
- [`capture_health`, which reports the clock without a correlation](@/docs/mcp-tools-server.md#capture-health)
- [REST: GET /v1/dialogs/:call_id/correlated](@/docs/api.md#get-v1-dialogs-call-id-correlated)
- [Keep a capture running between agent sessions](@/docs/mcp-deploy.md#keep-a-capture-running-between-agent-sessions)
