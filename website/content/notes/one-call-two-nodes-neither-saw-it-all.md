+++
title = "Join the two legs of a call that crossed a B2BUA"
date = 2026-09-01
updated = 2026-10-11
description = "How to find the second Call-ID of a call that a back-to-back user agent re-originated, and how to tell an identifier match from a timing guess."

[extra]
kind = "howto"
+++

## In short

Some kinds of telephone switch split a phone call that passes through them in
two: the switch ends the incoming call and places a new outgoing one, with a
new call identifier. The box on each side then logs only one of the two
identifiers, so the call looks lost between them. sipnab can look at a
recording from the switch, name the other half of the call, and say whether it
found that half by a shared identifier or only guessed from timing.

## Who this is for

Operators who hold captures from an SBC, proxy or PBX and need to follow one
call from one box to the next, either by hand or through an AI agent.

## Before you start

- A B2BUA (back-to-back user agent) is a SIP server that ends the incoming
  call and starts a new outgoing call, usually with a new Call-ID. Many SBCs
  and PBXes act as one on some calls and as a plain proxy on others.
- The commands below talk to sipnab's MCP server (the interface an AI agent
  uses) over standard input, so they run without an agent. They need `sipnab`
  on your `PATH` and `jq` (a JSON command-line tool).
- The repository has one capture that holds both legs of a B2BUA call:
  `tests/pcap-samples/b2bua-asterisk.pcapng`. The incoming leg has Call-ID
  `b2bua-caller-synth@203.0.113.1` and the outgoing leg has Call-ID
  `b2bua-leg-synth@203.0.113.101:5060`.

## Steps

1. Ask the box that re-originated the call first. Only that box saw both
   legs, so only its capture can name the Call-ID the next box knows the call
   by. Start sipnab on its capture with a node name, and call
   `find_correlated` with the Call-ID you already have:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_correlated","arguments":{"call_id":"b2bua-caller-synth@203.0.113.1"}}}' | sipnab --mcp -N --quiet --node-name sbc-edge-1 -I tests/pcap-samples/b2bua-asterisk.pcapng | jq 'select(.id==2) | .result.structuredContent'
   ```

   Output on sipnab 0.5.211:

   ```text
   {
     "capture_identity": {
       "dialog_generation": 64,
       "instance": "6388918dda16675c34b4e-2",
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
       "max_error_us": 36000,
       "synchronized": true
     },
     "total_matched": 1
   }
   ```

   `instance` and `max_error_us` differ on every run. If the box acted as a
   proxy on this call, `legs` is empty and `total_matched` is 0: the Call-ID
   did not change, so ask the next box for the same Call-ID.

2. Read `strategy` and `identifier_match` before `score`. In step 1 the
   strategy is `timing_heuristic` and `identifier_match` is `false`: no
   identifier crossed the switch, and sipnab paired the two legs because they
   share an endpoint and started 3 ms apart (`observed_gap_ms`). That is a
   guess. `heuristic_only: true` means every returned leg is a guess, so say so
   in anything you write about the call.

   For contrast, `tests/pcap-samples/sip-rtp-g711.pcap` holds two calls that
   share an SDP origin line (the line in the media description that names the
   session and its creator):

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_correlated","arguments":{"call_id":"1-1966@10.0.2.20"}}}' | sipnab --mcp -N --quiet --node-name sbc-edge-1 -I tests/pcap-samples/sip-rtp-g711.pcap | jq 'select(.id==2) | .result.structuredContent'
   ```

   ```text
   {
     "capture_identity": {
       "dialog_generation": 13,
       "instance": "63aff18dda16824bb76ea-2",
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
     "source_exhausted": true,
     "source_stopped_early": false,
     "timing_clock": null,
     "total_matched": 1
   }
   ```

   Here an identifier matched (`identifier_match: true`), `observed_gap_ms` is
   `null` because sipnab used no timing, and `timing_clock` is `null` because no
   leg needed it.

   sipnab has seven strategies. Two exist by design to cross a B2BUA:
   `session_id` (the [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) `Session-ID` header) and
   `charging_vector_related_icid` (only when the B2BUA chose to send it).
   `x_call_id` and `sdp_origin` cross only when the box copies the header or
   the SDP. `charging_vector_icid` and `via_branch` do not cross by design, and
   `timing_heuristic` is not an identifier. The full table is in the
   [`find_correlated` reference](@/docs/mcp-tools-signaling.md#find-correlated).

3. Check the clock only when different hosts timestamped the two legs.
   Inside one capture, one clock stamped every packet, so a 3 ms gap between
   two legs in that capture is a measured interval even if the clock's absolute
   time is wrong. When legs come from captures written on two hosts, clock
   offset between the hosts adds to the gap, and the timing match is only as
   good as both clocks.

   `timing_clock` describes the clock of the host answering the query, read
   from the kernel at the moment of the query. It does not describe the clock
   that stamped a capture file that sipnab reads. `max_error_us` is the kernel's
   upper bound on that clock's error, in microseconds, and it changes from
   reading to reading: three runs on one host on 2026-10-11 reported 1017000,
   36000 and 16500. The time window for a timing match is 2000 ms unless
   `--leg-correlation-window <MS>` sets another value. A `max_error_us` near
   that window means a timing match across hosts proves nothing.

4. Carry the Call-ID from step 1 to the next box and ask that box for it with
   `get_dialog`. The repository has no second capture of this call, so this
   example reads the same file under the node name `pbx-1`:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_dialog","arguments":{"call_id":"b2bua-leg-synth@203.0.113.101:5060"}}}' | sipnab --mcp -N --quiet --node-name pbx-1 -I tests/pcap-samples/b2bua-asterisk.pcapng | jq -c 'select(.id==2) | .result.structuredContent.dialog | {call_id, state, final_status_code, msg_count}'
   ```

   ```text
   {"call_id":"b2bua-leg-synth@203.0.113.101:5060","state":"Completed","final_status_code":200,"msg_count":15}
   ```

5. Record which box gave each answer. `capture_identity.node` names the box,
   and `--node-name` sets it. Without that flag, sipnab uses the system
   hostname. Not every answer carries `capture_identity`: `find_correlated`,
   `capture_status` and `list_dialogs` do, and `get_dialog` does not. Call
   `capture_status` once per node and keep the name. `capture_identity.instance`
   changes whenever a different capture loads; the node name does not.

   On a live box that an agent reaches over HTTP, the server command takes the
   same flag:

   ```bash
   sipnab --mcp -N --mcp-transport http --mcp-bind 127.0.0.1:8731 --node-name sbc-edge-1 -d eth0
   ```

   This form needs capture privileges on `eth0`, so it was not run for this
   note. The same arguments with `-I tests/pcap-samples/b2bua-asterisk.pcapng`
   in place of `-d eth0`, and port 28731, started and logged
   `MCP HTTP server listening on 127.0.0.1:28731`.

## Limits

- If the box sends no `Session-ID`, no correlation header that sipnab's
  configuration tells it to read, and rewrites the SDP, only the timing guess
  remains, and nothing in the signaling proves the two legs are one call. Configuring the box to
  insert a correlation header is the fix; see
  [Choose a correlation identifier](@/docs/mcp-estate.md#choose-a-correlation-identifier).
- `find_correlated` answers one hop inside one capture. `get_call_tree` walks
  every leg in one capture, and stops at a timing guess. Across boxes, repeat
  steps 1 and 4 at each box.
- The REST route `GET /v1/dialogs/:call_id/correlated` returns the same legs
  but no `capture_identity` and no `timing_clock`.

## Terms used here

- **SIP**: the signaling protocol that sets up and ends phone calls over IP.
- **Call-ID**: the SIP header that identifies one call between two endpoints.
- **Leg**: one SIP call between two boxes; a call through a B2BUA has two.
- **B2BUA**: back-to-back user agent, a SIP server that ends a call and places
  a new one in its place.
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
