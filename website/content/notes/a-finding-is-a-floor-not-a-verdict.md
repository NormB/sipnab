+++
title = "Check five things before you act on a sipnab finding"
date = 2026-09-01
updated = 2026-10-11
description = "Five checks, with the command and the field for each, that tell you whether a sipnab finding describes the whole capture and whether it describes a fault."

[extra]
kind = "howto"
+++

## In short

sipnab reads a network capture and lists the problems it found in the phone
calls inside it. A list like that can be incomplete without looking incomplete:
sipnab may not have finished reading, may have set some traffic aside, or may
not have been checking for a given problem at all. This how-to shows the five
checks to make before you act on a finding, and the exact output or field that
answers each one.

## Who this is for

Anyone who reads sipnab's problem list, at the command line with `--analyze` or
through an AI agent connected over MCP (the Model Context Protocol, the
interface an agent uses to call sipnab's tools).

## Before you start

The commands run from the root of a sipnab checkout, against captures in
`tests/pcap-samples/`. The MCP examples drive the server over standard input
with `printf` and select fields with `jq`, so you can reproduce each answer
without an agent. An agent sends the same tool call and receives the same
fields. `--node-name lab` sets the name that appears in
`capture_identity.node`. Without it, sipnab uses the host name.

## 1. Check that the answer is the whole answer

An MCP answer that lists dialogs (a dialog is one call, or one registration,
from its first SIP message to its last) carries five fields that say how much
of the capture stands behind it.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_problems","arguments":{"limit":1}}}' \
| sipnab -N --mcp --node-name lab -I tests/pcap-samples/sip-problem-call.pcap 2>/dev/null \
| jq -c 'select(.id==2) | .result.structuredContent | {returned, total_matched, truncated, source_exhausted, source_stopped_early}'
```

```json
{"returned":1,"total_matched":4,"truncated":true,"source_exhausted":true,"source_stopped_early":false}
```

- `returned` is the number of rows on this page. Here it is 1 because the call
  asked for `limit: 1`.
- `total_matched` is the number of dialogs that match across the whole capture,
  whatever `limit` and the paging cursor say. Here it is 4. This is the number
  that answers "how many".
- `truncated: true` means more matching rows exist than this page holds.
- `source_exhausted` is true once sipnab has read the capture to its end.
  sipnab reads a file in the background, so a call made right after the server
  starts can arrive before the file is fully loaded.
- `source_stopped_early` is true when the read ended before the file did, for
  example on a cut-off file or a read error.

The answer describes the whole capture only when `source_exhausted` is true and
`source_stopped_early` is false. Until then, every count is a lower bound, and
sipnab leaves `truncated: false` out of the answer rather than send it, so a
missing `truncated` key does not mean `false`. Each of these answers also carries
`capture_identity.instance`. If it changes between two pages, the server
loaded a different capture and the cursor from the earlier page no longer
applies.

## 2. Check what sipnab set aside

sipnab analyzes SIP (the signaling protocol that sets up and ends calls) only
on the ports named by `--portrange`, which defaults to `5060-5061`. When both the
source and the destination port of a SIP message fall outside that range,
sipnab recognizes the message, counts it, and leaves it out of every dialog and
every other count. The capture `codec-negotiation.pcap` carries its SIP on port
5080.

```bash
sipnab -N -q -I tests/pcap-samples/codec-negotiation.pcap --analyze --no-cli-print
```

```text
2026-10-12T00:42:07.841252Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 1 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (1). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
2026-10-12T00:42:07.841598Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 10 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (10). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
Capture analysis: 1 finding(s) across 0 dialog(s), 0 stream(s), 614 frame(s) read.

THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The findings below describe what it UNDERSTOOD, so their counts are floors and the ABSENCE of a finding is not evidence that the problem is absent. The blind finding(s) are listed first.

1. [BLIND] SIP discarded by --portrange — 10 message(s)
   sipnab recognized these as SIP and then threw them away because neither port was inside --portrange. They are in no dialog and no count. Widen the range (--portrange 1-65535 analyzes everything) and read the capture again.
   Evidence:
     - port 5080 | messages=10
```

The two `WARN` lines go to standard error, and the rest goes to standard output.
`BLIND` is the severity sipnab gives to anything that limits what the analysis
could see. It ranks above `CRITICAL`, so it is always first in the list. Run the
same capture with the range the finding names:

```bash
sipnab -N -q -I tests/pcap-samples/codec-negotiation.pcap --portrange 1-65535 --analyze --no-cli-print
```

```text
No problems found in 1 dialog(s) and 4 stream(s) across 614 frame(s). Every frame decoded, no port gate discarded SIP, and no retention cap was reached — so this is a statement about the capture, not only about what sipnab could read of it.
```

Over MCP, the same facts are in the `capture_status` answer:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"capture_status","arguments":{}}}' \
| sipnab -N --mcp --node-name lab -I tests/pcap-samples/codec-negotiation.pcap 2>/dev/null \
| jq 'select(.id==2) | .result.structuredContent | {dialog_count, unanalysed_sip_messages, unanalysed_busiest_ports, source_exhausted, capture_quality}'
```

```json
{
  "dialog_count": 0,
  "unanalysed_sip_messages": 10,
  "unanalysed_busiest_ports": [
    {
      "messages": 10,
      "port": 5080
    }
  ],
  "source_exhausted": true,
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
  }
}
```

`dialog_count: 0` next to `unanalysed_sip_messages: 10` means the capture held
SIP that sipnab did not analyze, not that the capture held no calls. The
`capture_quality` block counts packets the capture lost or could not use, such
as `kernel_dropped_packets` and `undecodable_frames`.
[How sipnab reports what a capture missed](@/notes/a-total-that-cannot-say-what-it-missed.md)
explains each counter.

## 3. Check that a detector was running

The security findings list is empty in two different situations: no detector
was running, or a detector ran and matched nothing. A detector is one of the
optional security checks, each turned on by its own flag. The answer says which
situation applies.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"security_findings","arguments":{}}}' \
| sipnab -N --mcp --node-name lab -I tests/pcap-samples/sip-problem-call.pcap 2>/dev/null \
| jq 'select(.id==2) | .result.structuredContent'
```

```json
{
  "armed_kinds": [],
  "detection_armed": false,
  "findings": [],
  "note": "No detection rule is armed on this server, so no finding could have been recorded. An empty findings list here means nothing was watching, NOT that the traffic was clean. Arm a detector with --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and re-run the capture.",
  "observation_gaps": [],
  "returned": 0,
  "schema_version": 1,
  "source_exhausted": true,
  "source_stopped_early": false,
  "total_matched": 0,
  "truncated": false
}
```

The same call on a server started with `--kill-scanner` (the scanner detector)
reports which detector ran. This command removes the `findings` array to keep
the output short:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"security_findings","arguments":{}}}' \
| sipnab -N --mcp --node-name lab --kill-scanner -I tests/pcap-samples/sip-problem-call.pcap 2>/dev/null \
| grep '"id":2' | jq -c '.result.structuredContent | del(.findings)'
```

```json
{"armed_kinds":["scanner"],"detection_armed":true,"observation_gaps":[],"returned":0,"schema_version":1,"source_exhausted":true,"source_stopped_early":false,"total_matched":0,"truncated":false}
```

Only this second answer supports the statement "the scanner detector found
nothing in this capture".

`describe_endpoint` follows the same rule for one address or user. Its
`findings.selectable` field is `false` when you ask about the endpoint by SIP
user, because sipnab files security findings against a source address and has
no way to select them by user. `failure_rate_pct` is `null`, not `0.0`, when no
call reached a final response, and `registration.applicable` is `false` when
no registration dialog involves the endpoint.

## 4. Read the finding's own text

sipnab ranks findings by what the caller and the operator lost. `BLIND` means
the analysis itself is incomplete. `CRITICAL` means nobody could hear: the
phones agreed on audio and none arrived, or it arrived in one direction only.
`MAJOR` means the call failed or the audio path shows damage, without proof that
the audio was absent. `MINOR` means measurable degradation, or an outcome that
is often normal, which sipnab lists so you can rule it out. Read the text of a
finding before acting on it.

```bash
sipnab -N -q -I tests/pcap-samples/sip-problem-call.pcap --analyze --no-cli-print
```

```text
Capture analysis: 2 finding(s) across 5 dialog(s), 0 stream(s), 23 frame(s) read.

1. [MAJOR] Call failed 5xx/6xx — 2 call(s)
   The call ended on a server-class or global failure (RFC 3261 §21.5, §21.6). Unlike a 4xx these are never an ordinary call outcome: something on the path or at the far end was unable to serve the request.
   Evidence:
     - Call-ID decline-7c6d5e@198.51.100.30 | 198.51.100.30:5060 -> 198.51.100.40 | 2023-11-14 22:13:26.000 UTC | status_code=603 | Decline
     - Call-ID unavail-4e5f60@192.0.2.50 | 192.0.2.50:5060 -> 192.0.2.60 | 2023-11-14 22:13:32.000 UTC | status_code=503 | Service Unavailable

2. [MINOR] Call failed 4xx — 2 call(s)
   The call ended on a request failure (RFC 3261 §21.4). Many 4xx codes are ordinary call outcomes — 486 Busy Here, 404 for a misdialled number, 480 for a phone that is off — so this is listed to be ruled out rather than acted on. The codes are named below; a run of 403 or 408 is not an ordinary outcome.
   Evidence:
     - Call-ID busy-3a2b1c@192.0.2.30 | 192.0.2.30:5060 -> 192.0.2.40 | 2023-11-14 22:13:23.000 UTC | status_code=486 | Busy Here
     - Call-ID notfound-1b2c3d@203.0.113.30 | 203.0.113.30:5060 -> 203.0.113.40 | 2023-11-14 22:13:29.000 UTC | status_code=404 | Not Found
```

The 4xx finding names a 486 (the called phone was busy) and a 404 (the number
does not exist). Both are ordinary call outcomes, and the finding text says so.

The same command on `tests/pcap-samples/SIP_DTMF2.cap` reports a finding whose
text gives the same kind of instruction:

```text
1. [MAJOR] RTP source no SDP advertised — 1 call(s)
   Media arrived from an address that no SDP in the dialog named — the signature of a NAT rewriting the media source. Frequently benign on its own (symmetric RTP through a NAT looks exactly like this); read it together with any one-way audio on the same call.
```

These are the first two lines of that finding. RTP is the stream that carries
the audio, SDP is the part of a SIP message that says where that stream should
go, and NAT is address translation by a router or firewall. For a one-way audio finding, see
[Rule out the media relay before you blame NAT](@/notes/rule-out-the-relay-before-the-nat.md).

## 5. Check the packet behind the finding

Each dialog in an answer carries a `frame` pointer: the capture file, the
frame's position in it, and a digest (a short fingerprint of the frame's
bytes). The `find_problems` call in step 1 returned the pointer
`tests/pcap-samples/sip-problem-call.pcap#5@884d4525ec86f71b`.

```bash
sipnab -N -q -I tests/pcap-samples/sip-problem-call.pcap --show-frame 'tests/pcap-samples/sip-problem-call.pcap#5@884d4525ec86f71b'
```

```text
VERIFIED  tests/pcap-samples/sip-problem-call.pcap#5@884d4525ec86f71b
540 bytes, frame 5 of tests/pcap-samples/sip-problem-call.pcap

00000000  02 00 00 00 00 01 02 00  00 00 00 02 08 00 45 00  |..............E.|
00000010  02 0e 00 00 40 00 40 11  b4 98 c0 00 02 1e c0 00  |....@.@.........|
00000020  02 28 13 c4 13 c4 01 fa  00 00 49 4e 56 49 54 45  |.(........INVITE|
00000030  20 73 69 70 3a 64 61 76  65 40 31 39 32 2e 30 2e  | sip:dave@192.0.|
00000040  32 2e 34 30 20 53 49 50  2f 32 2e 30 0d 0a 56 69  |2.40 SIP/2.0..Vi|
00000050  61 3a 20 53 49 50 2f 32  2e 30 2f 55 44 50 20 31  |a: SIP/2.0/UDP 1|
00000060  39 32 2e 30 2e 32 2e 33  30 3a 35 30 36 30 3b 62  |92.0.2.30:5060;b|
00000070  72 61 6e 63 68 3d 7a 39  68 47 34 62 4b 2d 62 75  |ranch=z9hG4bK-bu|
00000080  73 79 2d 33 0d 0a 4d 61  78 2d 46 6f 72 77 61 72  |sy-3..Max-Forwar|
00000090  64 73 3a 20 37 30 0d 0a  46 72 6f 6d 3a 20 22 63  |ds: 70..From: "c|
000000a0  61 72 6f 6c 22 20 3c 73  69 70 3a 63 61 72 6f 6c  |arol" <sip:carol|
000000b0  40 31 39 32 2e 30 2e 32  2e 33 30 3e 3b 74 61 67  |@192.0.2.30>;tag|
000000c0  3d 63 31 0d 0a 54 6f 3a  20 3c 73 69 70 3a 64 61  |=c1..To: <sip:da|
000000d0  76 65 40 31 39 32 2e 30  2e 32 2e 34 30 3e 0d 0a  |ve@192.0.2.40>..|
000000e0  43 61 6c 6c 2d 49 44 3a  20 62 75 73 79 2d 33 61  |Call-ID: busy-3a|
000000f0  32 62 31 63 40 31 39 32  2e 30 2e 32 2e 33 30 0d  |2b1c@192.0.2.30.|
00000100  0a 43 53 65 71 3a 20 31  20 49 4e 56 49 54 45 0d  |.CSeq: 1 INVITE.|
00000110  0a 43 6f 6e 74 61 63 74  3a 20 3c 73 69 70 3a 63  |.Contact: <sip:c|
00000120  61 72 6f 6c 40 31 39 32  2e 30 2e 32 2e 33 30 3a  |arol@192.0.2.30:|
00000130  35 30 36 30 3e 0d 0a 43  6f 6e 74 65 6e 74 2d 54  |5060>..Content-T|
00000140  79 70 65 3a 20 61 70 70  6c 69 63 61 74 69 6f 6e  |ype: application|
00000150  2f 73 64 70 0d 0a 43 6f  6e 74 65 6e 74 2d 4c 65  |/sdp..Content-Le|
00000160  6e 67 74 68 3a 20 31 36  36 0d 0a 0d 0a 76 3d 30  |ngth: 166....v=0|
00000170  0d 0a 6f 3d 2d 20 31 20  31 20 49 4e 20 49 50 34  |..o=- 1 1 IN IP4|
00000180  20 31 39 32 2e 30 2e 32  2e 33 30 0d 0a 73 3d 2d  | 192.0.2.30..s=-|
00000190  0d 0a 63 3d 49 4e 20 49  50 34 20 31 39 32 2e 30  |..c=IN IP4 192.0|
000001a0  2e 32 2e 33 30 0d 0a 74  3d 30 20 30 0d 0a 6d 3d  |.2.30..t=0 0..m=|
000001b0  61 75 64 69 6f 20 31 30  30 30 30 20 52 54 50 2f  |audio 10000 RTP/|
000001c0  41 56 50 20 30 20 38 20  31 30 31 0d 0a 61 3d 72  |AVP 0 8 101..a=r|
000001d0  74 70 6d 61 70 3a 30 20  50 43 4d 55 2f 38 30 30  |tpmap:0 PCMU/800|
000001e0  30 0d 0a 61 3d 72 74 70  6d 61 70 3a 38 20 50 43  |0..a=rtpmap:8 PC|
000001f0  4d 41 2f 38 30 30 30 0d  0a 61 3d 72 74 70 6d 61  |MA/8000..a=rtpma|
00000200  70 3a 31 30 31 20 74 65  6c 65 70 68 6f 6e 65 2d  |p:101 telephone-|
00000210  65 76 65 6e 74 2f 38 30  30 30 0d 0a              |event/8000..|
```

`VERIFIED` means the bytes at that position still match the digest. When they
do not, because someone replaced, cut short or rewrote the file after sipnab
made the pointer, sipnab prints nothing on standard output and exits with
status 1. To see that refusal, give the same frame a digest that does not
match:

```bash
sipnab -N -q -I tests/pcap-samples/sip-problem-call.pcap --show-frame 'tests/pcap-samples/sip-problem-call.pcap#5@0000000000000000'
```

```text
2026-10-12T00:40:53.072446Z ERROR sipnab::app::bootstrap: refusing: tests/pcap-samples/sip-problem-call.pcap frame 5 is not the frame this pointer was made against. The capture was rotated, truncated or rewritten since then. Showing you what is there now would look like an answer and be the wrong one.
```

A pointer without a digest (`tests/pcap-samples/sip-problem-call.pcap#5`)
prints the frame marked `UNVERIFIED`, because there is nothing to check the
bytes against.

## Terms used here

- **Capture**: a file of recorded network packets (pcap or pcapng format).
- **SIP**: Session Initiation Protocol, the messages that set up, change and
  end calls.
- **Dialog**: one call or registration, from its first SIP message to its last.
- **Port**: the number that identifies which service on a machine a packet is
  for. SIP usually uses 5060.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **Finding**: one problem sipnab reports, with a severity and the evidence for
  it.
- **Severity**: the rank of a finding. `BLIND` marks something that limits what
  sipnab could see.
- **Detector**: an optional security check, such as the scanner detector turned
  on by `--kill-scanner`.
- **Frame**: one packet as stored in the capture file.
- **Digest**: a short fingerprint of a frame's bytes, used to confirm the frame
  has not changed.
- **RTP**: Real-time Transport Protocol, the packets that carry the audio.
- **SDP**: Session Description Protocol, the part of a SIP message that says
  where to send the audio.
- **NAT**: network address translation, a router or firewall rewriting
  addresses as packets pass through.
- **jq**: a command-line program that selects fields from JSON.

## Related guides

- [Rules every tool follows](@/docs/mcp-tools.md#rules-every-tool-follows)
- [`capture_status`](@/docs/mcp-tools.md#capture-status),
  [`find_problems`](@/docs/mcp-tools.md#find-problems),
  [`describe_endpoint`](@/docs/mcp-tools.md#describe-endpoint) and
  [`security_findings`](@/docs/mcp-tools.md#security-findings)
- [Find the calls that went wrong](@/docs/first-cli-triage.md#3-find-the-calls-that-went-wrong)
- [`--show-frame` and frame pointers](@/docs/cli.md#pcapng-metadata)
