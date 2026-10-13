+++
title = "Find out why an answered call carried no audio"
date = 2026-09-01
updated = 2026-10-11
description = "A sequence of sipnab checks for a call answered and then silent: confirm the capture can see audio, rule out discarded signaling, explain unattached media, check for late media, and look for findings that name a cause."

[extra]
kind = "howto"
+++

## In short

A call can complete its setup correctly, get an answer, and still carry no
sound. Before reading that as a network fault, check that you captured at a
point where the audio packets pass at all: a capture that holds only signaling
cannot say anything about audio. sipnab does not report "no audio" for calls
in a capture that holds no audio packets at all. This page gives the checks in
order, with the sipnab command for each.

## Who this is for

Anyone using sipnab to investigate a complaint of silence on a call that the
signaling shows as answered.

## Steps

The commands below run from the root of a sipnab checkout against captures in
`tests/pcap-samples/` and `tests/fixtures/`. `--quiet` hides informational
log lines. Warnings still print, with a timestamp. The output shown has the
trailing spaces at the ends of table rows removed.

### 1. Check that the capture holds audio packets at all

Call audio travels as RTP (Real-time Transport Protocol) packets, on a path
that can differ from the signaling path. `--report` lists the calls, then an
`RTP Streams:` table of the audio streams it found:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --report --no-cli-print --quiet
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
1-1966@10.0.2.20                 sipp           test           Completed    200    8s         6      -        -
1-1968@10.0.2.20                 sipp           test           InCall       200    0s         4      -        -

RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps
--------------------------------------------------------------------------------------------------------------------------
0x343da99b   0    PCMU     8000   10.0.2.15:27942       10.0.2.20:6000        425     0      0.0%    0ms      8s     64
0x343ffa34   8    PCMA     8000   10.0.2.15:28102       10.0.2.20:6000        414     0      0.0%    0ms      8s     64
```

The same capture read through a BPF expression that keeps only the SIP port
(BPF is the packet filter language of libpcap and tcpdump) has the same two
answered calls and no stream table:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --report --no-cli-print --quiet 'udp port 5060'
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
1-1966@10.0.2.20                 sipp           test           Completed    200    8s         6      -        -
1-1968@10.0.2.20                 sipp           test           InCall       200    0s         4      -        -
```

If `--report` prints neither an `RTP Streams:` table nor an `Orphaned
Streams:` table (step 3), the capture holds no audio and cannot answer a
question about it. Capture again at a point the audio passes through. No sipnab
option recovers packets that were never captured.

sipnab has a finding for an answered call with no audio, `[CRITICAL] No media
on an answered call`. It does not raise it when the capture as a whole holds no
RTP, because then sipnab would report every answered call, including every call
from a signaling-only source: a capture point the audio does not pass
through, a HEP feed, or a run with `--no-rtp`. On the signaling-only read above:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --analyze --no-cli-print --quiet 'udp port 5060'
```

```text
No problems found in 2 dialog(s) and 0 stream(s) across 10 frame(s). Every frame decoded, no port gate discarded SIP, and no retention cap was reached — so this is a statement about the capture, not only about what sipnab could read of it.
```

### 2. Check that the port range discarded no SIP

By default sipnab reads SIP only on ports 5060 to 5061 (`--portrange`). sipnab
recognizes SIP on any other port and then discards it, and the audio of those
calls then belongs to no call:

```bash
sipnab -N -I tests/pcap-samples/codec-negotiation.pcap --analyze --no-cli-print --quiet
```

```text
2026-10-12T00:48:36.056409Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 1 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (1). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
2026-10-12T00:48:36.056770Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 10 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (10). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
Capture analysis: 1 finding(s) across 0 dialog(s), 0 stream(s), 614 frame(s) read.

THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The findings below describe what it UNDERSTOOD, so their counts are floors and the ABSENCE of a finding is not evidence that the problem is absent. The blind finding(s) are listed first.

1. [BLIND] SIP discarded by --portrange — 10 message(s)
   sipnab recognized these as SIP and then threw them away because neither port was inside --portrange. They are in no dialog and no count. Widen the range (--portrange 1-65535 analyzes everything) and read the capture again.
   Evidence:
     - port 5080 | messages=10
```

sipnab lists `[BLIND]` findings first: they say what sipnab could not read. Here
the SIP ran on port 5080. Widen the range and read the capture again:

```bash
sipnab -N -I tests/pcap-samples/codec-negotiation.pcap --portrange 1-65535 --analyze --no-cli-print --quiet
```

```text
No problems found in 1 dialog(s) and 4 stream(s) across 614 frame(s). Every frame decoded, no port gate discarded SIP, and no retention cap was reached — so this is a statement about the capture, not only about what sipnab could read of it.
```

With the range widened, the capture has one call and its four streams attach
to it.

### 3. Explain audio that belongs to no call

An orphaned stream is an audio stream that no captured call claims. With the
default port range, `--report` on the same capture lists the four streams
under `Orphaned Streams:`:

```bash
sipnab -N -I tests/pcap-samples/codec-negotiation.pcap --report --no-cli-print --quiet
```

```text
2026-10-12T00:48:36.075066Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 1 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (1). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
2026-10-12T00:48:36.075428Z  WARN sipnab::pipeline: SIP outside --portrange 5060-5061 is being skipped: 10 message(s) so far, in no count, no dialog, and no output. Busiest port(s): 5080 (10). Re-run with a range that covers them (e.g. --portrange 1-65535) to analyze them.
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------

Orphaned Streams:
SSRC         Source                   Destination              Pkts     Duration
--------------------------------------------------------------------------------
0x0e330af3   127.0.0.1:5094           127.0.0.1:5084           151      2s
0x0e330af3   127.0.0.1:5084           127.0.0.1:5094           151      2s
0x2d374e76   127.0.0.1:5094           127.0.0.1:5084           151      2s
0x2d374e76   127.0.0.1:5084           127.0.0.1:5094           151      2s
```

When sipnab runs as an MCP server (`sipnab --mcp -N`, the interface an AI agent
uses), two tools answer the same questions:

- `capture_status` reports `stream_count`, `orphaned_stream_count` and
  `unanalysed_sip_messages` beside the call counts. On this capture with the
  default port range it reported `"dialog_count":0`, `"stream_count":4`,
  `"orphaned_stream_count":4` and `"unanalysed_sip_messages":10`. The field
  name uses British spelling in the API; the name is exact.
- `reconcile_orphans` gives a reason for each orphaned stream:

| reason | what it means |
|---|---|
| `relay-asserted-but-no-dialog` | a media relay named this endpoint and no captured call claims it: the signaling is missing, not the audio |
| `signaled-but-no-dialog` | SDP named it and no call holds it: the capture missed the call, or its SDP arrived before the capture started |
| `never-named` | nothing in this capture named this endpoint |

`relay_was_consulted` is a field of the whole answer, not of each row. On this
capture each of the four rows had `"reason":"never-named"` and the answer had
`"relay_was_consulted":false`, and each row carried this `note`:

```text
nothing in this capture named this endpoint. A relay could answer it and none was asked: that is an absence of evidence, not evidence of absence
```

### 4. Check whether the audio started late rather than never

If audio starts long after the `200 OK` (the answer), the first part of the
conversation is missing from the call. sipnab reports this as `Media started late` when the
delay exceeds `--late-media-ms`, which defaults to 500 milliseconds:

```bash
sipnab -N -I tests/pcap-samples/SIP_DTMF2.cap --analyze --no-cli-print --quiet
```

```text
Capture analysis: 3 finding(s) across 5 dialog(s), 2 stream(s), 1360 frame(s) read.

1. [MAJOR] RTP source no SDP advertised — 1 call(s)
   Media arrived from an address that no SDP in the dialog named — the signature of a NAT rewriting the media source. Frequently benign on its own (symmetric RTP through a NAT looks exactly like this); read it together with any one-way audio on the same call.
   Evidence:
     - Call-ID 25672@192.168.105.110 | 192.168.105.110:5060 -> 192.168.105.105, SDP 192.168.105.110, RTP from 192.168.105.172 | 2005-09-09 12:03:17.334 UTC | rtp_packets=1331 streams=2

2. [MAJOR] Call failed 5xx/6xx — 1 call(s)
   The call ended on a server-class or global failure (RFC 3261 §21.5, §21.6). Unlike a 4xx these are never an ordinary call outcome: something on the path or at the far end was unable to serve the request.
   Evidence:
     - Call-ID 5514@192.168.105.110 | 192.168.105.110:5060 -> 192.168.105.105 | 2005-09-09 12:03:01.333 UTC | status_code=603 | Decline

3. [MINOR] Media started late — 1 call(s)
   RTP began well after the 200 OK, so the first part of the conversation was clipped. Usually a media relay that had not finished setting the path up when signaling completed.
   Evidence:
     - Call-ID 25672@192.168.105.110 | 192.168.105.110:5060 -> 192.168.105.105 | 2005-09-09 12:03:17.334 UTC | delay_after_200_ok_ms=22501 | a leg started late
```

Finding 3 shows audio that began 22,501 milliseconds after the answer. Set
`--late-media-ms` to the delay you expect your network to meet.
`--filter late-media` selects the same calls for a report, and the MCP
`find_problems` tool accepts `late-media` as a kind.

### 5. Look for findings that name a cause

Three findings point at a specific cause rather than an absence.

**Answered INVITE never acknowledged.** The caller must confirm an answer with
an ACK. When no ACK arrives, the answering side sends the answer again and then
ends the call. sipnab reports it once the answer has gone unacknowledged for
`--ack-timeout` seconds. The default is 32 seconds ([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) Timer H). The
call in this fixture ran 31.5 seconds without an ACK, so this run lowers the
threshold to 30 seconds:

```bash
sipnab -N -I tests/fixtures/sip-answered-never-acked.pcap --ack-timeout 30 --analyze --no-cli-print --quiet
```

```text
Capture analysis: 1 finding(s) across 1 dialog(s), 0 stream(s), 14 frame(s) read.

1. [MAJOR] Answered INVITE never acknowledged — 1 call(s)
   A 2xx answered the INVITE and no ACK confirmed it (RFC 3261 §13.3.1.4), so the UAS retransmitted until Timer H and then tore the call down. Audio typically stops within seconds of the answer.
   Evidence:
     - Call-ID noack-5d4c3b@192.0.2.70 | 192.0.2.70:5060 -> 192.0.2.80 | 2023-11-14 22:13:20.000 UTC | answer_transmissions=11 | 31.5s elapsed with no ACK
```

With the default of 32 seconds, the same capture reports no problems.

<!-- vale Google.Passive = NO -->

**ICMP: media undeliverable.** A router or host answered an audio packet with
an ICMP error, which means nothing was listening on the address and port the
sender addressed the audio to. sipnab's description of the finding reads: "Check that the
media relay is running and that the port the SDP advertised is the port it is
bound to." No capture in the repository produces this finding.

<!-- vale Google.Passive = YES -->

**ICE role conflict with no nominated pair.** ICE is the procedure two
endpoints use to find a network path for audio. One side must be
"controlling" and the other "controlled". `--stun` reports the checks, and
names a conflict that ended with no path chosen:

```bash
sipnab -N -I tests/fixtures/ice_checks.pcap --stun --no-cli-print --quiet
```

```text
STUN Transactions (10 packet(s), 5 transaction(s)):
Transaction              Method           Client                 Server                 Reqs  Response       RTT       Mapped Address         Role
----------------------------------------------------------------------------------------------------------------------------------------------------------
111111111111111111111111 Binding          192.0.2.10:50004       203.0.113.9:16000      1     success        12.0ms    192.0.2.10:50004       controlling
121212121212121212121212 Binding          192.0.2.10:50004       203.0.113.9:16000      1     success        18.0ms    192.0.2.10:50004       controlling
131313131313131313131313 Binding          203.0.113.9:16000      192.0.2.10:50004       1     success        11.0ms    203.0.113.9:16000      controlled
212121212121212121212121 Binding          192.0.2.11:50006       203.0.113.11:16002     1     error 487      12.0ms    -                      controlling
222222222222222222222222 Binding          203.0.113.11:16002     192.0.2.11:50006       1     error 487      14.0ms    -                      controlling

ICE: 5 connectivity check(s), 5 answered.
  nominated 192.0.2.10:50004 -> 203.0.113.9:16000 (nominated by the controlling agent, priority 2130706431), 18.0 ms
  ROLE CONFLICT 192.0.2.11:50006 <-> 203.0.113.11:16002: both claimed controlling, 2 x 487 Role Conflict. No pair between them was ever nominated, so this is a candidate cause of media that never started.
```

The endpoints nominated the first pair. The second pair had both sides claim
`controlling`, and no path between them was ever nominated, so audio between
those two addresses had no agreed path.

## Order of checks

1. Does `--report` print an `RTP Streams:` or `Orphaned Streams:` table? If
   not, capture at a point the audio passes through.
2. Is there a `[BLIND] SIP discarded by --portrange` finding? If so, re-read
   with `--portrange 1-65535`.
3. Are there orphaned streams? Ask `reconcile_orphans` why.
4. Did the audio start late? Check `Media started late` against
   `--late-media-ms`.
5. Is there a missing ACK, an ICMP error, or an ICE role conflict with no
   nominated pair?

## Terms used here

- **SIP**: the signaling protocol that sets up, answers and ends calls.
- **INVITE, 200 OK, ACK**: the SIP request that starts a call, the answer, and
  the caller's confirmation of the answer.
- **SDP**: the part of a SIP message that says where to send audio.
- **RTP**: the protocol that carries the audio packets.
- **Stream**: one direction of audio from one source, identified by its SSRC
  (a number in each RTP packet).
- **Dialog**: sipnab's record of one call's SIP exchange.
- **Orphaned stream**: an audio stream that no captured call claims.
- **Media relay**: a server that forwards a call's audio between the two
  parties.
- **BPF**: the packet filter language of libpcap and tcpdump.
- **HEP**: a protocol that SIP servers use to send copies of their messages to
  a collector.
- **MCP**: the Model Context Protocol, the interface sipnab offers to AI
  agents.
- **ICMP**: the protocol routers and hosts use to report delivery errors.
- **ICE, STUN**: the procedure, and the request protocol it uses, by which two
  endpoints test and choose a network path for audio.
- **Timer H**: the RFC 3261 timer, 32 seconds by default, after which an
  the answering side abandons an unacknowledged answer.

## Related guides

- [Troubleshooting: Dead air and clipping](@/docs/troubleshooting.md#dead-air-and-clipping)
- [Troubleshooting: One-way audio](@/docs/troubleshooting.md#one-way-audio)
- [Troubleshooting: Dropped calls](@/docs/troubleshooting.md#dropped-calls-call-answers-then-disconnects-mid-conversation)
- [Troubleshooting: Both ICE agents think they are in charge](@/docs/troubleshooting.md#both-ice-agents-think-they-are-in-charge)
- [MCP tools: `capture_status`](@/docs/mcp-tools-core.md#capture-status) and
  [`reconcile_orphans`](@/docs/mcp-tools-media.md#reconcile-orphans)
- [CLI reference: Diagnosis thresholds](@/docs/cli.md#diagnosis-thresholds),
  the rows for `--late-media-ms` and `--ack-timeout`
- [Filter DSL: Named aliases](@/docs/filter-dsl.md#named-aliases)
