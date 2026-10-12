# Run sipnab beside FreeSWITCH

sipnab reads the SIP and the audio that pass through FreeSWITCH off the wire,
so it needs nothing from FreeSWITCH: no module, no configuration change.
FreeSWITCH is a back-to-back user agent (B2BUA): it answers the caller's call
and places a second call, with a Call-ID of its own, to the callee. On the
FreeSWITCH machine sipnab sees both calls, which it calls dialogs, and the four
audio streams, and it can tie the two dialogs together as one call.
FreeSWITCH can also send sipnab a copy of its SIP over HEP, the protocol SIP
servers use to send Homer their traffic.

This guide adds sipnab to the FreeSWITCH machine from
[Use FreeSWITCH in your voice stack](freeswitch.md).

## Tested on

Every block on this page ran as written, in order, on 2026-10-12, with sipnab
0.5.211 from its release package, on the Debian 13 (kernel 6.12.63) and Ubuntu
24.04 (kernel 6.8.0) machines that [the FreeSWITCH guide](freeswitch.md) had
set up, with FreeSWITCH 1.11.3. Each test call carried audio both ways on both
legs. On both, causing each fault under [When something does not
work](#when-something-does-not-work) produced the message it quotes. The
examples use `192.0.2.10` as the machine's address.

## 1. Install sipnab

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_amd64.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_amd64.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_amd64.deb
sipnab --version
```

## 2. Watch a call through FreeSWITCH

sipnab watches SIP ports 5060-5061 unless you give it others. FreeSWITCH's
`external` profile, which takes the test call, listens on 5080, so give sipnab
the range from 5060 to 5080 with `--portrange`. Start sipnab on every
interface for 30 seconds, printing each SIP message as it passes, a report of
the calls at the end, and a copy of what it captured in
`/tmp/freeswitch-call.pcap` for the next steps:

```bash
sudo sipnab -N -d any --portrange 5060-5080 --duration 30 --report -O /tmp/freeswitch-call.pcap
```

sipnab writes the capture file after it has dropped its root privileges, as
the user `nobody`, so the file goes in `/tmp`, where `nobody` can write.

While it runs, place a test call from a second terminal, as in
[step 3 of the FreeSWITCH guide](freeswitch.md#3-place-a-test-call):

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sn uac_pcap 192.0.2.10:5080 -i 192.0.2.10 -p 5090 -s echo -m 1 -timeout 90s
```

sipnab prints the caller's `INVITE` to FreeSWITCH at `192.0.2.10:5080`, then
FreeSWITCH's own `INVITE` to the callee at `127.0.0.1:5070`, with a different
Call-ID, and the replies, `ACK`s and `BYE`s of both. When the 30 seconds are
up, the report lists two dialogs, both `Completed`: the caller's leg, whose
Call-ID SIPp made (`1-...@192.0.2.10`), with 7 messages, and the callee's leg,
whose Call-ID FreeSWITCH made, with 6. FreeSWITCH answers the caller's
`INVITE` with `100 Trying` and the callee does not, which is the seventh
message.

Below them, the `RTP Streams:` table holds the call's audio, all of it to or
from FreeSWITCH:

```text
RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps
--------------------------------------------------------------------------------------------------------------------------
0xdee0ee8f   8    PCMA     8000   192.0.2.10:6000       192.0.2.10:32348      236     0      0.0%    0ms      7s     64
0xeed25cad   0    PCMU     8000   192.0.2.10:25690      127.0.0.1:6000        360     0      0.0%    32ms     8s     54
0xeed25cad   0    PCMU     8000   127.0.0.1:6000        192.0.2.10:25690      360     0      0.0%    32ms     8s     54
0x02d49cad   8    PCMA     8000   192.0.2.10:32348      192.0.2.10:6000       236     0      0.0%    52ms     9s     50
0x0e05384e   101  telephone-event 8000   192.0.2.10:6000       192.0.2.10:32348      10      0      0.0%    6ms      0s     2
```

The caller sends 236 PCMA packets and 10 DTMF (`telephone-event`) packets to
FreeSWITCH, at a port FreeSWITCH chose for the call, and FreeSWITCH sends PCMA
back. On the callee's side the audio is PCMU, both ways: FreeSWITCH converts
between the two codecs. The callee's answer offered no `telephone-event`, so
no DTMF stream goes to the callee. FreeSWITCH chooses new ports for each
call.

## 3. Read one call: timing and audio quality

The capture file holds the whole call. Find the caller's leg, the dialog
whose Call-ID starts with `1-`, as SIPp names its calls, and print sipnab's
report of it:

```bash
# Run all of these, in order.
CALL=$(sipnab -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --json-dialogs --no-cli-print --quiet \
  | jq -r 'select(.call_id | startswith("1-")) | .call_id')
echo "$CALL"
sipnab -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --call-report "$CALL" --no-cli-print --quiet
```

A file you read takes `--portrange` too. The report gives the call's timing,
its SIP transactions, and a line for each of its audio streams, with the jitter,
the packet loss and an estimated MOS (mean opinion score, from 1 to 5) for
each:

```text
Media Streams:
  RTP 192.0.2.10->192.0.2.10 PCMA SSRC=0xdee0ee8f pkts=236 jitter=0ms loss=0.0% mos=4.36 R=90.8
  RTP 192.0.2.10->192.0.2.10 PCMA SSRC=0x02d49cad pkts=236 jitter=52ms loss=0.0% mos=4.33 R=89.5
  RTP 192.0.2.10->192.0.2.10 telephone-event SSRC=0x0e05384e pkts=10 jitter=6ms loss=0.0% mos=unknown (unpublished)
```

The callee's leg's report adds a line FreeSWITCH supplies. FreeSWITCH puts a
`Reason` header in the `BYE` it sends, and sipnab reads it:

```text
Cause:      Q.850 cause 16 "NORMAL_CLEARING" [Reason]
```

## 4. See both legs as one call

FreeSWITCH gives the callee's leg a Call-ID of its own, and its `INVITE`
carries nothing that names the caller's leg: no `Session-ID` header, the one
[RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) defines for that. sipnab
still ties the two together, from their addresses and their start times,
and says so.

**In the terminal interface.** Open the capture:

```bash
sipnab -I /tmp/freeswitch-call.pcap --portrange 5060-5080
```

The call list shows the two dialogs, `Dialogs: 2 shown of 2`. Press `Enter`
on the first to open its ladder, the diagram of its messages between the
caller at `192.0.2.10:5090` and FreeSWITCH at `192.0.2.10:5080`. Press `x`
for the extended flow, `Extended flow: on (multi-leg)`, which adds the
callee's leg and the callee, `127.0.0.1:5070`, as a third column. Press `Esc`
to go back to the call list. There, `Esc` asks `Are you sure you want to
quit?`, and `Y` quits.

**Over the REST API.** sipnab answers HTTP requests about what it captured.
The route `/correlated` names the other legs of a call:

```bash
# Run all of these, in order.
CALL=$(sipnab -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --json-dialogs --no-cli-print --quiet \
  | jq -r 'select(.call_id | startswith("1-")) | .call_id')
export SIPNAB_API_KEY="$(openssl rand -hex 32)"
sipnab -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --api 127.0.0.1:8080 --no-cli-print --quiet &
sleep 2
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" "http://127.0.0.1:8080/v1/dialogs/$CALL/correlated" | jq .
kill %1
```

```json
{
  "schema_version": 1,
  "source_call_id": "1-114198@192.0.2.10",
  "legs": [
    {
      "call_id": "3c33fca7-40b8-1240-48b2-bc24119de73a",
      "score": 50,
      "strategy": "timing_heuristic",
      "identifier_match": false,
      "observed_gap_ms": 2
    }
  ],
  "total_matched": 1,
  "heuristic_only": true
}
```

`timing_heuristic` and `identifier_match: false` say how sipnab matched the
leg: from its addresses and its start, 2 ms after the caller's, not from an
identifier both legs carry. On a busy FreeSWITCH, calls that start close
together can match the same way. The [REST API
reference](rest-api.md) describes the other
strategies.

**Over MCP.** sipnab's [MCP server](mcp.md) answers the same questions for an
AI agent. This takes the caller's leg's Call-ID from sipnab's report, sends
sipnab the messages a client would, and asks the `render_ladder` tool for that
leg as a Mermaid diagram. The `sleep` gives sipnab time to read the whole file
first:

```bash
# Run all of these, in order.
CALL=$(sipnab -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --report --no-cli-print --quiet \
  | awk '$1 ~ /^1-/ {print $1}')
{ printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  sleep 2
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"render_ladder","arguments":{"call_id":"%s","format":"mermaid"}}}\n' "$CALL"
} | sipnab --mcp -N -I /tmp/freeswitch-call.pcap --portrange 5060-5080 --quiet \
  | jq -r 'select(.id == 2) | .result.content[0].text'
```

The answer is a Mermaid `sequenceDiagram` of the caller's leg, from the
`INVITE` to the `200 OK` of the `BYE`, each message with its time from the
first. sipnab fences it as untrusted text taken from the capture, between the
`⟦untrusted-capture-data⟧` lines:

```text
⟦untrusted-capture-data⟧sequenceDiagram
    autonumber
    participant p0 as 192.0.2.10:5090
    participant p1 as 192.0.2.10:5080

    p0->>p1: INVITE
    Note right of p1: +0.000s
    p1-->>p0: 100 Trying
    Note right of p0: +0.001s
    p1-->>p0: 180 Ringing
    Note right of p0: +0.003s · PDD 3ms
    p1-->>p0: 200 OK
    Note right of p0: +0.041s
    p0->>p1: ACK
    Note right of p1: +0.041s
    p0->>p1: BYE
    Note right of p1: +9.047s
    p1-->>p0: 200 OK
    Note right of p0: +9.054s
⟦/untrusted-capture-data⟧
```

`PDD` is the post-dial delay, the time from the `INVITE` to the first ringing
reply. The MCP tool
`find_correlated` returns the same legs as the `/correlated` route.

## 5. Receive FreeSWITCH's own copy of its SIP (HEP)

FreeSWITCH's SIP stack can send a HEP copy of every SIP message it sends and
receives to a collector, such as Homer or sipnab. Then sipnab needs no capture
of the SIP at all. Turn it on for both profiles, sending to `127.0.0.1:9060`
with the capture id `100`:

```bash
# Run all of these, in order.
cd /usr/local/freeswitch/conf
sudo sed -i 's|^    <param name="debug-presence" value="0"/>|&\n    <param name="capture-server" value="udp:127.0.0.1:9060;hep=3;capture_id=100"/>|' autoload_configs/sofia.conf.xml
sudo sed -i 's|<param name="sip-capture" value="no"/>|<param name="sip-capture" value="yes"/>|' sip_profiles/internal.xml sip_profiles/external.xml
grep -h -E '^ *<param name="(capture-server|sip-capture)"' autoload_configs/sofia.conf.xml sip_profiles/internal.xml sip_profiles/external.xml
sudo systemctl restart freeswitch
```

`capture-server` names the collector, the HEP version and the capture id, a
number that tells a collector which sender a copy came from. `sip-capture`
turns the copies on for a profile.

Start sipnab's HEP listener for 30 seconds. `-d any` adds the call's audio
from the wire, which HEP does not carry:

```bash
sudo sipnab -N -L 127.0.0.1:9060 -d any --duration 30 --report --hep-senders
```

While it runs, place the test call from a second terminal, as in step 2.
sipnab prints each message as it arrives, marked `origin=hep`, and the report
lists the same two dialogs, with 7 and 6 messages, and the same five audio
streams. Below them it names the sender:

```text
  SOURCE                                PACKETS  LAST SEEN                    IDLE  STATE
  hep:100@127.0.0.1                          13  2026-10-12T08:18:49.166Z      14s  sending
```

`hep:100` is the `capture_id` from `capture-server`. The capture id is what the
sender claims, and nothing proves it. What keeps other senders out here is the
address: sipnab listens on `127.0.0.1`, which only this machine can reach.

## Without FreeSWITCH

sipnab does not depend on FreeSWITCH. Steps 2 to 4 read SIP and RTP off the
wire or from a capture file, and work the same on any SIP traffic, from any
SIP server or none. Step 5 is the one that needs FreeSWITCH, because
FreeSWITCH sends the HEP. A capture file you take on the FreeSWITCH machine,
such as `/tmp/freeswitch-call.pcap`, works with steps 3 and 4 on any machine
with sipnab installed.

## When something does not work

- **sipnab reports `No SIP signaling found, but ... RTP packets across ...
  stream(s) were parsed`.** It saw the call's audio, but none of its SIP:
  FreeSWITCH's `external` profile is on 5080, outside 5060-5061, the range
  sipnab watches by default. Give sipnab the range with `--portrange
  5060-5080`.
- **Reading a capture file, sipnab warns `SIP outside --portrange 5060-5061 is
  being skipped` and names `Busiest port(s): 5080`, then says `Call-ID '...'
  not found in tracked dialogs`.** The same range applies to a file. Add
  `--portrange 5060-5080` to the command that reads it.
- **The MCP answer ends with `INCOMPLETE RUN — this report does not describe
  the whole capture` and `the capture is still being read`.** The question
  reached sipnab before it had read the whole file. Keep the `sleep` before the
  `tools/call` line, or make it longer for a larger file.
