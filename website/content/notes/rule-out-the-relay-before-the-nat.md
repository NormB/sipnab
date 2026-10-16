+++
title = "Diagnose one-way audio in the order sipnab ranks the causes"
date = 2026-09-01
updated = 2026-10-16
description = "Steps to work through a one-way audio complaint with sipnab: what the capture missed, network error reports, NAT, STUN and TURN relays, and finally a call set up to send audio one way."

[extra]
kind = "howto"
+++

## In short

"One-way audio" means one person on a call can hear the other. The other
person cannot hear them. Several different faults cause it:

- a network device rejecting the audio,
- an address rewritten by a router,
- a relay server that stopped forwarding,
- a call set up to carry audio in one direction only.

sipnab's `--analyze` report lists the problems it finds in a recorded call.
The most serious come first. This how-to follows that order. It is also the
order of the troubleshooting guide.

## Who this is for

Anyone handling a one-way audio complaint who has a packet capture (pcap file)
of the call.

## Know the order of the checks

Work through the causes in this order:

- **What sipnab could not read.**
  - `--analyze` lists these `BLIND` findings above every other finding.
- **ICMP errors against the audio.**
  - An ICMP error is a message a router or host sends back when it cannot
    deliver a packet.
  - `--analyze` rates `ICMP: media undeliverable` as critical.
- **NAT.**
  - NAT (network address translation) is the router function that rewrites
    private addresses into public ones.
  - `--analyze` rates `RTP source no SDP advertised` as major.
- **STUN and TURN.**
  - STUN lets a phone learn its public address.
  - TURN relays audio through a server.
  - `--analyze` rates an unanswered STUN request and a lapsed TURN allocation
    as major. It rates an SDP address that STUN contradicts as critical.
- **The call's own setup, comfort noise and codecs.**
  - The one-way finding rests only on the audio packets seen in each
    direction.
  - It does not read the audio direction the call's SDP asked for.
  - So a call set up to send audio one way is also reported as one-way audio.

Within one severity level, `--analyze` lists first the finding that occurred
most often.

The captures used below ship in the sipnab repository.

- `-q` hides informational log lines.
- `--no-cli-print` suppresses the per-message output.
- The output below has the trailing spaces at the ends of table lines
  removed.

## Steps

- Run the analysis and read it from the top:

```bash
sipnab -N -q -I tests/fixtures/stun_sdp_mismatch.pcap --analyze --no-cli-print
```

```text
Capture analysis: 4 finding(s) across 1 dialog(s), 2 stream(s), 69 frame(s) read.

1. [CRITICAL] One-way audio — 1 call(s)
   RTP flowed in one direction only: one party heard the other and was not heard back. The usual causes are a NAT that never opened the return pinhole, an SDP advertising an address the far end cannot route to, or a firewall dropping inbound media.
   Evidence:
     - Call-ID stun-sdp-mismatch-1@192.168.10.50 | 192.168.10.50:5060 -> 198.51.100.30, SDP 198.51.100.30, RTP from 203.0.113.7 | 2023-11-14 22:13:21.000 UTC | rtp_packets=60 streams=2 | 203.0.113.7:41000 -> 192.168.10.50:40000 carried 30 packet(s); nothing came back the other way

2. [CRITICAL] SDP advertises an address STUN contradicts — 1 call(s)
   The client's SDP names an address that STUN is on record either replacing with a different, reachable one, allocating on a TURN relay, or never answering about at all: the far end is sending media to an address that cannot receive it. Where the STUN exchange and the call coincide this is the cause of one-way audio rather than an inference from it; evidence seen well outside the call is matched by client IP alone and says so in its notes.
   Evidence:
     - Call-ID stun-sdp-mismatch-1@192.168.10.50 | 192.168.10.50:5060 -> 198.51.100.30, STUN client 192.168.10.50:5060, SDP advertises 192.168.10.50 | 2023-11-14 22:13:21.000 UTC | stun_requests=2 | 2 request(s) drew no STUN response, so the client never learned a public address and advertised 192.168.10.50

3. [MAJOR] RTP source no SDP advertised — 1 call(s)
   Media arrived from an address that no SDP in the dialog named — the signature of a NAT rewriting the media source. Frequently benign on its own (symmetric RTP through a NAT looks exactly like this); read it together with any one-way audio on the same call.
   Evidence:
     - Call-ID stun-sdp-mismatch-1@192.168.10.50 | 192.168.10.50:5060 -> 198.51.100.30, SDP 198.51.100.30, RTP from 203.0.113.7 | 2023-11-14 22:13:21.000 UTC | rtp_packets=60 streams=2

4. [MAJOR] STUN Binding Request unanswered — 1 transaction(s)
   A client asked a STUN server what its public address was and nothing came back, so it never learned one and will advertise its private address in any SDP it later sends. RFC 5389 §7.2.1 retransmits only on timeout, so a repeated request is itself proof the earlier ones drew silence.
   Evidence:
     - client 192.168.10.50:5060, server 198.51.100.20:3478 | 2023-11-14 22:13:20.000 UTC | requests=2 | retransmitted, which by itself proves the first request went unanswered
```

  On this capture all four findings concern one call:

  - The phone's STUN requests got no answer (finding 4).
  - So it put its private address 192.168.10.50 in its SDP (finding 2).
  - Its audio reached the far side from a different address (finding 3).

- If the report starts with a BLIND finding, fix the capture or the options
  before reading anything else.
  - Every count below it is a lower bound.
  - This run deliberately restricts the SIP ports to 5070 on a capture whose
    SIP uses 5060.
  - `2>/dev/null` discards two warning lines that repeat the same fact:

```bash
sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --analyze --no-cli-print --portrange 5070-5070 2>/dev/null
```

```text
Capture analysis: 1 finding(s) across 0 dialog(s), 0 stream(s), 852 frame(s) read.

THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The findings below describe what it UNDERSTOOD, so their counts are floors and the ABSENCE of a finding is not evidence that the problem is absent. The blind finding(s) are listed first.

1. [BLIND] SIP discarded by --portrange — 10 message(s)
   sipnab recognized these as SIP and then threw them away because neither port was inside --portrange. They are in no dialog and no count. Widen the range (--portrange 1-65535 analyzes everything) and read the capture again.
   Evidence:
     - port 5060 | messages=10
```

- Look for an ICMP finding against the audio.
  - None of the captures in the repository contains one. So this step shows no
    output.
  - The troubleshooting guide's section "First: check whether the network
    already answered" shows what sipnab prints.
  - Such a finding names the address and port that rejected the audio. It also
    names the device that reported it.

- Check NAT. `--nat-issues` selects calls whose audio arrived from an address
  that no SDP in the call advertised:

```bash
sipnab -N -q -I tests/fixtures/stun_sdp_mismatch.pcap --nat-issues --report --no-cli-print
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
stun-sdp-mismatch-1@192.168...   alice          bob            Completed    200    7s         7      0.2s     -

RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps
--------------------------------------------------------------------------------------------------------------------------
0x11223344   0    PCMU     8000   192.168.10.50:40000   198.51.100.30:41000   30      0      0.0%    0ms      1s     66
0x55667788   0    PCMU     8000   203.0.113.7:41000     192.168.10.50:40000   30      0      0.0%    0ms      1s     66
```

  A NAT match on its own can be normal. Read it together with a one-way
  finding on the same call. Finding 3 in the first step says this.

- Check STUN and TURN.
  - Unanswered STUN requests already appear in the analysis (first step, finding 4).
  - For a call that went silent partway through, check whether a TURN relay
    allocation expired.
  - A TURN server grants an allocation for a lifetime.
  - It removes the allocation if the phone does not renew (Refresh) it in time.
  - That stops the relayed audio with no SIP message:

```bash
sipnab -N -q -I tests/fixtures/turn_relay.pcap --stun --no-cli-print
```

```text
STUN Transactions (7 packet(s), 3 transaction(s)):
Transaction              Method           Client                 Server                 Reqs  Response       RTT       Mapped Address         Relayed Address
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
2b3c4d5e6f708192a3b4c5d6 Allocate         192.0.2.10:50000       198.51.100.20:3478     1     success        12.0ms    203.0.113.5:12262      198.51.100.77:49160
112233445566778899aabbcc CreatePermission 192.0.2.10:50000       198.51.100.20:3478     1     success        8.0ms     -                      -
0102030405060708090a0b0c ChannelBind      192.0.2.10:50000       198.51.100.20:3478     1     success        8.0ms     -                      -

TURN Allocations (1):
Client                 Server                 Relayed Address        Lifetime  Refreshes  Status
---------------------------------------------------------------------------------------------------
192.0.2.10:50000       198.51.100.20:3478     198.51.100.77:49160    60s       0          LAPSED
152 relayed ChannelData frame(s), 25864 byte(s) of application data, crossed these allocations. Those bytes are also analyzed as ordinary media: the frame is unwrapped and the RTP inside it reaches the stream store, so a relayed call appears in the stream list rather than as a call with no media.
  192.0.2.10:50000 -> 198.51.100.20:3478: 152 frame(s) on channel 0x4001, carrying 2 stream(s) (SSRC 0x11223344, 0x55667788)
    channel 0x4001 is bound to peer 203.0.113.9:16000

1 allocation(s) were still carrying traffic after the lifetime they were last granted had run out, with no Refresh seen in between. A TURN server tears an allocation down when its lifetime lapses, and the relayed media stops with it — mid-call, with no SIP message to say why.
  192.0.2.10:50000 -> 198.51.100.20:3478: 60s lifetime, 0 refresh(es) seen, traffic continued 1s past expiry
    media on it: 152 frame(s) on channel 0x4001, carrying 2 stream(s) (SSRC 0x11223344, 0x55667788)
```

  `LAPSED` marks the allocation that ran past its lifetime. sipnab reports
  that it saw no Refresh. That can also mean the capture missed it.

- If none of the above applies, check whether the endpoints set the call up
  to send audio one way. `tests/pcap-samples/sip-rtp-g711.pcap` holds two calls
  that `--analyze` reports as one-way audio:

```bash
sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --analyze --no-cli-print
```

```text
Capture analysis: 1 finding(s) across 2 dialog(s), 2 stream(s), 852 frame(s) read.

1. [CRITICAL] One-way audio — 2 call(s)
   RTP flowed in one direction only: one party heard the other and was not heard back. The usual causes are a NAT that never opened the return pinhole, an SDP advertising an address the far end cannot route to, or a firewall dropping inbound media.
   Evidence:
     - Call-ID 1-1966@10.0.2.20 | 10.0.2.20:5060 -> 10.0.2.15, SDP 10.0.2.20 | 2016-11-26 14:52:59.666 UTC | rtp_packets=425 streams=1 | 10.0.2.15:27942 -> 10.0.2.20:6000 carried 425 packet(s); nothing came back the other way
     - Call-ID 1-1968@10.0.2.20 | 10.0.2.20:5060 -> 10.0.2.15, SDP 10.0.2.20 | 2016-11-26 14:53:08.286 UTC | rtp_packets=414 streams=1 | 10.0.2.15:28102 -> 10.0.2.20:6000 carried 414 packet(s); nothing came back the other way
```

  `--nat-issues` selects neither call on this capture. Select the one-way
  calls whose SIP messages contain an SDP direction other than `sendrecv`
  (two-way):

```bash
sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --filter "one_way == true AND payload =~ 'a=(sendonly|recvonly|inactive)'" --report --no-cli-print
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

  In both calls:

  - The INVITE's SDP carries `a=recvonly`.
  - The `200 OK`'s SDP carries `a=sendonly`.
  - Both ends agreed that audio flows one way, and it did.

  The MCP tool `get_sdp_timeline` shows the same thing per offer and answer.
  On call `1-1966@10.0.2.20` it shows `"mode":"recvonly"` for the offer and
  `"mode":"sendonly"` for the answer.

  The `payload` field matches any message in the call. So a call put on hold
  with a re-INVITE also matches this filter. Read the matching messages before
  concluding.

- Check comfort noise and codecs last.
  - Some trunks send comfort noise (generated background noise) instead of
    audio during silence.
    - sipnab does not report one-way audio when comfort noise exceeds a share
      of a call's packets.
    - `--cn-suppression-ratio` sets that share. The default is 0.3.
    - Raising it can hide real one-way calls. Lowering it reports more.
    - `sip-rtp-g711.pcap` carries no comfort noise. On it,
      `--cn-suppression-ratio 0.5` produces output identical to the previous
      step.
  - The MCP tool `check_codec_negotiation` lists the codecs `offered`,
    `answered` and `common` to both.
    - For call `1-1966@10.0.2.20`, `common` holds PCMU.
    - So the two ends shared a codec.

## Terms used here

- **SIP**: the protocol that sets up, changes and ends phone calls over IP.
- **SDP**: the part of a SIP message that describes the audio: address, port,
  codecs and direction (`sendrecv`, `sendonly`, `recvonly`, `inactive`).
- **Offer / answer**: the SDP one side proposes and the SDP the other side
  replies with; in the captures above, the INVITE and the `200 OK`.
- **RTP**: the protocol that carries the audio packets.
- **Stream**: the RTP packets sent in one direction, identified by an SSRC
  number.
- **Dialog**: one SIP conversation, such as one call.
- **pcap**: a file format for recorded network traffic.
- **ICMP error**: a message a router or host sends back when it cannot deliver
  a packet.
- **NAT**: network address translation, which rewrites private addresses into
  public ones at a router.
- **STUN**: a protocol a phone uses to ask a server which public address it
  appears from.
- **TURN**: a protocol for relaying audio through a server; an allocation is
  the relay address the server grants for a limited lifetime.
- **Comfort noise**: low-level generated noise sent instead of audio during
  silence.
- **Codec**: the audio encoding, such as PCMU (G.711 µ-law).
- **MCP**: Model Context Protocol, the interface AI assistants use to call
  sipnab's tools.

## Related guides

- [Troubleshooting: one-way audio](@/docs/troubleshooting.md#one-way-audio)
- [First: check whether the network already answered](@/docs/troubleshooting.md#first-check-whether-the-network-already-answered)
- [NAT traversal issues](@/docs/troubleshooting.md#nat-traversal-issues)
- [NAT discovery went unanswered](@/docs/troubleshooting.md#nat-discovery-went-unanswered)
- [A relayed call that went quiet halfway through](@/docs/troubleshooting.md#a-relayed-call-that-went-quiet-halfway-through)
- Cookbook [4. Diagnose a one-way audio complaint](@/docs/cookbook.md#diagnose-a-one-way-audio-complaint)
  and [45. Check whether comfort noise explains a one-way finding](@/docs/cookbook.md#check-whether-comfort-noise-explains-a-one-way-finding)
- [STUN / TURN JSON (`--json-stun`)](@/docs/output-formats.md#stun-turn-json-json-stun)
- [`get_sdp_timeline`](@/docs/mcp-tools-signaling.md#get-sdp-timeline) and
  [`check_codec_negotiation`](@/docs/mcp-tools-signaling.md#check-codec-negotiation)
