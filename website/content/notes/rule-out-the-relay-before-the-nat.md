+++
title = "Rule out the relay before you blame the NAT"
date = 2026-09-01
description = "One-way audio has four ordinary causes and they look identical in a complaint ticket. The order to eliminate them costs four commands, and the first one rules out the answer everybody reaches for first."

[extra]
kind = "howto"
+++

Somebody called, somebody answered, and one of them heard nothing. The ticket
says NAT, because the ticket always says NAT. Before touching a firewall,
spend four commands ruling out the three cheaper explanations, in an order
that puts the free ones first.

The order matters because each step invalidates the next. A capture sipnab
could not fully read makes every later count a floor. An SDP that asked for
one-directional media makes the whole question moot. A relay that stopped
relaying explains the silence without any NAT taking part.

## Step 0 — find out what the analysis could not see

```bash
sipnab -N -I capture.pcap --analyze --no-cli-print
```

`--analyze` ranks every problem it found, worst first, and puts what it could
NOT read above all of them. A run that hit a port gate says so:

```text
THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The
findings below describe what it UNDERSTOOD, so their counts are floors and the
ABSENCE of a finding is not evidence that the problem is absent. The blind
finding(s) are listed first.

1. [BLIND] SIP discarded by --portrange — 10 message(s)
```

Nothing below that line means anything yet. Widen the gate and read the capture
again before you spend a step on a conclusion the tool already warned you about.

## Step 1 — ask whether the SDP wanted two directions

This is the step people skip, and it is the one that most often ends the
investigation. Here is `--analyze` over `tests/pcap-samples/sip-rtp-g711.pcap`,
a capture that ships with sipnab:

```text
1. [CRITICAL] One-way audio — 2 call(s)
   RTP flowed in one direction only: one party heard the other and was not
   heard back.
   Evidence:
     - rtp_packets=425 streams=1 | carried 425 packet(s); nothing came back
       the other way
```

CRITICAL, two calls, hard numbers. Now read the offer and the answer those
calls actually exchanged. The INVITE carries `a=recvonly` and the `200 OK`
carries `a=sendonly`. Both endpoints agreed on media in one direction, media
went in one direction, and the finding describes the packets correctly while
describing no fault at all.

The finding still earns its place. sipnab compares what crossed the wire
against what the session asked for, and a session that negotiated
one-directional media at setup looks the same on the wire as one a firewall cut
in half. Only the SDP separates them, and the fastest way to read the SDP as a
sequence rather than as two message dumps is the `get_sdp_timeline` MCP tool,
which reports a mode per exchange:

```jsonc
{ "direction": "offer",  "media_addr": "192.0.2.20", "media_port": 6000,  "mode": "recvonly" }
{ "direction": "answer", "media_addr": "192.0.2.15", "media_port": 27942, "mode": "sendonly" }
```

Two `mode` values that do not both say `sendrecv`, and the call behaved as
designed. Stop here.

## Step 2 — ask whether a NAT rewrote anything

Only now does the NAT question earn a command:

```bash
sipnab -N -I capture.pcap --nat-issues --report --no-cli-print
```

`--nat-issues` selects calls whose RTP arrived from an address no SDP in the
dialog advertised, which is the signature of a NAT rewriting the media source.
On the capture above it selects nothing at all — the media arrived from exactly
the address and port the answer advertised. Same capture, same two calls,
CRITICAL under `--one-way` and empty under `--nat-issues`. Those two aliases
disagreeing is information rather than a contradiction: the media went where
the SDP said, and it went one way because the SDP said that too.

An empty `--nat-issues` on a call that really has lost half its audio moves
suspicion off the address rewrite and onto the return path — a pinhole that
opened for the outbound direction and never for the inbound one. That is a
firewall question rather than a NAT-rewrite question, and the two want
different people.

## Step 3 — ask whether a relay sat in the path and stopped

A media relay explains a mid-call silence that no SIP message accounts for,
because the relay's own state expires and SIP never hears about it:

```bash
sipnab -N -I capture.pcap --stun --no-cli-print
```

Two shapes matter. A Binding Request nobody answered means the client never
learned its public address, so whatever it put in its SDP was its private one:

```text
1 transaction(s) drew no response. A client whose Binding Request goes
unanswered never learns its public address, so it advertises the private one in
its SDP — which is what a firewall silently dropping UDP to the STUN port looks
like from the inside.
  192.0.2.10:5060 -> 198.51.100.20:3478: 2 request(s), no reply
  (retransmitted, which by itself proves the first went unanswered)
```

A retransmission is the proof rather than a guess.
[RFC 5389 §7.2.1](https://www.rfc-editor.org/rfc/rfc5389#section-7.2.1)
retransmits a Binding Request only on timeout, so a second copy on the wire
means the first one drew silence.

The other shape is a TURN allocation that outlived the lifetime its server last
granted:

```text
1 allocation(s) were still carrying traffic after the lifetime they were last
granted had run out, with no Refresh seen in between.
  192.0.2.10:50000 -> 198.51.100.20:3478: 60s lifetime, 0 refresh(es) seen,
  traffic continued 1s past expiry
```

The server tears that allocation down when the lifetime lapses and the relayed
media stops with it, mid-call, with nothing in the signaling to say why. If
your one-way complaint arrives with "it was fine for the first minute", read
this section before anything else.

## Step 4 — ask whether comfort noise explains it

A trunk running aggressive voice-activity detection sends comfort noise instead
of speech during silence, and a stream that is mostly comfort noise proves
nobody lost the far end. sipnab stops reporting the one-way finding once comfort
noise passes a share of the call's packets:

```bash
sipnab -N -I capture.pcap --cn-suppression-ratio 0.5 --analyze --no-cli-print
```

The default is 0.3, and it is the one threshold in the tool whose failure mode
is silence rather than noise. A VoLTE or mobile trunk routinely passes 30 %
comfort noise, and above the ratio sipnab never reports one-way audio on that
trunk again. Raise it toward 1 where the trunk genuinely behaves that way.
Lower it where any comfort noise at all should still leave the call
bidirectional.

## The last suspect

Codec, and it comes last for a reason: a codec mismatch usually produces no
media or a `488`, not half of it. Check it with `check_codec_negotiation`,
which reports `offered`, `answered` and `common` as three separate lists, so an
empty `common` leaves nothing to argue about. A one-way call whose `common`
list holds a codec both ends implemented is not a codec problem, whatever the
vendor says.

The order above costs four commands and about a minute. Keep to it because
steps 1 and 3 both produce a clean, defensible "not a fault" and "not your
firewall", and both of them come before the step that would have had somebody
opening ports.
