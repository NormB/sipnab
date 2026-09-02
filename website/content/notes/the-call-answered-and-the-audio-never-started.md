+++
title = "The call answered and the audio never started"
date = 2026-09-01
description = "A 200 OK, an ACK, and then nothing. Half the work is proving your capture point could have seen the media, because sipnab deliberately refuses to call a signaling-only tap a silent call."

[extra]
kind = "howto"
+++

Setup went perfectly. `INVITE`, `100`, `180`, `200 OK`, `ACK`, and then both
parties sat in silence until somebody hung up. The signaling holds no clue,
which is exactly why this one takes longer than a call that failed with a
`503`.

Work it in two halves. The first half asks whether your capture could have
answered the question at all. The second half asks what stopped the media.
Skipping the first half is how a signaling tap gets read as a silent trunk.

## Why sipnab refuses to call it silence

sipnab has a finding for this exact case:

```text
[CRITICAL] No media on an answered call
The call was answered and its SDP asked for RTP that was expected to flow, and
not one packet of it arrived. Neither party heard anything. Check that the
capture point sees the media path at all before reading this as a fault.
```

Now watch it decline to fire. Take a capture that definitely holds media and
read it through a BPF expression that keeps only signaling:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --analyze --no-cli-print 'udp port 5060'
```

```text
No problems found in 2 dialog(s) and 0 stream(s) across 10 frame(s). Every
frame decoded, no port gate discarded SIP, and no retention cap was reached —
so this is a statement about the capture, not only about what sipnab could read
of it.
```

Two answered calls, zero RTP, and no no-media finding. That is deliberate.
sipnab treats "did the capture record any RTP at all" as a property of the RUN
rather than of any one call, because on a signaling-only source — a proxy tap
that never sees the media path, a HEP feed, `--no-rtp` — every answered call
has zero RTP and a per-call flag would describe where you put the tap. The
source comment records the measurement: on one signaling-only corpus capture
the guard is the difference between 338 no-media claims and none.

So the first thing to establish is which kind of capture you are holding.

## First prove the tap sees media at all

```bash
sipnab -N -I capture.pcap --report --no-cli-print
```

The `RTP Streams` table under the call list is the answer. A capture with an
empty stream table cannot tell you anything about audio, whatever its call list
says, and the fix is a capture point rather than a flag. Over MCP the same fact
arrives as `capture_status`, where `stream_count` and `orphaned_stream_count`
sit beside the dialog counts.

Once the stream table has rows, a call with none of its own is evidence about
that call.

## Media on the wire that belongs to no call

The awkward middle case: the tap sees plenty of RTP and none of it attaches to
the dialog you are looking at. That is an orphaned stream, and the useful
question is not "how many" but "why". `reconcile_orphans` answers the second
one with three verdicts:

| verdict | what it means |
|---|---|
| `relay-asserted-but-no-dialog` | a relay named this endpoint and no captured dialog claims it — the signaling is missing, not the media |
| `signaled-but-no-dialog` | SDP named it and no dialog holds it, so either the capture missed the dialog or its SDP arrived before capture started |
| `never-named` | nothing in this capture named this endpoint at all |

Read `relay_was_consulted` beside the verdict. A `never-named` verdict with
`relay_was_consulted: false` means nobody asked, which is an absence of
evidence rather than evidence of absence, and the tool says so in the note it
attaches:

```jsonc
{ "reason": "never-named", "relay_was_consulted": false,
  "note": "nothing in this capture named this endpoint. A relay could answer it and none was asked: that is an absence of evidence, not evidence of absence" }
```

A worked example, because it closes the loop with the section above. The
shipped capture `tests/pcap-samples/codec-negotiation.pcap` reports four
orphans, one finding, and no dialogs at all. The finding is not about the
call:

```text
1. [BLIND] SIP discarded by --portrange — 10 message(s)
   Evidence:
     - port 5080 | messages=10
```

The SIP ran on port 5080, outside the default port gate, so sipnab threw the
signaling away and every stream it decoded had nothing to attach to. Widen the
gate and the whole picture changes at once — `dialog_count` goes from 0 to 1,
`unanalysed_sip_messages` from 10 to 0, and `total_orphans` from 4 to 0:

```bash
sipnab -N -I tests/pcap-samples/codec-negotiation.pcap --portrange 1-65535 --analyze --no-cli-print
```

Four orphaned streams looked like a media problem and were a port-gate problem.
Check `unanalysed_sip_messages` before you believe any orphan count.

## Media that started, but late

Once the dialog and its streams sit together, the next question is timing
rather than presence. RTP that begins well after the `200 OK` clips the front
of the conversation, and to a caller that reads as dead air:

```bash
sipnab -N -I capture.pcap --late-media-ms 500 --analyze --no-cli-print
```

sipnab reports it as `Media started late`, and names the usual source: a media
relay that had not finished setting the path up when signaling completed.
`--filter late-media` selects the same calls for a report, and the MCP surface
takes `late-media` as a `find_problems` alias.

Two hundred milliseconds of late media is a relay doing its job. Two seconds is
a relay that answered the control plane before it had the path. The threshold
belongs to your network, which is why it moves.

## The causes that have a packet behind them

Everything above infers. Three findings state a cause instead, and they are
worth checking early because they end the argument:

- **`ICMP: media undeliverable`** — a router answered a media datagram with an
  ICMP error, so the audio went to a socket nothing was listening on. Check
  that the relay is running and that the port its SDP advertised is the port it
  bound.
- **`Answered INVITE never acknowledged`** — a `2xx` answered the INVITE and no
  ACK confirmed it ([RFC 3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261#section-13.3.1.4)),
  so the far end retransmitted until Timer H and then tore the call down. Audio
  usually stops within seconds of the answer, which matches the complaint
  exactly. `--ack-timeout` sets how long sipnab waits before calling it a fault
  rather than a capture that stopped early — the default is Timer H, 32
  seconds.
- **ICE never nominated a pair** — `--stun` reports a role conflict that never
  resolved, and says which of the two it is:

```text
ROLE CONFLICT 192.0.2.11:50006 <-> 203.0.113.11:16002: both claimed
controlling, 2 x 487 Role Conflict. No pair between them was ever nominated, so
this is a candidate cause of media that never started.
```

ICE resolves an ordinary role conflict by itself, at the cost of one round
trip. The sentence that matters is the second one — a nominated pair means the
conflict cost you nothing, and no nominated pair means the media had nowhere to
go. Two endpoints configured with the same role, or a B2BUA relaying one side's
role attribute to the other, are the usual sources.

## The order, in short

1. Does the stream table have rows? If not, move the tap, not the flags.
2. Does `unanalysed_sip_messages` read zero? If not, widen `--portrange` and
   start over.
3. Do the streams attach to the dialog? If not, ask `reconcile_orphans` why.
4. Did the media arrive late rather than never? Set `--late-media-ms` to what
   your relay should manage.
5. Is there an ICMP error, a missing ACK, or an unresolved role conflict? Those
   name a cause instead of implying one.
