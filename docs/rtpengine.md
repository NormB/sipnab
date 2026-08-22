# Attribute media on an rtpengine relay

You installed sipnab on a media relay, ran a capture, and got a screen full of
orphaned RTP streams. Every packet is there and none of it says which call it
belongs to. This page fixes that.

**The short version.** A standalone relay carries no SIP, so a capture there
has media and nothing to name it with. rtpengine knows the name — its `ng`
control protocol carries the Call-ID and the ports it allocated — and it can
already mirror that control plane to a Homer collector. sipnab reads that
mirror and ties the media to the call.

## The problem, on a real capture

Both runs below read the same forty RTP packets on the same four sockets. The
only difference is whether the six control-plane packets are in the file.

Without the control plane, everything orphans:

```text
Orphaned Streams:
SSRC         Source                   Destination              Pkts     Duration
--------------------------------------------------------------------------------
0x0a0a0a0a   10.0.0.60:40001          10.0.0.40:38156          10       0s
0x0b0b0b0b   10.0.0.60:40002          10.0.0.40:38664          10       0s
0x0a0a0a0a   10.0.0.40:38664          10.0.0.60:40002          10       0s
0x0b0b0b0b   10.0.0.40:38156          10.0.0.60:40001          10       0s
```

With it, the same media resolves to one call — and gains a codec, because the
control plane carries the SDP too:

```text
RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts
----------------------------------------------------------------------------------
0x0a0a0a0a   0    PCMU     8000   10.0.0.60:40001       10.0.0.40:38156       10
0x0b0b0b0b   0    PCMU     8000   10.0.0.60:40002       10.0.0.40:38664       10
0x0a0a0a0a   0    PCMU     8000   10.0.0.40:38664       10.0.0.60:40002       10
0x0b0b0b0b   0    PCMU     8000   10.0.0.40:38156       10.0.0.60:40001       10

Calls named by a media relay (no SIP for them in this capture):
Call-ID                                                      Streams
---------------------------------------------------------------------
km-670bd208@sipnab                                           4
```

Reproduce both from the committed fixtures:

Without the control plane, every stream orphans:

```sh
sipnab -N -I tests/fixtures/rtpengine-media-only.pcap --report
```

With it, the same media resolves to one call:

```sh
sipnab -N -I tests/fixtures/rtpengine-ng-hep.pcap --report
```

Four streams and not two: the relay holds its own socket per leg, plus the far
party's on the other side of each. All four belong to one call.

## Which method fits your deployment?

Read down the first column and stop at the first row you can satisfy.

| Your situation | Use | Changes rtpengine? | Notes |
|---|---|---|---|
| rtpengine already reports to a Homer collector | Capture on the relay host | **No** | sipnab reads the copy already on the wire. Nothing about your Homer pipeline changes. |
| rtpengine reports nowhere yet | Turn on `--homer-enable-ng`, point it anywhere sipnab can see | Yes, once | The destination can be a collector, or a host that discards the traffic |
| You need it delivered rather than sniffed | `--hep-listen` on sipnab, point rtpengine at it | Yes | Costs you the collector — see the warning below |

**rtpengine takes exactly one Homer destination.** `--homer` is a single
value, not a repeatable option, so "send to the real collector and to sipnab"
does not exist. Anything that points rtpengine at sipnab takes it away from
the collector it feeds. That is why sipnab reads the traffic off the wire by
default: a diagnostic tool has no business in a production data path, and if
sipnab stops, nothing else notices.

## Set it up

### If rtpengine already reports to Homer

Nothing to configure. Capture on the relay host and sipnab decodes the
control plane it sees:

```sh
sudo sipnab -i eth0
```

Confirm rtpengine is mirroring the control plane and not only RTCP stats:

```sh
grep -E '^homer' /etc/rtpengine/rtpengine.conf
```

You want `homer-enable-ng = true` in that output. Without it rtpengine sends
RTCP statistics only, which carry no Call-ID and no SDP.

### If it reports nowhere yet

Add these to the `[rtpengine]` section of `/etc/rtpengine/rtpengine.conf`:

```ini
homer = 10.0.0.60:9060
homer-protocol = udp
homer-id = 2001
homer-enable-ng = true
```

Then restart it:

```sh
sudo systemctl restart rtpengine
```

`homer-id` becomes the per-node key when you correlate several nodes, so give
each relay a distinct one.

## Verify it works

Place one call through the relay, then check that sipnab saw control traffic:

```sh
sudo sipnab -i eth0 --report
```

A working setup names the call under **Calls named by a media relay**. If it
does not, work down this list:

| Symptom | Cause | Fix |
|---|---|---|
| No relay-named calls, streams still orphaned | rtpengine sends RTCP stats only | Set `homer-enable-ng = true` and restart |
| Nothing at all on the wire | rtpengine has no `homer` destination | Set one |
| Control traffic visible, streams still orphaned | Capture missed the HEP, or a filter excluded it | Widen the filter; the default filter excludes media |
| Relay-named calls appear but media does not | The media is on ports your filter drops | Include the `port-min`–`port-max` range |

## What rtpengine's forwarding mode changes

Nothing, and a measurement says so rather than an assumption.

rtpengine forwards either in userspace or, with `table = N` and the
`xt_RTPENGINE` kernel module, inside netfilter. If kernel-forwarded media were
invisible to a capture, attributing it would be pointless — so this run
checked it against rtpengine 12.5.1, with the module confirmed active and
accounting the packets itself:

```text
/proc/rtpengine/0/list   local 10.0.0.40:34232   250 packets   [kernel-forwarded]
                         output → 10.0.0.60:40001              250 packets
capture on the relay     ingress 500/500         egress 500/500
```

Both directions stay fully visible in both modes. The reason is structural: a
capture's receive tap runs before netfilter, and the module re-injects through
the normal transmit path, which passes the transmit tap. You do not have to
know or care which mode a relay runs in.

## What this does not do

Stated here rather than discovered later.

- **It does not tie the two halves of a B2BUA call together.** A B2BUA gives
  one call two Call-IDs. The control plane names each leg's media and ties
  neither to the other.
- **It does not read DTLS-SRTP media.** rtpengine terminates DTLS and emits no
  key log, so on a WebRTC-facing relay the payload stays unreadable.
- **It does not attribute recording or forking streams.** Those commands
  create media that belongs to the call without being one of its two legs, and
  counting one as an ordinary leg would turn a two-party call into a
  three-stream one. sipnab counts them and says so instead.
- **It does not name a call that started before the capture did.** A control
  message that already happened never reaches the wire, so sipnab cannot read
  it. Asking rtpengine directly closes that gap, and RE4 tracks that work.

## Where this is going: the next phase

**None of this section describes what sipnab does today.** What this page
documents above is one hop naming its own media, proven against a recorded
capture. This section states what that foundation exists FOR, so the next
phase aims at a goal rather than at whatever comes next.

The goal is a call that crosses an SBC, a proxy, an rtpengine and a PBX,
assembled end to end, so that an operator can ask a question in their own
words and an agent answers with evidence from every hop the call touched.

Naming media on the relay is the hop that was missing, because it is the only
hop that carries no SIP of its own. Once each hop can name a call, an agent
can filter to a customer — by caller, callee, trunk, address, or time window —
and pull the whole call rather than one machine's view of it.

These are the questions that arrive, and what answering each one takes.

| The customer says | The question really is | What the answer needs |
|---|---|---|
| "Our calls sound bad" | Where in the path did the media degrade? | Per-hop loss, jitter and MOS on the SAME call, so a good leg and a bad leg separate cleanly |
| "Calls are not completing" | Which hop rejected it, and what did it say? | The final response and its origin hop, plus whether media was ever negotiated |
| "Calls drop after a while" | Who tore it down, and on what clock? | The BYE or the timeout, and which side sent it |
| "We hear them, they can't hear us" | Which direction is missing, and from where? | Both directions of media at each hop, not just a packet count |
| "It only fails for one carrier" | What is different about that path? | The same call shape across two trunks, compared |

### "Our calls sound bad"

The hard part is not measuring quality, it is locating it. A relay reporting
2% loss tells you nothing on its own — the question is whether the loss was
already there when the media arrived, or appeared on the way out.

That needs the same call measured on both sides of each hop, which needs each
hop to agree on the call's name. On the relay that agreement is what
this page adds. The analysis then reads as a chain: clean into the SBC, clean
into the relay, lossy out of the relay, and now the fault has an address
rather than a symptom.

Watch for the answer being "neither hop": identical loss at every hop points
at the access network, and a codec that changes between hops points at
transcoding rather than at the network.

### "Calls are not completing"

Same filter, different evidence. Here the media is usually absent rather than
degraded, so the question moves to signaling — and to the gap between them.

The failure modes separate cleanly once you can see every hop at once:

- **A final response from an upstream hop**, which names the rejecter. The
  response class matters: a 4xx is the far end declining, a 5xx is a server
  failing, a 6xx is a global refusal, and they lead to different owners.
- **No response at all**, which is a timeout, and the hop that stopped
  answering is the one to look at.
- **A call answered with no media**, which is a negotiation failure rather
  than a routing one — the signaling succeeded and the SDP did not.
- **A relay with no ports left**, which looks like a random failure from the
  proxy's side and is obvious from the relay's.

The last two are exactly the cases a signaling-only view gets wrong, because
from the proxy the call looks answered.

### "Calls drop after a while"

A drop has a clock attached, and the clock identifies the cause. A tear-down
at a round number is a timer — a session timer, a NAT binding, a relay's own
media timeout. A tear-down when media stopped is the media stopping. Reading
the relay's teardown against the proxy's BYE says which came first, which is
the whole question.

### "We hear them, they can't hear us"

One-way audio is a direction problem, and a relay is where directions become
visible: it holds both parties' sockets, so a leg with media arriving and
nothing leaving is plainly asymmetric. The value of naming the call is being
able to say WHICH call is asymmetric on a box carrying hundreds.

### "It only fails for one carrier"

The comparison case. Two calls of the same shape down two trunks, assembled
the same way, differing in one hop's behavior. Hard to do by hand across
machines and straightforward once every hop names its calls the same way.

## See also

- [Encapsulations](encapsulations.md) — HEP and the other wrappers sipnab reads
- [Capture SIP over TLS](tls-capture.md) — when encryption hides the signaling
- [MCP tools](mcp-tools.md) — the agent-facing surface over these results
