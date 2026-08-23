# The rtpengine control plane

How sipnab names media it captures on a standalone relay, why this delivery
path won, and which decisions here are load-bearing.

Read [Attribute media on an rtpengine relay](../rtpengine.md) first if you
want the operator's view. This page is about the code.

## The problem this solves

A media relay carries no SIP. sipnab installed on one sees two sockets of RTP
per call and nothing that names the call, so `RtpStream::orphaned` is true for
every stream in the capture. The output is accurate and useless — the same
shape as the NAT case the codebase already names: an operator can see that
media exists, how much, and how badly it performs, and cannot say which call
any of it belongs to.

The name is on the box. rtpengine's `ng` control protocol carries the Call-ID
and the ports the relay allocated, and that pair is the join key.

## Wire format

An `ng` message is a cookie, one space, and a bencoded dictionary:

```text
14661e9e...  d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp122:v=0...e
```

Three properties matter to the parser, all confirmed against rtpengine 12.5.1
rather than taken from documentation:

**Dictionary keys arrive unsorted.** The bencode specification requires
lexicographic order and rtpengine does not produce it — a live `offer` arrives
as `command`, `call-id`, `from-tag`, `sdp`. A decoder that enforced the rule,
or that binary-searched keys, would fail on every real message.
`bencode::Value::Dict` therefore keeps arrival order and looks up by scan.

**Replies carry no `call-id`.** An `offer` reply's entire body is
`d3:sdp136:v=0...e`. This is the single most consequential fact about the
protocol for our purposes, because the reply is the half that carries the
relay's OWN allocated ports.

**The cookie is a retransmission key, and rtpengine deduplicates on it.** A
repeated cookie gets a cached reply instead of reprocessing. Anything that
SENDS `ng` must generate a fresh cookie per transaction. Reusing one returns
port allocations belonging to a call rtpengine may already have deleted. This
cost one wrong measurement during development, until rtpengine's own log —
`Detected command from 127.0.0.1 as a duplicate` — explained it.

## Why HEP, and not a sniffer on the ng socket

Sniffing `ng` off its own socket needs no configuration anywhere, which is a
real advantage. It also needs, because of the reply asymmetry above, a
cookie-to-call transaction map to tie a reply back to the request that named
the call. Around that it needs UDP, TCP, HTTP and WebSocket handling, plus a
UNIX socket it cannot capture at all, plus fragment reassembly for an offer
carrying ICE candidates over an MTU-sized path.

Over HEP every one of those disappears. rtpengine's `--homer-enable-ng`
mirrors the exact wire bytes of every message in both directions and puts the
Call-ID in the HEP correlation-id chunk — on requests and replies alike. The
tie arrives with the message, so there is no transaction state to keep, one
transport instead of four, and no fragment problem.

Decoded from the committed fixture, every packet carries it:

```text
HEP #1 capture-proto=0x3d correlation-id='km-670bd208@sipnab'  d7:command5:offer...
HEP #2 capture-proto=0x3d correlation-id='km-670bd208@sipnab'  d3:sdp136:v=0...   <- reply
```

The passive sniffer stays on the roadmap as a second delivery path behind the
same decoder, not as a separate feature.

## Why the wire, and not our own listener

sipnab could receive on `--hep-listen` and have rtpengine send to it. That
works today with no new parsing at all, and it is the wrong default.

`--homer` is a single `G_OPTION_ARG_STRING`, not a repeatable option, so
rtpengine has exactly ONE Homer destination. Pointing it at sipnab takes it
away from the collector it already feeds. Reading the copy already on the wire
needs no configuration change and leaves that pipeline untouched — and if
sipnab stops, nothing downstream notices. A diagnostic tool does not belong in
a production data path.

Relay mode (`--hep-listen` plus `--hep-send`) stays documented as a fallback
with that cost stated.

## Module layout

| File | Holds |
|---|---|
| [`src/rtpengine/bencode.rs`](../../src/rtpengine/bencode.rs) | Bencode decoder. Borrowed values, depth-limited, hostile-input facing |
| [`src/rtpengine/ng.rs`](../../src/rtpengine/ng.rs) | Cookie/body split, command classification, field extraction |
| [`src/rtpengine/control.rs`](../../src/rtpengine/control.rs) | The two read-only requests, their replies, and the client that carries them |
| [`src/rtpengine/reconcile.rs`](../../src/rtpengine/reconcile.rs) | The two moments sipnab asks, the port index, and the bounds that keep asking from becoming polling |
| [`src/rtpengine/mod.rs`](../../src/rtpengine/mod.rs) | `sdp_links_from_ng`, the bridge into the existing SDP linking |

The decoder is hostile-input facing on both delivery paths, so every length is
bounds-checked before use, `bencode::MAX_DEPTH` bounds the recursion, and
anything malformed is an error rather than a partial value. A truncated
dictionary is not a dictionary with fewer keys. The decoder rejects duplicate
keys rather than resolving them, because last-wins and first-wins are both
silent and a
message with two `call-id` keys names no call with confidence.

[`fuzz/fuzz_targets/rtpengine_ng.rs`](../../fuzz/fuzz_targets/rtpengine_ng.rs) drives the decoder, the message layer and
`sdp_links_from_ng`, the last with the correlation-id both present and absent.

## Where it joins the existing machinery

`sdp_links_from_ng` returns the same `(IpAddr, u16, String, SdpMedia)` tuples
`extract_sdp_links` returns for a SIP body, so no new linking machinery
exists. The call-id comes from the message body when it has one and from the
correlation-id otherwise — preferring the body means a passive wire capture,
which has no correlation-id, still works for the request half.

### `PacketAction::RelayControl`

Classification returns a new variant rather than reusing `Sip`. That is
deliberate: sipnab observed no SIP message, and synthesizing one to reuse the
variant would put signaling into the dialog store that nobody sent, in a tool
whose whole value is saying what it actually saw.

The variant also pays for itself structurally. This codebase's most-named
defect class is a change that reaches some packet appliers and not the others,
and adding an enum variant makes the compiler name every one of them. It found
six: the live router, the `--cores` shard, the batch path, the TUI's
file-open, and two test harnesses that mirror them
([`tests/rtp_quality_provenance_test.rs`](../../tests/rtp_quality_provenance_test.rs), [`tests/corpus_lint_test.rs`](../../tests/corpus_lint_test.rs)). The
behavior itself lives once, in
[`pipeline::apply_relay_control_links`](../../src/pipeline.rs), so the six
call sites cannot drift apart.

### `EndpointAssertion`, and why it is not a fourth `InputOrigin`

An `ng` endpoint is the relay asserting a port it allocated itself. That is
not the same claim as an endpoint parsed from an SDP body on the wire, and the
difference has to survive into provenance.

It is a field on `SdpProvenance` rather than a fourth `InputOrigin` variant
because the two are independent axes. `InputOrigin` is a TRANSPORT fact — the
bytes arrived on the wire, over HEP, or out of a process. `EndpointAssertion`
is a fact about the CLAIM. They cross freely: a relay's assertion arrives over
HEP today and would arrive off the wire through the same decoder tomorrow, and
ordinary signaling arrives over every origin there is. A fourth `InputOrigin`
would have forced every match on transport to handle a value that is not about
transport.

`RtpStream::dialog_assertion` carries it onward, written in the same breath as
`dialog_origin` so the two can never describe different bindings.

## The report surface, and a bug worth remembering

The report gains a section naming calls a relay attributed whose SIP is not in
the capture. It has to exist: once attributed, those streams correctly leave
the orphan table, and without the new section their Call-ID would then appear
nowhere at all — a worse answer than the orphan row it replaced.

The first version keyed on "this stream has a Call-ID that no dialog in this
report matches". That is wrong, and the way it is wrong is instructive: it is
also exactly what `--limit 1` produces — one dialog kept, and streams still
pointing at the calls the run dropped. Ordinary SIP signaling named those
streams, so reporting them as relay-named gave a confident wrong answer about
where the name came from.

It now keys on `RtpStream::dialog_bound_from_relay`, which reads recorded
provenance. `limit_caps_tracked_dialogs` caught the original within one gate
run, and `a_dialog_dropped_by_limit_is_not_reported_as_relay_named` keeps it
caught.

## Proving the claim

[`tests/fixtures/rtpengine-ng-hep.pcap`](../../tests/fixtures/rtpengine-ng-hep.pcap) is a live capture, not a construction:
rtpengine 12.5.1 with `--homer-enable-ng`, six HEP packets covering
offer/answer/delete with their replies, and forty relayed RTP packets on the
four sockets those commands allocated.

Two properties make it discriminating rather than merely convenient, and
[`tests/rtpengine_ng_test.rs`](../../tests/rtpengine_ng_test.rs) asserts both instead of describing them:

- **It contains no SIP whatsoever.** If these streams end up attributed, the
  attribution can only have come from the control plane, because there is no
  other source of a Call-ID in the file.
- **The HEP targets a third party.** The relay reports to a collector
  at another address and sipnab is a bystander, which is the RE6 deployment.

[`tests/fixtures/rtpengine-media-only.pcap`](../../tests/fixtures/rtpengine-media-only.pcap) is the same capture with the six
HEP packets removed and nothing else changed. It is the control case: strip
the control plane and every stream returns to being an orphan with no codec
and no call. Without a paired negative, "sipnab attributed the streams" stays
consistent with sipnab attributing them for some unrelated reason.

### The pair, not just the relay

Both fixtures above carry an `ng` exchange this project generated itself. That
proves the decoder and proves nothing about whether a real proxy and a real
relay, talking to each other, produce something sipnab can use.

`rtpengine-opensips-ng.pcap` closes that. It is a SIPp call driven through
OpenSIPS and rtpengine in the harness, with `--homer-enable-ng` set, filtered
to what a SEPARATE relay host would see: media and the relay's own control
plane, no SIP. The Call-ID it recovers is OpenSIPS's, so the name travels
proxy to rtpengine to HEP to sipnab and arrives on a host that captured no
signaling at all. `rtpengine-opensips-media-only.pcap` is the same capture
with the sixteen control-plane packets removed.

Two things came out of building it that the synthetic test could not reach.

**The report lied when signaling WAS present.** The relay-named section keyed
on provenance alone, so a co-resident relay -- where the proxy anchors media
through an rtpengine on the same box -- produced rows under a heading reading
"no SIP for them in this capture" about calls whose signaling was three lines
above. The predicate now requires both halves: relay-named AND unrepresented
here. Neither test is sufficient alone, and the file says why.

**rtpengine refuses to mirror into the void.** It CONNECTS its Homer socket,
so an unreachable destination answers with ICMP port-unreachable, rtpengine
logs `Connection error from Homer ... Connection refused` and stops tracing.
Aiming `--homer` at an address nobody answers therefore yields no control
plane at all, which looks exactly like a broken feature. The harness
ships `hep-sink` to stand in for Homer for that reason.

**What the pair also shows is where this feature does NOT help.** Measured on
the unfiltered capture, a co-resident relay needs none of it: the proxy's own
rewritten SDP already names both sockets, and stripping the control plane
changes nothing. The filtered view is the honest one to assert against
because it is the only topology where the control plane adds anything.

Every gate here was mutation-tested and none survived:

| Mutation | Caught by |
|---|---|
| Classifier claim removed | [`tests/rtpengine_ng_test.rs`](../../tests/rtpengine_ng_test.rs) |
| Relay links stored with signaled provenance | `pipeline::relay_control_tests` |
| Correlation-id fallback removed | `rtpengine::ng` tests |
| Media-creating commands attributed as legs | `rtpengine::ng` tests |
| Duplicate-key check removed | `rtpengine::bencode` tests |
| Depth limit removed | `rtpengine::bencode` tests |
| Trailing-byte check removed | `rtpengine::bencode` tests |
| Decoder made to require sorted keys | `rtpengine::bencode` tests |

## Kernel forwarding, measured

rtpengine forwards either in userspace or, with `table = N` and the
`xt_RTPENGINE` module, inside netfilter. If kernel-forwarded media were
invisible to `AF_PACKET`, attributing it would be pointless, so this run
measured it rather than reasoning about it.

Against rtpengine 12.5.1 with the module confirmed active and accounting the
packets itself:

```text
/proc/rtpengine/0/list   local 10.0.0.40:34232   250 packets  [kernel-forwarded]
                         output → 10.0.0.60:40001             250 packets
capture on the relay     ingress 500/500          egress 500/500
```

Both directions are fully visible in both modes, and nothing in this subsystem
needs to know which mode a relay is in. The reason is structural: `AF_PACKET`'s
receive tap runs before netfilter, and the module re-injects through the normal
transmit path, which passes the transmit tap.

Note the module is still `xt_RTPENGINE` at 12.5.1, not `nft_rtpengine`.

## What is deliberately not here

- **`subscribe` / `publish` / `start recording` and friends.** They carry a
  join key and decoding them is nearly free. The risk is misattribution, not
  complexity: a recording subscription creates a stream that belongs to the
  call without being one of its two legs, and attributed as an ordinary leg a
  two-party call shows three streams — after which the media analysis that
  judges one-way audio and asymmetry answers a question nobody asked. They are
  counted (`rtpengine::media_creating_commands_seen`) so a run can say what it
  did not attribute.
- **HEP carrying SIP or RTP off the wire.** The claim covers `ng` only.
  Claiming those here would change what every existing capture containing HEP
  reports, which is a much larger decision than this required.
- **Mid-call reconciliation.** A control message that already happened is not
  on the wire for sipnab to read, so a call already running when the capture starts stays
  unnamed until a re-offer. Closing it means asking rtpengine directly, which
  makes sipnab send packets to a production relay — tracked as RE4 with the
  bounds that keeps it from becoming a service.
