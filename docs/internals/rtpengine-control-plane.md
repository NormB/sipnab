# The rtpengine control plane

This page covers three things:

- how sipnab names media it captures on a standalone relay
- why this delivery path won
- which decisions here are load-bearing

Read [Attribute media on an rtpengine relay](../rtpengine.md) first if you want the operator's view.
This page is about the code.

## The problem this solves

A media relay carries no SIP.

- sipnab installed on one sees two sockets of RTP per call.
- It sees nothing that names the call.
- So `RtpStream::orphaned` is true for every stream in the capture.

The output is accurate and useless.
It is the same shape as the NAT case the codebase already names:

- An operator can see that media exists, how much, and how badly it performs.
- The operator cannot say which call any of it belongs to.

The name is on the box.

- rtpengine's `ng` control protocol carries the Call-ID and the ports the relay allocated.
- That pair is the join key.

## Wire format

An `ng` message is a cookie, one space, and a bencoded dictionary:

```text
14661e9e...  d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp122:v=0...e
```

Three properties matter to the parser, all confirmed against rtpengine 12.5.1 rather than taken from documentation.

**Dictionary keys arrive unsorted.**

- The bencode specification requires lexicographic order.
- rtpengine does not produce it.
  A live `offer` arrives as `command`, `call-id`, `from-tag`, `sdp`.
- A decoder that enforced the rule, or that binary-searched keys, would fail on every real message.
- `bencode::Value::Dict` therefore keeps arrival order and looks up by scan.

**Replies carry no `call-id`.**

- An `offer` reply's entire body is `d3:sdp136:v=0...e`.
- This is the single most consequential fact about the protocol for our purposes.
- The reason: the reply is the half that carries the relay's OWN allocated ports.

**The cookie is a retransmission key, and rtpengine deduplicates on it.**

- A repeated cookie gets a cached reply instead of reprocessing.
- Anything that SENDS `ng` must generate a fresh cookie per transaction.
- Reusing one returns port allocations belonging to a call rtpengine may already have deleted.
- This cost one wrong measurement during development.
  rtpengine's own log explained it: `Detected command from 127.0.0.1 as a duplicate`.

## Why HEP, and not a sniffer on the ng socket

Sniffing `ng` off its own socket needs no configuration anywhere.
That is a real advantage.

It also needs several other things:

- a cookie-to-call transaction map, because of the reply asymmetry above
  - The map ties a reply back to the request that named the call.
- UDP, TCP, HTTP and WebSocket handling
- a UNIX socket it cannot capture at all
- fragment reassembly for an offer carrying ICE candidates over an MTU-sized path

Over HEP every one of those disappears.

- rtpengine's `--homer-enable-ng` mirrors the exact wire bytes of every message in both directions.
- It puts the Call-ID in the HEP correlation-id chunk, on requests and replies alike.
- The tie arrives with the message. So:
  - there is no transaction state to keep
  - there is one transport instead of four
  - there is no fragment problem

Decoded from the committed fixture, every packet carries it:

```text
HEP #1 capture-proto=0x3d correlation-id='km-670bd208@sipnab'  d7:command5:offer...
HEP #2 capture-proto=0x3d correlation-id='km-670bd208@sipnab'  d3:sdp138:v=0...   <- reply
```

The passive sniffer stays on the roadmap as a second delivery path behind the same decoder.
It is not a separate feature.

## Why the wire, and not our own listener

sipnab can receive on `--hep-listen` and have rtpengine send to it.
That works since 0.5.125, and not before, although this page said it did.

The claim was wrong in a way worth recording, because the shape recurs.

- The listener strips the HEP wrapper before the parser runs.
- So by the time the pipeline looked for `ng`, there was no HEP header left to parse.
- The check never fired.
- Worse, the correlation id went with it.
  - An `ng` REPLY names its call in the correlation id and nowhere else.
  - So even the half carrying the relay's allocated ports had lost the only route back to a call.

"No new parsing at all" was true of the DECODER and false of the PATH.
Nothing tested the path.

- The fix carries the wrapper's two load-bearing claims in `PreParsed`.
- It gives the pipeline a second arm for the delivered shape.
- [`tests/hep_listen_ng_test.rs`](../../tests/hep_listen_ng_test.rs) covers it.
- `hep_to_packet_carries_the_capture_protocol_and_correlation_id` covers the listener half.
  - The integration tests structurally cannot cover that half.
  - They build `PreParsed` by hand.
- Mutation found that gap rather than review.

It remains the wrong default.

- `--homer` is a single `G_OPTION_ARG_STRING`, not a repeatable option.
- So rtpengine has exactly ONE Homer destination.
- Pointing it at sipnab takes it away from the collector it already feeds.
- Reading the copy already on the wire needs no configuration change.
  - It leaves that pipeline untouched.
  - If sipnab stops, nothing downstream notices.
- A diagnostic tool does not belong in a production data path.

Relay mode (`--hep-listen` plus `--hep-send`) stays documented as a fallback with that cost stated.

## Module layout

| File | Holds |
|---|---|
| [`src/rtpengine/bencode.rs`](../../src/rtpengine/bencode.rs) | Bencode decoder. Borrowed values, depth-limited, hostile-input facing |
| [`src/rtpengine/ng.rs`](../../src/rtpengine/ng.rs) | Cookie/body split, command classification, field extraction |
| [`src/rtpengine/control.rs`](../../src/rtpengine/control.rs) | `list` and `query`, their reply parsers, and the client that carries them -- over a datagram by default, over a stream when the answer asked for is bigger than a datagram can return |
| [`src/relay/mod.rs`](../../src/relay/mod.rs) | The seam's declarations: `ControlDecoder`, `ControlMessage`, `DecodedControl`, and the media-creating tally. Declares only -- it imports no implementation, so a second relay can satisfy it |
| [`src/relay/types.rs`](../../src/relay/types.rs) | The vocabulary a caller programs against: commands, replies, and the views of a call the relay returns |
| [`src/relay/reconcile.rs`](../../src/relay/reconcile.rs) | The two moments sipnab asks, the port index, the bounds that keep asking from becoming polling, and the hand-off the capture path offers to |
| [`src/rtpengine/mod.rs`](../../src/rtpengine/mod.rs) | `sdp_links_from_ng`, the bridge into the existing SDP linking, and `NgControlDecoder` -- the `ng` implementation of the seam above, reaching UP to satisfy it |
| [`src/app/relay_reconciler.rs`](../../src/app/relay_reconciler.rs) | The thread that drains the hand-off and does the asking |
| [`src/app/servers.rs`](../../src/app/servers.rs) | The composition root: chooses which implementation satisfies the seam and hands it to the MCP surface, so no consuming layer names one |

The decoder is hostile-input facing on both delivery paths. So:

- every length is bounds-checked before use
- `bencode::MAX_DEPTH` bounds the recursion
- anything malformed is an error rather than a partial value

A truncated dictionary is not a dictionary with fewer keys.

The decoder rejects duplicate keys rather than resolving them.

- Last-wins and first-wins are both silent.
- A message with two `call-id` keys names no call with confidence.

[`fuzz/fuzz_targets/rtpengine_ng.rs`](../../fuzz/fuzz_targets/rtpengine_ng.rs) drives three things:

- the decoder
- the message layer
- `sdp_links_from_ng`, with the correlation-id both present and absent

## Where it joins the existing machinery

`sdp_links_from_ng` returns the same `(IpAddr, u16, String, SdpMedia)` tuples `extract_sdp_links` returns for a SIP body.
So no new linking machinery exists.

- The call-id comes from the message body when it has one.
- Otherwise it comes from the correlation-id.
- Preferring the body means a passive wire capture still works for the request half.
  Such a capture has no correlation-id.

### `PacketAction::RelayControl`

Classification returns a new variant rather than reusing `Sip`.
That is deliberate.

- sipnab observed no SIP message.
- Synthesizing one to reuse the variant would put signaling into the dialog store that nobody sent.
- This is a tool whose whole value is saying what it actually saw.

The variant also pays for itself structurally.

- This codebase's most-named defect class is a change that reaches some packet appliers and not the others.
- Adding an enum variant makes the compiler name every one of them.
- It found six:
  - the live router
  - the `--cores` shard
  - the batch path
  - the TUI's file-open
  - two test harnesses that mirror them
    ([`tests/rtp_quality_provenance_test.rs`](../../tests/rtp_quality_provenance_test.rs), [`tests/corpus_lint_test.rs`](../../tests/corpus_lint_test.rs))
- The behavior itself lives once, in [`pipeline::apply_relay_control`](../../src/pipeline.rs).
  So the six call sites cannot drift apart.
- The variant carries one `pipeline::RelayControlMessage`:
  its links, the relay that said it, how it arrived, and its cookie.
  So every applier passes the message whole rather than unpacking its fields.

### `EndpointAssertion`, and why it is not a fourth `InputOrigin`

An `ng` endpoint is the relay asserting a port it allocated itself.

- That is not the same claim as an endpoint parsed from an SDP body on the wire.
- The difference has to survive into provenance.

It is a field on `SdpProvenance` rather than a fourth `InputOrigin` variant.
The two are independent axes:

- `InputOrigin` is a TRANSPORT fact.
  The bytes arrived on the wire, over HEP, or out of a process.
- `EndpointAssertion` is a fact about the CLAIM.

They cross freely.

- A relay's assertion arrives over HEP today.
  It would arrive off the wire through the same decoder tomorrow.
- Ordinary signaling arrives over every origin there is.
- A fourth `InputOrigin` would have forced every match on transport to handle a value that is not about transport.

`RtpStream::dialog_assertion` carries it onward, written in the same breath as `dialog_origin`.
So the two can never describe different bindings.

## The report surface, and a bug worth remembering

The report gains a section naming calls a relay attributed whose SIP is not in the capture.
It has to exist:

- Once attributed, those streams correctly leave the orphan table.
- Without the new section, their Call-ID would then appear nowhere at all.
- That is a worse answer than the orphan row it replaced.

The first version keyed on "this stream has a Call-ID that no dialog in this report matches".
That is wrong, and the way it is wrong is instructive.

- It is also exactly what `--limit 1` produces.
  The run keeps one dialog, and streams still point at the calls the run dropped.
- Ordinary SIP signaling named those streams.
- So reporting them as relay-named gave a confident wrong answer about where the name came from.

It now keys on `RtpStream::dialog_bound_from_relay`, which reads recorded provenance.

- `limit_caps_tracked_dialogs` caught the original within one gate run.
- `a_dialog_dropped_by_limit_is_not_reported_as_relay_named` keeps it caught.

## Proving the claim

[`tests/fixtures/rtpengine-ng-hep.pcap`](../../tests/fixtures/rtpengine-ng-hep.pcap) holds:

- six HEP packets covering offer/answer/delete with their replies
- forty relayed RTP packets on the four sockets those commands allocated

It started as a live capture from rtpengine 12.5.1 with `--homer-enable-ng`.

- [`tests/support/synthetic_captures.rs`](../../tests/support/synthetic_captures.rs) now builds it.
  - It keeps the live exchange's key order, reply shapes, ports and timing.
  - It replaces every address, MAC address and cookie with a documentation value.
- The repository publishes nothing from the lab's network.
- [`tests/synthetic_captures_test.rs`](../../tests/synthetic_captures_test.rs) rebuilds the file byte for byte.
  It checks those wire shapes on the committed bytes.

Two properties make it discriminating rather than merely convenient.
[`tests/rtpengine_ng_test.rs`](../../tests/rtpengine_ng_test.rs) asserts both instead of describing them:

- **It contains no SIP whatsoever.**
  - If these streams end up attributed, the attribution can only have come from the control plane.
  - There is no other source of a Call-ID in the file.
- **The HEP targets a third party.**
  - The relay reports to a collector at another address.
  - sipnab is a bystander.
  - That is the RE6 deployment.

[`tests/fixtures/rtpengine-media-only.pcap`](../../tests/fixtures/rtpengine-media-only.pcap) is the same capture with the six HEP packets removed and nothing else changed.

- It is the control case.
- Strip the control plane, and every stream returns to being an orphan with no codec and no call.
- Without a paired negative, "sipnab attributed the streams" stays consistent with sipnab attributing them for some unrelated reason.

### The pair, not just the relay

Both fixtures above carry an `ng` exchange this project generated itself.

- That proves the decoder.
- It proves nothing about whether a real proxy and a real relay, talking to each other, produce something sipnab can use.

`rtpengine-opensips-ng.pcap` closes that.

- It began as a SIPp call driven through OpenSIPS and rtpengine in the harness, with `--homer-enable-ng` set.
- A filter reduced it to what a SEPARATE relay host would see:
  media and the relay's own control plane, no SIP.
- The Call-ID it recovers is the one OpenSIPS handed the relay.
  - So the name travels proxy to rtpengine to HEP to sipnab.
  - It arrives on a host that captured no signaling at all.
- `rtpengine-opensips-media-only.pcap` is the same capture with the four control-plane packets removed.

The harness capture carried the opening of a third-party G.722 recording.
So in September 2026 [`tests/support/synthetic_captures.rs`](../../tests/support/synthetic_captures.rs) rebuilt the pair.
The rebuild:

- keeps OpenSIPS's key order
- keeps the relay's conversion from G.722 to PCMU
- keeps the timing
- puts synthetic G.722 in the caller's packets
- moves the addresses into 198.51.100.0/24

Two things came out of building it that the synthetic test could not reach.

**The report lied when signaling WAS present.**

- The relay-named section keyed on provenance alone.
- A co-resident relay is one where the proxy anchors media through an rtpengine on the same box.
- So a co-resident relay produced rows under a heading reading "no SIP for them in this capture".
- Those rows were about calls whose signaling was three lines above.
- The predicate now requires both halves: relay-named AND unrepresented here.
- Neither test is sufficient alone, and the file says why.

**rtpengine refuses to mirror into the void.**

- It CONNECTS its Homer socket.
- So an unreachable destination answers with ICMP port-unreachable.
- rtpengine then logs `Connection error from Homer ... Connection refused` and stops tracing.
- Aiming `--homer` at an address nobody answers therefore yields no control plane at all.
  That looks exactly like a broken feature.
- The harness ships `hep-sink` to stand in for Homer for that reason.

**What the pair also shows is where this feature does NOT help.**

- Measured on the unfiltered capture, a co-resident relay needs none of it.
  - The proxy's own rewritten SDP already names both sockets.
  - Stripping the control plane changes nothing.
- The filtered view is the honest one to assert against.
  It is the only topology where the control plane adds anything.

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
| Reassigned relay port not re-reported | `rtpengine::reconcile` tests |
| Unchanged socket re-reported on every refresh | `rtpengine::reconcile` tests |
| Duplicate-key check returned to a linear scan | `rtpengine::bencode` tests |
| Duplicate keys compared as lossy text rather than bytes | `rtpengine::bencode` tests |
| Decoder made to return its entries sorted | `rtpengine::bencode` tests |
| Hand-over fired only on a port's FIRST reassignment | `rtpengine::reconcile` tests |
| Integer digits left to `from_str`, which takes a leading `+` | `rtpengine::bencode` tests |
| Byte-string length left to `from_str`, same leading `+` | `rtpengine::bencode` tests |
| Socket recorded ahead of the ceiling check | `rtpengine::reconcile` tests |
| Socket record dropped entirely, making every packet an ask | `rtpengine::reconcile` tests |

## Kernel forwarding, measured

rtpengine forwards in one of two places:

- in userspace
- inside netfilter, with `table = N` and the `xt_RTPENGINE` module

If kernel-forwarded media were invisible to `AF_PACKET`, attributing it would be pointless.
So this run measured it rather than reasoning about it.

Against rtpengine 12.5.1 with the module confirmed active and accounting the packets itself:

```text
/proc/rtpengine/0/list   local 192.0.2.40:34232  250 packets  [kernel-forwarded]
                         output → 192.0.2.60:40001            250 packets
capture on the relay     ingress 500/500          egress 500/500
```

Both directions are fully visible in both modes.
Nothing in this subsystem needs to know which mode a relay is in.

The reason is structural:

- `AF_PACKET`'s receive tap runs before netfilter.
- The module re-injects through the normal transmit path, which passes the transmit tap.

Note the module is still `xt_RTPENGINE` at 12.5.1, not `nft_rtpengine`.

## Asking the relay directly

Everything above decodes a message somebody else sent.

- A control message that already happened never returns to the wire.
- So a call already running when the capture starts stays unnamed until a re-offer.
- Incident response usually begins mid-call.
- `--rtpengine-control` names the relay's own `ng` port, and sipnab asks it.

Two questions reach the relay:

- `list`, which names the active calls
- `query`, which says which relay-side PORT belongs to which call

The port is the one thing sipnab can already see in a capture.
The relay is the only thing that knows what it allocated the port for.

Nothing else reaches it.

- The last section on this page says why `delete` is unreachable rather than merely unused.
- A `TransmitPermit` gates both questions.
- Only a live capture source yields one.
- So an analyst opening a customer's pcap cannot make sipnab send packets at the addresses inside it.

### Two triggers, and neither of them a clock

**Startup, before the capture opens.**

- [`bootstrap::relay_startup_snapshot`](../../src/app/bootstrap.rs) runs inside `launch`'s privileged window.
- It runs against the RESOLVED capture source.
- It spends one `list` plus one `query` per call.
- The answers become a port index.
- [`pipeline::apply_relay_snapshot`](../../src/pipeline.rs) registers every socket in it as a media ENDPOINT through `link_endpoint_from`.

Registering rather than linking is what the rest of this depends on.

- A stream that turns up later resolves its endpoint from memory at creation.
- That is exactly as it would from an SDP body already on file.
- So the packet path never makes a network call.

Against rtpengine 12.5.1:

```text
rtpengine at 127.0.0.1:22222: 2 call(s) enumerated, complete; queried 2 of them, 8 relay port(s) now attributable
```

**A stream nothing explains.**

- [`rtp::stream_store`](../../src/rtp/stream_store.rs) records an orphan socket at stream CREATION.
- It does so under the write lock the RTP path already holds.
- That is what makes the second trigger an event rather than a periodic sweep.
  - Nothing rescans the store looking for orphans.
  - A run whose relay accounts for every stream it sees asks nothing after startup.

Both ends of the stream go into the hand-off.

- Which end belongs to the relay is exactly what the packet cannot say.
- A socket the relay does not hold costs one lookup in the index the startup snapshot already built.

```text
rtpengine at 127.0.0.1:22222: 2 unexplained stream(s) offered, 0 attributed, 4 control transaction(s) spent of a ceiling of 66
```

### Why the asking runs on a thread

One question is a round trip, and `DEFAULT_CONTROL_TIMEOUT` gives it two seconds.

- Asking from the packet path would stall capture for as long as the relay stayed quiet.
- That trades dropped packets for an attribution.
- That is the wrong way round for a tool whose job is watching the traffic.

So the capture path only OFFERS a socket.

- `OrphanSink` has no blocking send at all.
- So the only way to hand a socket over cannot wait, however long the relay takes.

[`app::relay_reconciler`](../../src/app/relay_reconciler.rs) does the asking, and it holds no timer.

- Its loop blocks on the hand-off queue.
- It wakes only when the capture path finds a stream nothing explains.
- When every `OrphanSink` drops, the queue closes, the loop ends, and the thread prints what it did.
- There is no flag to poll and no timeout to pick.

**The join order follows from that.**

- The run joins the reconciler only AFTER the capture-processing thread.
- That thread owns the sink whose drop closes the queue.
- Join the reconciler first, and it waits forever on a queue nothing has closed.

### Three bounds, and none of them the traffic

Three things bound the asking.
Not one of them depends on how much traffic the capture carries:

- **Once per socket.**
  - `asked_ports` latches.
  - So a stream that stays unexplained costs one lookup for the run rather than one per packet.
  - Staying unexplained is the normal case for media the relay never touched.
- **A ceiling on transactions.**
  - `DEFAULT_BUDGET` is `2 * (DEFAULT_LIST_LIMIT + 1)`, 66 at the defaults.
  - That covers a full startup snapshot and a comparable refresh after it.
  - A capture full of orphans cannot turn into a flood of control traffic.
- **A bounded hand-off.**
  - `ORPHAN_QUEUE_DEPTH` caps the queue.
  - `MAX_PENDING_ORPHAN_SOCKETS` caps the buffer feeding it.
  - Neither one ever makes the capture path wait.

When one of them bites, sipnab counts it and says so.

- For the hand-off: `OrphanSink::dropped` and `StreamStore::orphan_sockets_dropped`.
- For the other two: the offered-versus-attributed and spent-of-ceiling figures in the closing line above.

A stream sipnab never asked about is not a stream the relay disowned.
A bound that bites quietly is how those two turn into the same sentence.

`ReadyReconciler` carries the reconciler from launch into the capture loop rather than rebuilding it there.
Rebuilding discards all three at once.
A second reconciler starts with:

- a full ceiling
- an empty `asked_ports`
- no memory of which calls it had already read

### Why the index keys on address and port

`Reconciler`'s index keys on `(IpAddr, u16)`.

- That matches the key `StreamStore` uses for SDP endpoints.
- The two indexes join on that key.
- So they have to agree on what a socket is.

Keying on the port alone was wrong, and not subtly.

- rtpengine allocates from ONE port range across every `--interface`.
- So the same port number genuinely sits on two addresses at once.
- A port-keyed index hands one interface's media to the other's call.
- It reports that with the same confidence as a correct answer.

### The provenance of an answer nobody captured

`SdpProvenance::relay_queried` sets `origin: None`, and the absence is the point.

- `Wire`, `Hep` and `Uprobe` each assert that sipnab OBSERVED the addressing somewhere.
- This addressing sipnab ASKED FOR instead.
- No `InputOrigin` says that honestly.
- A binding made from such an endpoint therefore withholds the cross-source claim rather than inventing one.
- That is the same rule `EndpointAssertion` follows earlier on this page, applied to the other axis.

The rtpmap stays empty for a related reason.

- A `query` reply names a codec but no payload type.
- An rtpmap entry needs both.
- Synthesizing the missing half would put a number sipnab never heard into a field an operator reads as measured.

### Naming what "nothing" means

`Unattributed` exists to prevent one collapse.

- "The relay does not hold this port" and "sipnab could not ask" are different facts.
- A type with a single way of saying no reports the second as the first.
- A run that never reached the relay then reads exactly like a run the relay answered.

So it keeps five reasons apart:

- the relay refused the question, or nothing answered at all
- the relay named calls sipnab could not read
- the relay's enumeration came back capped
- the run had already spent its transaction ceiling
- sipnab asked, and the relay does not hold the port

Only the last of those says anything about the relay.

- `why_not` tests them most-conclusive-first.
- So the last arm becomes reachable only after a complete answer.
- Where two gaps hold at once, it names the truncated enumeration first.
  - That is the wider gap.
  - Closing it shrinks the other one too.

### Reaching past a capped enumeration

sipnab does not merely report the cap.

- A capped answer earns ONE wider ask, for `WIDE_LIST_LIMIT` Call-IDs.
- That number aims to be past what a datagram can return.
- So `ControlClient` sends it over a stream.
- A relay with no `listen-tcp-ng` refuses the connection.
- So sipnab discovers availability by asking.
- It does not declare it in a flag that could assert a listener which is not there.

Measured against rtpengine 14.2.0.0 holding 1200 calls with 55-character Call-IDs:

| `limit` | Reply size | Over a datagram | Over a stream |
|---|---|---|---|
| 32 (default) | ~2 KB | fine | fine |
| 1000 | 61034 bytes | fine, in two reads | fine, in two reads |
| 1200 | 73234 bytes | **no reply at all** — past the maximum UDP payload | all 1200 returned |

The code has to carry two consequences.

- A stream has no message boundary, and the connection stays open after the answer.
  - So there is no EOF to read up to.
  - `round_trip_stream` reads until the bencode COMPLETES.
  - That is what rtpengine does in the other direction.
- Nothing bounds a stream.
  - `MAX_STREAM_REPLY_BYTES` is what stops the far end deciding how much memory sipnab allocates.

The wider ask runs once for the run, whether it succeeds or fails.

- The summary says which happened.
- "We never tried" and "we tried and could not" send an operator to different places.

Reaching further also moves the binding constraint from the enumeration to the transaction ceiling.

- A run can enumerate more calls than it can afford to query.
- Such a run names how many went unread.
- It does not leave the operator to subtract two numbers.

## What is deliberately not here

- **`subscribe` / `publish` / `start recording` and friends.**
  - They carry a join key, and decoding them is nearly free.
  - The risk is misattribution, not complexity.
    - A recording subscription creates a stream that belongs to the call without being one of its two legs.
    - Attributed as an ordinary leg, a two-party call shows three streams.
    - After that, the media analysis that judges one-way audio and asymmetry answers a question nobody asked.
  - sipnab counts them (`rtpengine::media_creating_commands_seen`).
    - [`output::dialog_report`](../../src/output/dialog_report.rs) prints that count beside the relay-named calls.
    - It is on a line beginning `Media-creating relay commands seen:`.
    - So a run says what it did not attribute.
    - The counter landed first and no surface read it.
      That is the same silence it exists to break.
    - A run that saw none prints nothing rather than a zero.
  - The same misattribution reaches the ACTIVE path.
    There sipnab answers it rather than declining it.
    - A `query` walks every side the relay holds.
    - So a recording or forwarding fork comes back as a tag of its own with its own relay ports.
  - rtpengine stamps each `subscriptions` entry with a `type`:
    - `offer/answer` for the other side of a dialog
    - `pub/sub` for a side that only receives media from another
  - sipnab reads that stamp.
    - A `pub/sub` peer becomes a media subscription rather than a party the call is with.
    - The fork's ports are still attributed to the call they fork.
    - The startup summary names how many of the ports it counted a subscriber holds.
  - Folded together instead, a two-party call comes back with three parties.
    - That is the same wrong answer the passive path refuses.
    - It arrives through the door sipnab does open.
- **HEP carrying SIP or RTP off the wire.**
  - The claim covers `ng` only.
  - Claiming those here would change what every existing capture containing HEP reports.
  - That is a much larger decision than this required.
- **Sending anything that changes the relay.**
  - `offer`, `answer`, `delete` and `start recording` are the other half of the `ng` protocol.
  - Every one of them changes a production box: it moves media, tears a call down, or fills a disk.
  - None of them is reachable.
    - `ReadOnlyCommand` has two variants and `ReadOnlyRelay` has two methods.
    - So no value in this codebase means `delete`.
  - A reviewer asking "does sipnab ever tell a relay to do something" reads one enum instead of auditing every call site.
  - An edit that wants to send one has to add a variant.
    That shows up in a diff rather than passing as an oversight.

## Engineering notes moved from the user guide

These notes were on [the user page](../rtpengine.md) and moved here when that
page became task-first.

### `--hep-parse` once switched relay attribution off

`--hep-parse` unwraps a HEP datagram and hands the payload to the parser.
sipnab recognizes mirrored `ng` two ways: by the metadata a HEP listener
recorded before stripping the wrapper, and by parsing the wrapper off a
sniffed datagram that still has one. Before 0.5.128 the unwrap discarded the
wrapper without recording what it said, so neither route had anything to
match on. The control plane reached the capture and sipnab dropped it, no counter
moved, and every relay stream stayed orphaned, with the feature built, the
filter admitting the ports and the datagrams on the wire. From 0.5.128 the
unwrap carries the wrapper's capture protocol and correlation id forward, and
the sniffed-mirror port check (`sniffed_mirror_port_believed`) is the one gate
for both paths.

Two related version boundaries the user page used to state:

- `--hep-listen` decoded delivered `ng` from 0.5.125. Earlier builds accepted
  the traffic and decoded none of it.
- Through 0.5.192 the default capture filter admitted no media, so a relay
  capture needed a filter of its own that named the relay's port range.

### "Authoritative about the port"

The user page once called a `media-relay` assertion "authoritative about the
port". That was true of rtpengine, which cannot be wrong about which socket it
opened, and false of the assertion, because nothing authenticates a sniffed
mirror. [`tests/rtpengine_sniffed_ng_gate_test.rs`](../../tests/rtpengine_sniffed_ng_gate_test.rs) pins the
current wording's claim: sipnab believes a mirror from any source on the HEP port
and refuses it elsewhere.

### What the multi-node procedure rests on

[`tests/multi_node_relay_fanout_test.rs`](../../tests/multi_node_relay_fanout_test.rs)
pins the three properties the per-host procedure on the user page depends on:

- The proxy holds signaling and no media.
- Exactly one relay claims a call.
- The proxy's SDP names which one.

sipnab does not aggregate across nodes: there is no cluster mode, central
index, or node that answers for another. An aggregator is infrastructure, and
[positioning](../design/positioning.md) rules it out.

The longer-term goal that relay attribution serves, a call assembled across
every hop, is in
[rtpengine: the multi-hop goal](../design/rtpengine-multi-hop-goal.md).
