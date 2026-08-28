# Running a live interface and a HEP listener in one process

**Status:** STAGES 0, 1 AND 2 SHIPPED, and SRC2 on top of them. `-d <iface>` with
`-L <addr>` runs both in one process, every source numbers its own frames, a
stream says whether its dialog crossed sources, and a call whose two witnesses
told different stories says so — see §10. Stage 3 (multi-node) remains open —
see §7.
**Verified against:** `94fad2de` (0.5.117) when written; stage 1 landed on
`8c03a453` (0.5.118); stage 2 landed on top of 0.5.120.
**Backlog:** [`docs/design/backlog.md`](https://github.com/NormB/sipnab/blob/main/docs/design/backlog.md) **SRC1** (`:447`).
**Raised by:** Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) alongside
[#245](https://github.com/NormB/sipnab/issues/245), from OpenSIPS deployment
experience.
**Check:** `grep -n 'Composite(Vec<CaptureSource>)' src/capture/native.rs` exits 0
(stage 1), `grep -n 'fn next_origin' src/capture/packet.rs` exits 0
(stage 2), and `grep -n 'fn detect_source_disagreement' src/sip/diagnosis.rs`
exits 0 (SRC2).

That grep is the narrowest fact separating "designed" from "built": the plan used
to carry at most ONE source, by type, and this variant is what lets it carry two.
The original check pointed at `pub source: Option<CaptureSource>` in
[`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs) on the expectation that a composite would change that
signature. It did not — the composite went INSIDE `CaptureSource`, so the plan
still holds one `Option` and that grep still matches. A check whose subject
survives the change it was meant to detect is not a check, which is exactly what
the original paragraph warned about and then walked into.

## 1. The problem in one paragraph

Written before the fix; kept in the present tense because it describes the
behavior up to 0.5.118, which is what the rest of the page reasons against.

An operator running OpenSIPS has two ways to see decrypted SIP. eCapture plus
`--keylog` lifts TLS session keys out of the daemon, which works but depends on
symbol discovery, library layout and a keylog channel staying healthy.
OpenSIPS's own HEP mirror hands sipnab the same SIP already in plaintext, with
no key extraction anywhere in the path — strictly more robust, because there is
nothing to be fragile about. Choosing HEP today costs every RTP stream and every
media-quality figure, because sipnab creates a stream only from real RTP packets
and a HEP-delivered RTCP report has no stream to attach to. So the operator picks
between signaling that always works with no media, and media with signaling that
depends on key extraction holding up. Neither is the answer, and the answer —
HEP for signaling, the local NIC for media, one process — is refused by one
`else if` chain.

## 2. How one source becomes the only source

Also as of 0.5.117. The chain below still resolves the single-source cases; what
changed is that a resolved `Live` and a `-L` address now compose instead of the
first one winning, and `-I` with `-L` is refused rather than silently preferring
the file.

### 2.1 The chain in `plan`

`plan` ([`src/app/bootstrap.rs:257`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L257)) resolves the source once, into a single
`Option<CaptureSource>`, through an if/else chain that starts at
[`src/app/bootstrap.rs:323`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L323) and ends at [`src/app/bootstrap.rs:419`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L419). In order:

| Arm | Line | Condition |
| --- | --- | --- |
| `File` | [`src/app/bootstrap.rs:323`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L323) | `cli.has_input()` — any `-I` |
| `Live` | [`src/app/bootstrap.rs:369`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L369) | `-d <device>` |
| `Live` | [`src/app/bootstrap.rs:373`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L373) | `[capture] device` from the config file |
| `Uprobe` | [`src/app/bootstrap.rs:377`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L377) | `--uprobe-tls` or `--uprobe-library` |
| `Hep` | [`src/app/bootstrap.rs:387`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L387) | `-L <addr>` |
| `None` | [`src/app/bootstrap.rs:417`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L417) | auto-detection, deferred to launch time |

`-L` sits below `-d`, so `sipnab -d eth0 -L 0.0.0.0:9060` binds no HEP socket and
says nothing about it. That silence is the same defect class the chain already
warns about one arm up: [`src/app/bootstrap.rs:315`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L315) warns when `-I` and `-d` arrive
together, with a comment naming the reason — an operator who adapted a documented
pcap command gets "a confident wrong answer nobody has reason to doubt". The
`-d` + `-L` pair produces exactly that shape and has no warning at all. Nothing
in [`src/cli.rs`](https://github.com/NormB/sipnab/blob/main/src/cli.rs) marks the two flags as conflicting either; they parse happily
together and one of them evaporates.

### 2.2 What `launch` does with the answer

`launch` ([`src/app/bootstrap.rs:1179`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L1179)) takes the same singular `Option`. Four
decisions downstream read the source as a scalar:

- **Auto-detection.** [`src/app/bootstrap.rs:880`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L880) substitutes a default interface
  when the plan produced `None`.
- **Channel shape.** [`src/app/bootstrap.rs:926`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L926) picks a batched channel for
  `File` and a per-packet channel for everything else, because a live source's
  packets have to become visible the moment they arrive.
- **Transmit permission.** `TransmitPermit::for_source`
  ([`src/security/transmit_guard.rs:88`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L88)) grants or refuses the scanner-kill path
  from the source *variant*: `Live` and `Hep` yes, `File` and `Uprobe` no.
- **Thread spawn.** [`src/app/bootstrap.rs:936`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L936) branches to
  `start_multi_capture` for `--multi-device`, otherwise `start_capture`
  ([`src/capture/native.rs:455`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L455)), which matches the variant and spawns one named
  thread per arm.

### 2.3 How a packet reaches the pipeline

Every reader — `capture_live_fanout` ([`src/capture/live.rs:253`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L253)), `capture_files`
([`src/capture/file.rs:310`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L310)), `capture_hep` ([`src/capture/hep.rs:1831`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1831)), the
uprobe reader — builds a `Packet` ([`src/capture/packet.rs:452`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L452)) and calls
`tx.send(..)`. `PacketTx` derives `Clone` ([`src/capture/channel.rs:142`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L142)), and the
channel is an unbounded crossbeam queue guarded by a bounded slot semaphore
([`src/capture/channel.rs:204`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L204)). The consumer is the batch receive loop at
[`src/app/batch.rs:2831`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2831), which stops when the channel disconnects — that
is, when the last sender clone drops.

**A second source joins here and nowhere else.** The channel is already
many-producer, the receive loop already ends on the last producer, and the
parser already tells the two kinds of packet apart:

- `Packet::interface` ([`src/capture/packet.rs:452`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L452)) is an `Arc<str>` naming the
  source. Live capture sets the device name ([`src/capture/live.rs:533`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L533)); the
  HEP listener sets `hep:<capture-id>@<peer>` via `hep_source_label`
  ([`src/capture/hep.rs:121`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L121)) and `hep_to_packet` ([`src/capture/hep.rs:134`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L134)).
- `ParsedPacket` ([`src/capture/parse.rs:124`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L124)) carries an `input_origin`
  field holding the `InputOrigin` enum ([`src/capture/parse.rs:90`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L90)) — `Wire`, `Hep` or
  `Uprobe`. Line [`src/capture/parse.rs:2307`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L2307) derives it per packet from the presence of
  pre-parsed addressing and the source name. Nothing in that derivation consults
  the run's configured source, so it already answers correctly in a mixed run.

### 2.4 The fan-in that already exists

`--multi-device` is the precedent, and it is close to the shape this feature
needs. `start_multi_capture` ([`src/capture/native.rs:639`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L639)) validates the device
list, then `run_multi_capture` ([`src/capture/native.rs:735`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L735)) spawns one thread
per device, hands each a `tx.clone()`, drops its own clone so the channel closes
when the last reader exits, aggregates a per-device readiness signal, tears every
sibling down when any one fails to open, and joins them all from a coordinator
thread whose `JoinHandle` becomes the single `CaptureHandle`
([`src/capture/native.rs:386`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L386)).

Every structural question a composite source raises — readiness aggregation,
one-fails-all teardown, a single join handle, channel close on last producer —
`run_multi_capture` has already answered. What it does not do is mix *kinds*: it
is a list of `Live` devices, and the source it reports is one
`CaptureSource::Live` whose `device` field is the comma-joined string
([`src/capture/native.rs:537`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L537)).

## 3. Correlation

The backlog calls correlation "the hard part". Reading the code changes that
assessment materially, and the honest version has two halves: the common case is
already solved, and the ways it goes wrong are real but nameable.

### 3.1 The dialog-to-stream binding is already source-agnostic

sipnab does not correlate a dialog to a stream by capture source. It correlates
by SDP media endpoint, and the key is a bare `(IpAddr, u16)`.

`extract_sdp_links` ([`src/pipeline.rs:1677`](https://github.com/NormB/sipnab/blob/main/src/pipeline.rs#L1677)) resolves each `m=` section's address
through `effective_address` ([`src/sip/sdp.rs:289`](https://github.com/NormB/sipnab/blob/main/src/sip/sdp.rs#L289)) — media-level `c=` when
present, session-level otherwise — and yields `(ip, port, call_id, media)`
tuples. `process_packet` ([`src/pipeline.rs:2331`](https://github.com/NormB/sipnab/blob/main/src/pipeline.rs#L2331)) feeds each one to `link_to_dialog_with_sdp`
([`src/rtp/stream_store.rs:1105`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1105)), which lands in `link_endpoint_with_ptime`
([`src/rtp/stream_store.rs:1210`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1210)). That function does two things:

1. `remember_sdp_endpoint` ([`src/rtp/stream_store.rs:1318`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1318)) records
   `(addr, port) -> SdpEndpoint { call_id, rtpmap, ptime }`, so a stream created
   *later* resolves at creation through `resolve_from_sdp`
   ([`src/rtp/stream_store.rs:1379`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1379)), called from [`src/rtp/stream_store.rs:507`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L507).
2. It sweeps the endpoint index for streams that already exist and fills an
   unset `associated_dialog`.

Neither path reads the capture source. A HEP-delivered INVITE whose SDP advertises
`198.51.100.7:20000` populates the same map entry a NIC-captured INVITE would, and
an RTP stream the NIC observes on that socket binds to that `Call-ID` at creation.

**So the first stage of this feature needs no new correlation code.** That is the
single most important finding here, and it reverses the backlog's framing. The
plumbing is the work; correlation, for the deployment Dan Jenkins describes —
OpenSIPS mirroring its own signaling to a sipnab on the same box that watches the
media interface — falls out of a mechanism that already ships.

### 3.2 What a mixed run can key on, ranked

Ordered by how much each tie actually proves:

| Key | Strength | Where it comes from |
| --- | --- | --- |
| SDP `c=` / `m=` endpoint | Strong | The offer/answer names the exact socket; RTP either arrives there or does not |
| SSRC named in an RTCP report | Strong, narrow | Ties a report to a stream sipnab measured; useless before any RTP exists |
| RTCP companion port | Moderate | [RFC 3550 §11](https://www.rfc-editor.org/rfc/rfc3550#section-11) pairing, one port above an even media port |
| Call-ID | Zero, across sources | Media carries none. It ties HEP dialogs to each other, never a dialog to a stream |
| Timing | Weak | Argued against below |

Call-ID deserves the explicit zero. It is the obvious answer and it is not an
answer: an RTP packet has no Call-ID field, so the identifier that makes the
signaling side tractable does not exist on the media side. This is the same
observation `attribute_media_quote` opens with
([`src/rtp/stream_store.rs:1508`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1508)): *"An ICMP error about media carries no
Call-ID — a media datagram has none to carry."*

Timing deserves a firmer no. "The stream started 40 ms after the 200 OK, so it
belongs to that call" is a coincidence detector on a busy proxy, where dozens of
calls answer per second and every one of them starts media. sipnab already
carries a timing-based leg correlator at score 50 out of 100
([`src/sip/dialog_store.rs:1419`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1419)), the lowest of seven strategies, and that is for
correlating *signaling to signaling* where a Call-ID is present as a
cross-check. Using timing to attach media to a dialog has no such cross-check.
It should stay out.

### 3.3 Failure modes, stated as failures

A stream attributed to the wrong dialog is worse than an unattributed one,
because the wrong attribution arrives looking like a measurement. These are the
ways this design produces one.

**F1 — The proxy sees a different SDP than the wire does. MEASURED, and it does
not bite — but only at one tracer scope.** The worry was structural: when
OpenSIPS engages rtpengine or any media relay, the SDP that OpenSIPS *received*
describes the endpoints as the far side offered them, while media on the NIC
flows to the relay's rewritten address. If HEP carried only the received message,
the map entry and the observed socket would never meet and every stream would
come out orphaned (`RtpStream::orphaned`, [`src/rtp/stream.rs:478`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream.rs#L478)).

§8 said to answer that before writing code. It was answered — see
[§8.1](#81-the-measurement-f1) for the run — and the answer is that OpenSIPS's
`tracer` module mirrors **both** the received and the sent copy of every message
it traces, so the rtpengine-rewritten SDP is in the HEP stream too. Measured
against OpenSIPS 3.6.7 with rtpengine 12.5.1 anchoring the media, the set of
media endpoints advertised across the mirrored messages was **exactly** the set
of sockets RTP was observed on: four of four, nothing advertised that was not
seen, nothing seen that was not advertised.

The condition attached to that is the part an operator has to get right, and it
is a *configuration* property rather than a property of HEP. `trace()` at
transaction scope (`"t"`) mirrors both directions. At message scope (`"m"`) it
mirrors only what OpenSIPS received, and F1 reproduces exactly: in the same
relayed call, one advertised endpoint against four observed sockets. So the
feature's documentation has to name the scope, not merely the topology.

**F2 — Endpoint collision across nodes.** `sdp_endpoints` is keyed on
`(IpAddr, u16)` with no node dimension. A single sipnab receiving HEP from
several nodes — the multi-node fan-in `hep_source_label` exists to make
distinguishable — can be told by two nodes that `192.0.2.1:20000` belongs to two
different calls. `remember_sdp_endpoint` overwrites `existing.call_id`
([`src/rtp/stream_store.rs:995`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L995) onward), so the last offer wins, and
`resolve_from_sdp` hands that winner to a stream. [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) space repeats across
sites, so this is ordinary rather than exotic. **This is the wrong-attribution
mode**, and it is the reason stage one should accept HEP from exactly one node.

**F3 — Endpoint reuse over time.** `associated_dialog` is set only when unset
([`src/rtp/stream_store.rs:940`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L940)), and `sdp_endpoints` is bounded by insertion
order with oldest-out eviction rather than by age
([`src/rtp/stream_store.rs:1014`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1014)). A media gateway cycles a finite RTP port range,
so on a process running for days — which is precisely the deployment shape this
feature is for, unlike the minutes-long pcap read the eviction policy was sized
for — a stale entry can outlive its call and claim the next stream on that
socket. A wall-clock TTL on `sdp_endpoints` is the fix, and it belongs to this
feature rather than to some later one. **SHIPPED in stage two** — on the CAPTURE
clock rather than wall time, so a replay reaches the same answer as the live run
that produced it, and grounded on [RFC 3261 §16.8](https://www.rfc-editor.org/rfc/rfc3261#section-16.8) Timer C, the longest a
compliant proxy keeps an unanswered INVITE transaction alive.

**F4 — Clock disagreement.** A HEP v3 packet's timestamp comes from the
*sender's* clock, read from the `TS_SEC`/`TS_USEC` chunks by `parse_hep_v3`
([`src/capture/hep.rs:955`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L955) onward) and carried verbatim into `Packet::timestamp`
by `hep_to_packet` ([`src/capture/hep.rs:134`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L134)). A live packet's timestamp comes
from the local kernel (`pcap_ts_to_chrono`, [`src/capture/live.rs:928`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L928)). Two
clocks, no discipline between them. Every figure that subtracts a signaling time
from a media time — post-dial delay against first RTP, ringback analysis,
one-way-audio onset — inherits the offset.

Two details soften this and one sharpens it. HEP v2 carries no timestamp at all,
so `parse_hep_v2` ([`src/capture/hep.rs:1221`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1221)) stamps local receive time, and v3
falls back the same way when the chunk pair is unrepresentable — a v2 mirror
therefore has *one* clock, not two. And when the skew runs the wrong way,
`elapsed_ms` ([`src/sip/timing.rs:58`](https://github.com/NormB/sipnab/blob/main/src/sip/timing.rs#L58)) refuses a backwards pair rather than
publishing it, so the visible symptom is a *missing* duration, not a negative
one. Its own rustdoc names the cause: *"a merge of files whose clocks
disagree"*. The sharpening detail is that a skew in the *forward* direction has
no such guard, and sipnab cannot detect it in general. What it can do is state
that a run mixed two clocks, which costs nothing and lets a reader discount a
figure that looks wrong. **SHIPPED in stage two** as `two_clocks_warning`
([`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs)), which names both members and needs BOTH kinds
present — two HEP listeners read one remote clock and two interfaces one local
one, and warning about a disagreement that cannot happen is how a warning
becomes noise.

**F5 — Arrival order inverts.** HEP adds a network hop and a mirroring decision,
so a locally-captured RTP packet can reach the pipeline before the HEP-delivered
INVITE that describes it. The store already survives this — `resolve_from_sdp`
handles SDP-then-RTP and the endpoint sweep in `link_endpoint_with_ptime` handles
RTP-then-SDP, which is exactly the SNB-0007 ordering fix — so the association is
order-independent. What is *not* order-independent is the clock rate: a stream
created before its `a=rtpmap` accumulates jitter against a placeholder, and
`link_endpoint_with_ptime` ([`src/rtp/stream_store.rs:1210`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1210))
restarts the estimator and records where, so `measured_jitter_ms`
([`src/rtp/stream_store.rs:1032`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1032)) withholds the figure until it
reconverges. That machinery exists and covers this. Worth a test, not a design change.

**F6 — Duplicate observation.** If the NIC also sees the signaling that HEP is
mirroring — the mirroring host is the capture host, and no BPF filter excludes
port 5060 — each message arrives twice, from two sources, with two timestamps.
Dialog reconstruction folds them into one dialog whose message ladder is doubled.
This is the concrete reason the `-d`/`-L` combination needs guidance in its help
text about restricting the BPF filter to media, and a candidate for a duplicate
detector later. It is not a reason to refuse the combination.

### 3.4 Say how strong the tie is

sipnab already has the right pattern for this and should reuse it rather than
invent one. `MediaMatch` ([`src/rtp/stream_store.rs:30`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L30)) grades ICMP media
attribution across five tiers and its rustdoc states the principle directly: the
variant travels to every surface *"rather than collapsed to a boolean because
the tiers are not equally strong. A reader deciding whether to act on a finding
needs to know which of those they have."*

A cross-source binding is a weaker tie than a same-source one, for the reasons in
§3.3, and the output should say so rather than present both as "associated". The
minimum honest form is one field on a stream recording that its dialog arrived
over a different source than its media. That is cheap, and it is what lets an
operator discount a suspicious attribution instead of trusting it.

## 4. The provenance and leg-correlation threads

**Provenance: build on it, and it needs one small extension.**
[`docs/design/packet-provenance.md`](https://github.com/NormB/sipnab/blob/main/docs/design/packet-provenance.md) shipped in five stages. `FrameRef`
([`src/capture/packet.rs:377`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L377)) resolves a fact to the bytes behind it, and
`SipMessage::frame` ([`src/sip/message.rs:84`](https://github.com/NormB/sipnab/blob/main/src/sip/message.rs#L84)), `SipDialog`
([`src/sip/dialog.rs:87`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L87)), whose `first_frame` field sits at line 148, and `RtpStream` ([`src/rtp/stream.rs:290`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream.rs#L290)) carries the same field at line 323
carry it downstream.

The gap that matters here: `Packet::frame_ref` ([`src/capture/packet.rs:502`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L502))
requires **both** a source name and a frame ordinal, and the live and HEP readers
stamp only the name. Ordinals come from [`src/capture/file.rs:778`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L778),
[`src/parallel.rs:675`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L675) and the uprobe readers; neither `capture_live_fanout` nor
`capture_hep` writes one. So in a mixed live-plus-HEP run every
`first_frame` is `None`, and nothing on a dialog or a stream records which source
produced it. `input_origin` survives to the parser and then stops: `grep -rn
input_origin src/sip/ src/rtp/ src/output/` finds only test fixtures, and the one
real consumer is the scanner-kill gate at [`src/app/batch.rs:3680`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L3680).

That is the extension this feature needs, and it is small: stamp a per-source
ordinal in the live and HEP readers so `frame_ref` starts returning `Some`, and
carry `input_origin` onto the dialog and the stream. Both are increments to a
shipped mechanism rather than new mechanism.

**SHIPPED in stage two**, so the paragraph above describes the state up to
0.5.120 rather than today's. Both readers now stamp an ordinal — one counter per
device, one per HEP *sender* — and `input_origin` reaches `SipMessage`,
`SipDialog` and `RtpStream`. See [§7](#stage-2--provenance-and-honest-limits--shipped).

**Leg correlation: adjacent, and deliberately separate.**
[`docs/design/icid-correlation.md`](https://github.com/NormB/sipnab/blob/main/docs/design/icid-correlation.md) and the seven strategies at
[`src/sip/dialog_store.rs:43`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L43) correlate *signaling to signaling* across a B2BUA,
keyed on `Session-ID`, `P-Charging-Vector`, the SDP `o=` tuple, or `Via` branch.
Every one of those keys is a SIP header. None exists on an RTP packet. The
problem here is signaling-to-media across two transports, which shares the word
"correlation" and no mechanism.

[`docs/design/multi-capture-comparison.md`](https://github.com/NormB/sipnab/blob/main/docs/design/multi-capture-comparison.md) made exactly this distinction once
already, naming its question B "leg correlation" so nobody would read question
A's existence as progress on it: *"They share a noun and nothing else."* The same
sentence applies. This design should not wait on leg correlation and should not
claim to advance it.

[`docs/design/positioning.md`](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md) does bear on the priority: multi-node reach with no
infrastructure is the stated wedge, and a single process taking HEP from a proxy
while watching its own NIC is that wedge in its smallest form.

## 5. Threading and ownership

### 5.1 Shape

One coordinator thread, one reader thread per member, one `tx.clone()` each —
`run_multi_capture` ([`src/capture/native.rs:735`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L735)) generalised from a device list
to a source list. No new concurrency primitive, no new channel, no ordering
guarantee that does not already hold.

### 5.2 What breaks

**Packet ordering.** Already unordered across producers, and the pipeline already
tolerates it: the SDP-endpoint map is order-independent by construction (§3.3,
F5). What changes is the *magnitude* of the skew — a HEP hop is a network delay,
not a scheduler delay — which strengthens the case for the TTL in F3, since a
map keyed by insertion order behaves differently when insertions arrive out of
time order.

**Timestamps from two clocks.** F4. No mechanism can fix it; a stated fact costs
nothing.

**`--count N` is enforced twice, and the run-level copy is the one that holds.**
Each reader keeps a thread-local counter and stops at `config.count`
([`src/capture/hep.rs:1544`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1544) and its check; [`src/capture/live.rs:573`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L573)), and the
consumer independently breaks at `total_count >= max_count`
([`src/app/batch.rs:3051`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L3051)). Because each reader gets a clone of the same
`CaptureConfig`, the per-reader copies are per source, so a member can stop
itself while the other keeps going. The consumer's total still bounds the run,
so the flag does not silently double — but the per-reader stop is a source-level
early exit nobody asked for, and it is worth an explicit test rather than an
assumption. Note that this shape already exists under `--multi-device`.

**`--duration` is fine.** Each reader measures its own elapsed wall time from its
own start, and the starts are within milliseconds. No shared state needed.

**Shutdown.** Already correct. Every reader polls `signals::shutdown_requested`,
the coordinator drops its `tx` clone so the channel closes when the last reader
exits, and the batch loop breaks on `Disconnected` ([`src/app/batch.rs:2831`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2831)).
When one member ends and the other continues — a HEP sender restarting while the
NIC keeps capturing — the loop keeps running, which is correct: `source_exhausted`
([`src/app/batch.rs:3175`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L3175)) means every source is done, and with two sources it
should keep meaning exactly that.

One consequence to accept rather than fix: **the channel carries no
end-of-source marker.** `Item` is `One` or `Many` ([`src/capture/channel.rs:130`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L130))
and nothing else, so a consumer cannot tell "the HEP sender stopped" from "the
HEP sender is quiet". A `--hep-listen` run already has the same blind spot, which
`IdleWatch` ([`src/capture/hep.rs:1693`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1693)) papers over with a log line after a
silence threshold. A composite run inherits both the blind spot and the paper.

**Backpressure is shared and the accounting is asymmetric.** `PacketTx::send`
blocks at the cap ([`src/capture/channel.rs:225`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L225) onward) and both producers draw
on one slot pool with one `CaptureMeter`. A burst on either source blocks the
other, and the two then fail *differently*: a blocked live reader stops calling
`pcap_next`, the kernel ring overflows, and libpcap counts it — surfaced by
`fold_stats` ([`src/capture/live.rs:877`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L877)) and reported at
[`src/capture/live.rs:653`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L653). A blocked HEP listener stops calling `recv_from`, the
kernel UDP receive buffer overflows, and **nothing counts it**, because UDP
reports nothing to a receiver that was not listening. So the same backpressure
event produces a loud number on one source and silence on the other. The one
counter that would show the shared stall itself — `capacity_hits` on the
`CaptureMeter` ([`src/capture/channel.rs:59`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L59)) — reaches no output surface; only
`backpressure_blocks` and queue depth are exported
([`src/output/prometheus.rs:205`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L205) onward). Splitting the slot pool per source would
trade a shared stall for two smaller ones and does not fix the asymmetry. The
honest answer is a HEP receive-side drop estimate, which is a separate piece of
work; until it exists, this feature should not claim that a quiet HEP source
means no loss.

**`--cores` is untouched.** `RunMode::CoresFile` requires `cli.has_input()`
([`src/app/bootstrap.rs:687`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L687)), so it never sees a live or HEP source. The existing
`cores_ignored_warning` ([`src/app/bootstrap.rs:2810`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L2810)) already names both reasons a
run stays single-threaded. A composite source adds nothing here and needs
nothing.

**Metrics and the writer read the source as a scalar.** The `-O` writer is the
concrete casualty. It initializes on the first packet's `link_type`
([`src/app/batch.rs:2846`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2846)), and the two members disagree: live capture yields
`DLT_EN10MB`, while `Packet::with_pre_parsed` ([`src/capture/packet.rs:679`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L679)) sets
`link_type = 0` and a `data` buffer holding the bare transport payload — no
Ethernet, no IP, no UDP. That absence is deliberate and documented at
[`src/capture/hep.rs:84`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L84) onward: fabricating a `DLT_RAW` header made `etherparse`
read `INVITE`'s leading `0x49` as an IPv4 header with IHL 9 and drop every HEP
message silently. So the bytes are honest and unwritable, not an oversight to
patch. Classic pcap refuses the second member outright
([`src/capture/writer.rs:550`](https://github.com/NormB/sipnab/blob/main/src/capture/writer.rs#L550)), and *which* member gets refused depends on which
packet arrives first, so the run fails non-deterministically. pcapng is worse:
it appends a second interface and writes the bare SIP text as if it were a frame
of the declared link type, producing an export that decodes into something nobody
sent. Refusing `-O` alongside a composite source is the only defensible stage-one
answer, and the refusal message should name `--hep-send` for the case where the
operator wanted the signaling forwarded rather than written.

## 6. CLI and validation

### 6.1 What becomes legal

`-d <iface>` together with `-L <addr>`, and only that pair. Everything else in
the chain stays exactly as it is.

The intended invocation forwards signaling from the proxy and takes media off the
wire, so the BPF filter should exclude the signaling ports the mirror already
covers (F6):

```
sipnab -N -d eth0 -L 127.0.0.1:9060 udp portrange 10000-20000
```

### 6.2 What stays refused

- **`-I` with anything.** Not a scheduling restriction — a security one. File
  packets parse as `InputOrigin::Wire` ([`src/capture/parse.rs:90`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L90) and its
  siblings), and `kill_response_eligible` ([`src/security/scanner_kill.rs:142`](https://github.com/NormB/sipnab/blob/main/src/security/scanner_kill.rs#L142))
  admits `Wire` unconditionally. Today that conflation is safe only because
  `TransmitPermit::for_source` ([`src/security/transmit_guard.rs:88`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L88)) refuses a
  `File` run outright, so no file-origin packet ever reaches the kill path. Pair
  `File` with `Hep` and the source-level refusal disappears while the per-packet
  gate waves file-origin packets through — sipnab transmitting at historical
  third-party addresses, which is the exact outcome the whole guard exists to
  prevent. Admitting `File` into a composite requires a fourth `InputOrigin`
  first. Out of scope, and the refusal message should say why rather than say
  "unsupported".
- **`--uprobe-tls` with anything.** Uprobe reads carry no addressing at all
  ([`src/capture/parse.rs:84`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L84) onward). Combining is coherent in principle and buys
  nothing over `-d` plus `--keylog`; leave it refused until someone asks.
- **`--multi-device` with `-L`.** `--multi-device` reinterprets the `-d` string as
  a comma-separated list ([`src/app/bootstrap.rs:936`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L936)). Composing a list with a
  HEP member is reasonable and should wait for stage three.
- **`-O` with a composite.** §5.2.
- **`--cores > 1`.** Already warned, offline-only, no change.

### 6.3 What the operator gets told

`plan` already sets the precedent: `--cores` with `--json` exits 2 with a precise
message ([`src/app/bootstrap.rs:629-655`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L629-L655)), `--cores` on a live source warns
(`cores_ignored_warning`, [`src/app/bootstrap.rs:2810`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L2810)), `-I` beating `-d` warns
([`src/app/bootstrap.rs:315`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L315)). Three rules follow that precedent:

1. **Refuse what produces a wrong answer.** `-I` with a composite; `-O` with a
   composite. Exit 2, name the flag, name the reason, name the alternative.
2. **Warn what merely surprises.** Two clocks in one run (F4). A HEP member with
   no BPF filter excluding the signaling ports the mirror already covers (F6).
3. **Say the composite exists.** One info line at startup naming both members,
   because an operator reading a log needs to know which run they are looking at.
   Today a `-d eth0 -L :9060` run says nothing about HEP at all, so the operator's
   belief that a listener is up goes uncontradicted.

Before any of that: **stage zero is a warning for today's silent precedence**, and
it should land whether or not the rest is ever built.

## 7. Staged plan

### Stage 0 — Warn that `-L` is being ignored — **SHIPPED**

**Value alone:** yes, and immediately. An operator who typed both flags today
believes they have a HEP listener and does not. This is the `-I`/`-d` warning at
[`src/app/bootstrap.rs:315`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L315) applied to the pair one arm down.

**Not in scope:** any change to the chain. `-d` keeps winning.

**Tests:** a unit test on the warning function pinning the message and the exact
flag pair; a test that each flag alone stays silent. Mutation check — delete the
warning and the first test must fail.

**What shipped, and how it differs.** Stage 1 landed with it, so `-d` + `-L` no
longer needs a warning — it composes. The silent precedence that remains is
`--uprobe-tls` beating `-L`, and that is what `hep_listen_ignored_warning`
([`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs)) warns about. It is keyed on the RESOLVED source rather
than on the flags, so a new arm added to the chain cannot reintroduce a silent
drop without failing
`hep_listen_warning_fires_where_a_uprobe_run_swallows_the_listener`. `-I` with
`-L` is refused outright instead of warned, for the security reason in §6.2.

### Stage 1 — `CaptureSource::Composite` for `Live` + `Hep` — **SHIPPED**

**Value alone:** the whole feature for the single-node deployment. HEP supplies
signaling, the NIC supplies RTP, and §3.1 means dialog-to-stream binding works
with no new correlation code.

**Scope:** a `Composite(Vec<CaptureSource>)` variant; `plan` builds it when `-d`
and `-L` both appear; `run_multi_capture` generalised from device names to source
descriptors; `TransmitPermit::for_source` returns a permit only when **every**
member is `Live` or `Hep`, so the security property is conjunctive rather than
disjunctive and cannot be widened by adding a member.

**Explicitly NOT in stage one:**

- No `File` member. §6.2.
- No `Uprobe` member.
- No `-O`. §5.2.
- No cross-source correlation heuristic. Nothing keyed on timing, nothing keyed
  on Call-ID reaching media. The SDP endpoint map is the whole mechanism.
- No TUI changes. Two reasons, and the second is the stronger one:
  `capture_mode` ([`src/tui/mod.rs:157`](https://github.com/NormB/sipnab/blob/main/src/tui/mod.rs#L157)) is one display string with no room for a
  second source, and the TUI never joins the capture handle at all — it drops it
  ([`src/app/tui_mode.rs:528`](https://github.com/NormB/sipnab/blob/main/src/app/tui_mode.rs#L528)), so a capture thread that failed reports nothing.
  With one source that loses one error; with a composite it loses the answer to
  "which member died". Batch first, and the TUI needs that join before it takes
  a composite.
- No HEP-loss estimate.

**Tests:**

- *Happy path.* Feed a HEP INVITE with SDP naming a synthetic media socket and
  RTP on that socket from a second producer into one channel; assert the stream's
  `associated_dialog` matches the HEP dialog's Call-ID.
- *Reverse order.* Same, RTP first. Assert the same binding, and assert the
  jitter estimate is withheld rather than reported against the placeholder clock.
- *No false binding.* HEP dialog advertising one socket, RTP on a different one.
  Assert the stream is orphaned. This is the test that fails if someone
  "improves" matching with a timing fallback.
- *Wrong-node collision.* Two HEP dialogs advertising the same `(addr, port)`,
  then RTP on it. Today the last offer wins silently. Pin the current behavior
  so the fix in stage three is visible as a change, and assert the run does not
  claim more confidence than it has.
- *Refusals.* `-I` plus `-L` exits 2 with the security reason. `-O` plus a
  composite exits 2. Each asserted on the message, not merely the code.
- *Transmit permit.* A composite containing a `File` member yields no permit.
  This test must fail if the rule is written as "any member is live".
- *Shutdown.* One member ends, the run continues; both end, the channel closes
  and `source_exhausted` flips exactly once.
- *Readiness.* A HEP bind failure tears down the live member and surfaces one
  error naming the failed member — the behavior `run_multi_capture` already has
  for devices, asserted for a mixed list.

**What shipped, and where each test lives.** [`tests/composite_source_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/composite_source_test.rs)
carries the plan-level and correlation tests; [`src/capture/native.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs) carries the
coordinator tests (they drive the private spawner, exactly as the `--multi-device`
teardown tests do); [`src/security/transmit_guard.rs`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs) carries the permit tests;
[`tests/hep_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/hep_test.rs) carries one end-to-end process run.

| Design test | Name |
| --- | --- |
| Happy path | `hep_signaling_binds_the_stream_the_nic_captured` |
| Reverse order | `rtp_arriving_before_the_hep_invite_still_binds` |
| No false binding | `a_hep_dialog_does_not_claim_a_stream_on_a_different_socket` |
| Wrong-node collision | `two_hep_nodes_advertising_one_socket_collide_and_the_last_offer_wins` |
| Refusals | `an_input_file_with_a_hep_listener_is_refused_with_the_security_reason`, `writing_a_capture_file_from_a_composite_is_refused`, `multi_device_with_a_hep_listener_is_refused` |
| Transmit permit | `a_composite_transmits_only_when_every_member_may`, `an_empty_composite_grants_no_permit` |
| Readiness | `a_hep_bind_failure_tears_the_interface_member_down` |
| Composition | `an_interface_and_a_hep_listener_feed_one_channel`, `a_live_device_and_a_hep_listener_run_in_one_process` |

Four departures from the plan above, each for a reason:

1. **The jitter half of the reverse-order test was not asserted.** The design
   asks it to check that the estimate is withheld against the placeholder clock.
   That machinery (`jitter_restart_at`, `measured_jitter_ms`) is real and
   already tested where it lives; the composite adds no new path through it, and
   asserting it here would have duplicated an existing gate rather than pinning
   anything the composite changed.
2. **`source_exhausted` is not asserted directly.** The composition test asserts
   the mechanism underneath it — the channel closes once the last producer exits
   — because `source_exhausted` reads that closure and nothing else. What is not
   covered is a member *ending while the other continues* under a real batch
   loop; the coordinator-level test covers the teardown direction only.
3. **The empty-composite permit test is additional.** `all()` over an empty slice
   is vacuously true, so the natural one-line spelling of the conjunctive rule
   hands a permit to a source with no members at all.
4. **A `composite_filter_warning` and its two tests are additional.** They are
   not in the plan because the plan did not notice that the auto-generated BPF
   filter is signaling-only: a composite with no explicit filter would capture no
   media at all — the exact thing the feature exists to capture — while doubling
   every dialog's message ladder (F6).

### Stage 2 — Provenance and honest limits — **SHIPPED**

**Value alone:** yes, independent of stage one. Ordinals on live and HEP packets
make `first_frame` resolvable for every source, which the provenance design
listed as stage five and left partly open.

**Scope:** per-source ordinals in the live and HEP readers; `input_origin`
carried onto the dialog and the stream; a flag on a stream recording that its
dialog arrived over a different source; a wall-clock TTL on `sdp_endpoints`
(F3); the startup line naming both clocks (F4).

**Tests:** ordinals are per source and monotonic; two members interleaving do not
share a counter; an SDP endpoint older than the TTL does not claim a new stream;
the cross-source flag appears on a stream bound across sources and not on one
bound within a source; a resolvable `first_frame` on a live-captured stream,
which no test can assert today.

**What shipped, and where each test lives.** `FrameCounter`
([`src/capture/packet.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs)) is the one rule both readers use, and it
mints no digest for the reason `FrameRef::uprobe` already gives: a digest exists
so a resolver can prove it found the same bytes again, and a live frame is gone
the instant it is read. The live reader keeps one counter for its device; the
HEP listener keeps one per SENDER (`HepFrameOrdinals`,
[`src/capture/hep.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs)), because a listener is a fan-in and one
listener-wide counter would hand each node a sequence full of holes.
`input_origin` now reaches `SipMessage`, `SipDialog` and `RtpStream`, and
`SdpProvenance` ([`src/rtp/stream_store.rs`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs)) carries an endpoint's
source and capture time so both the TTL and the cross-source flag are decided
per fact rather than per run.

| Design test | Name |
| --- | --- |
| Ordinals per source, monotonic | `ordinals_are_per_source_and_monotonic` |
| No shared counter | `two_members_interleaving_do_not_share_an_ordinal_counter` |
| Endpoint TTL | `an_sdp_endpoint_older_than_the_ttl_does_not_claim_a_new_stream` |
| Cross-source flag | `the_cross_source_flag_marks_only_a_stream_bound_across_sources` |
| Live `first_frame` | `a_live_captured_stream_has_a_resolvable_first_frame` |
| Two clocks (F4) | `two_clocks_warning_fires_on_a_hep_member_beside_a_local_one`, `two_clocks_warning_is_silent_on_a_single_source` |
| Sender-table bound | `a_new_hep_sender_past_the_bound_gets_no_ordinal_rather_than_a_recycled_one` |
| Fanout collision | `only_an_ungrouped_socket_numbers_its_own_frames` |

Six departures from the plan above, each for a reason:

1. **The TTL bites in exactly one place**, `resolve_from_sdp` — the path where
   an endpoint learned earlier claims a stream that did not exist yet, which is
   the F3 shape exactly. `link_endpoint_from` sweeps streams that already exist
   using an entry it has just written, so there is nothing stale there to guard
   against, and applying the TTL to it would have broken the post-merge re-link
   a `--cores` run depends on.
2. **The TTL is measured on the CAPTURE clock**, against the stream's own first
   packet, never `Utc::now()`. A wall-clock TTL expires every endpoint in an
   archived capture, so replay and live would disagree about the same bytes.
3. **Only forward staleness expires.** A negative difference means the media is
   older than the offer describing it, which two clocks (F4) and a HEP hop (F5)
   make ordinary rather than suspicious. Expiring on it would refuse exactly the
   bindings this feature exists to make.
4. **The cross-source flag is derived, not stored.** `dialog_origin` is written
   beside `associated_dialog` at both binding sites, and
   `RtpStream::dialog_bound_across_sources` is the single predicate every
   surface reads — the same shape as `orphaned()`, so a future binding path
   cannot forget to maintain a second field beside it. It requires BOTH origins
   to be known: an absent one is "nobody said", never "the same source".
5. **A HEP sender past the table bound gets no ordinal at all.** The label
   carries a capture-agent id an unauthenticated peer chooses, so the table is
   attacker-growable and shares the rate limiter's bound. Recycling a counter
   there would mint a second frame 0 for a source that already had one — two
   datagrams with one name, which is the collision the pointer system exists to
   prevent.
6. **The one the plan did not anticipate: `PACKET_FANOUT`.** `--cores N` on a
   live device opens N sockets that all stamp the SAME device name, so a counter
   per socket would mint `eth0#0` from each of them — the same collision as (5)
   in the live reader. A grouped socket therefore stamps nothing, which is
   `--cores`' pre-stage-two behavior rather than a regression. See
   [`docs/design/live-fanout.md`](https://github.com/NormB/sipnab/blob/main/docs/design/live-fanout.md) §2.3.

**What this stage did not close.** `capture_live_fanout` needs a real device and
`CAP_NET_RAW`, so no test drives its loop: the live ordinal is covered by the
counter's own tests plus the packet-to-stream propagation test, and the one line
joining them is covered by review. And a live or HEP pointer still resolves to
`ResolveError::Unreadable` rather than to a variant naming a source whose bytes
were never stored — a missing answer rather than a wrong one, which is the safe
direction, but a `FrameSource` variant for it would be more honest and is left
for whoever needs to follow one.

### Stage 3 — Multi-node — **OPEN**

**Value alone:** yes, and it is the positioning payoff — but only after stage two,
because it is unsafe without the node dimension F2 describes.

**Scope:** key `sdp_endpoints` on `(node, addr, port)` where node comes from the
HEP capture id, so two sites advertising the same RFC 1918 socket stop colliding;
`--multi-device` composed with a HEP member; whatever the TUI needs to show more
than one source.

**Tests:** the stage-one collision test inverts — two nodes, same socket, two
dialogs, each stream binds to its own node's dialog; a stream whose node cannot
be determined stays orphaned rather than guessing.

## 8. What would make this not worth doing

Four things, ranked by how likely each is to be true.

**1. Relayed media makes it inert (F1) — the real risk. ANSWERED: no.** The
worry was that most OpenSIPS deployments reaching for this run rtpengine, so the
mirrored SDP would describe endpoints the local NIC never sees and the feature
would ship as a no-op with a good story. The measurement below refutes it at
transaction tracer scope and confirms it at message scope, which turns the risk
from "does this work at all" into "say which `trace()` scope it needs".

### 8.1 The measurement (F1)

Taken 2026-08-20 on an isolated harness built from the repo's own images —
OpenSIPS **3.6.7** (`eaee48e28`), rtpengine **12.5.1**, SIPp UAC/UAS, one call
carrying twelve seconds of real G.711A. Signaling was mirrored with `proto_hep`
+ `tracer` to a HEP collector; the media path was recorded with `tcpdump`; the
advertised set was every `c=`/`m=` endpoint in every mirrored message, and the
observed set was every socket RTP actually flowed on.

| Run | Tracer scope | Media | Advertised | Observed | Intersection |
| --- | --- | --- | --- | --- | --- |
| 1 | `"t"` (transaction) | rtpengine-anchored | 4 | 4 | **4 of 4** |
| 2 | `"t"` (transaction) | direct, no relay | 2 | 2 | **2 of 2** |
| 3 | `"m"` (message) | rtpengine-anchored | 1 | 4 | 1 of 4 |

**How the both-directions finding was established, rather than assumed.** Run 1
put 11 HEP records on the wire for 13 SIP packets: each traced message appears
twice, distinguishable by the HEP source-address chunk, and the two copies
*differ* — the sent copy of the INVITE carries the added `Record-Route`, the
second `Via`, and the rtpengine-rewritten `c=`/`m=`. That is the outgoing buffer,
not the received one. `tracer.c` arms both `TMCB_MSG_MATCHED_IN` and
`TMCB_MSG_SENT_OUT`, which is the mechanism behind the count.

**What each run means.** Run 1 is the case the design feared and it works
exactly: `172.31.0.10:30030` and `172.31.0.10:30036` were advertised in the
*sent* copies and are precisely the relay-side sockets the capture saw. Run 2
matches too, but is moot at the proxy: with direct media no RTP crosses the
OpenSIPS host at all, so a `-d` capture *there* sees nothing to correlate — the
match existed only because the measurement captured on the shared segment. That
is the topology sentence this feature owes an operator, and it is the opposite of
the one the design expected to have to write. Run 3 is F1 reproduced on demand.

**Four caveats the measurement produced, none of which changes the design:**

1. `proto_hep` refuses to initialize without a HEP *listener* even when the
   config only sends — `No HEP listener defined!`, exit 255. A
   `socket=hep_udp:<ip>:<port>` line is mandatory alongside `hep_id`. Purely an
   OpenSIPS-side documentation point.
2. Match on **both** endpoints of a stream's socket pair, not just the
   capture-local one. Under scope `"t"` either rule works; under `"m"` the single
   advertised endpoint is the stream's *remote* peer, so a local-only rule binds
   zero streams where a both-ends rule binds one. sipnab already does the right
   thing — `resolve_from_sdp` ([`src/rtp/stream_store.rs:1379`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1379)) tries `key.src`
   and `key.dst` — so this is a property to keep rather than one to add.
3. The ACK is never mirrored: it is end-to-end and outside the INVITE server
   transaction. No SDP rode on it here, but a delayed-offer call puts the ANSWER
   in the ACK, and that answer would be absent from the HEP feed. Not measured.
4. rtpengine advertises the RTCP port only via `a=rtcp:` (30031, 30037), never in
   `m=`/`c=`. `extract_sdp_links` reads `m=`/`c=`, so those sockets are unknown to
   it. No RTCP flowed in these runs, so whether that produces real orphans is
   unconfirmed.

Dialog scope (`"d"`) was not measured.

**2. Mis-attribution outweighs the gain.** F2 and F3 are real, and a stream
attributed to the wrong dialog is worse than an orphan because it arrives looking
like a measurement. The staging answers this directly: stage one confines the
feature to one HEP node, and stage three does not open multi-node until the node
dimension exists. If that ordering slipped — multi-node before the key change —
the feature would start producing confident wrong answers, and that is a reason
to stop rather than a reason to hurry.

**3. Duplicate observation is worse than expected (F6).** If operators routinely
capture with no BPF filter and see every message twice, doubled message ladders
would arrive as bug reports about sipnab rather than about the invocation. The
mitigation is help text and one line of guidance; if it turns out not to be
enough, a duplicate detector is a larger piece of work than the feature it
protects.

**4. Only the transmit-guard interaction is delicate.** §6.2 is the one place
this feature could weaken a security property, and it does so only if the permit
rule is written as "any member is live". Written conjunctively it is stronger
than today's, because it forces every future member to justify itself. Cheap to
get right, catastrophic to get wrong, and one test pins it.

### The alternative, if the answer is stop

Keep the sources separate and make the limitation explicit, which is strictly
better than today because today the limitation is *silent*:

1. Ship stage 0 regardless. `-d` beating `-L` without a word is a wrong answer an
   operator has no way to detect.
2. Document the two-process workaround honestly: one sipnab on `-L` for
   signaling, one on `-d` for media, and no correlation between them. State the
   cost — no media attached to a HEP-delivered dialog, in either process —
   instead of leaving it to be discovered.
3. Name the topology in which the workaround is the *right* answer anyway. Where
   media never crosses the machine running the mirror, no single process could
   have correlated them, and no amount of design changes that.

## 9. Open questions

Things this design could not settle from the code alone.

- ~~**Does the mirrored SDP match the wire in a real OpenSIPS deployment?**~~
  **Answered** — §8.1. Yes at tracer scope `"t"`, exactly and in both the relayed
  and direct topologies; no at scope `"m"`, where F1 reproduces.
- **Does a delayed-offer call's SDP answer survive the mirror?** New, from §8.1
  caveat 3: the ACK is end-to-end and outside the INVITE server transaction, so
  the tracer never sees it. A call whose answer rides on the ACK would advertise
  only the offer, and half the media would be unattributable. Unmeasured.
- **Do `a=rtcp:` ports need reading?** New, from §8.1 caveat 4: rtpengine
  advertises the RTCP socket only there, and `extract_sdp_links` reads `m=`/`c=`.
  Whether that produces real orphans is unconfirmed — no RTCP flowed in the runs.
- **Does OpenSIPS mirror RTCP over HEP in practice?** `HepProtocol`
  ([`src/capture/hep.rs:811`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L811)) parses protocol type 5 as RTCP, and SRC1 says such a
  report has nothing to attach to. Whether it becomes attachable once the NIC
  supplies the stream depends on whether the HEP path reaches RTCP ingestion at
  all, which this design did not trace.
- **How much HEP loss does a shared slot pool cause under a live burst?** §5.2
  establishes that nothing counts it. Unmeasured, and this page follows the
  repo's standing rule against upgrading a reasoned claim to a measured one.
- **What should the TUI show for two sources?** `capture_mode`
  ([`src/tui/mod.rs:157`](https://github.com/NormB/sipnab/blob/main/src/tui/mod.rs#L157)) is one string rendered by
  [`src/tui/render/status.rs:117`](https://github.com/NormB/sipnab/blob/main/src/tui/render/status.rs#L117), which branches on an `Online`/`Offline` prefix.
  Deferred to stage three rather than guessed at here.

## 10. SRC2 — comparing the two witnesses

**Status: SHIPPED.** Backlog **SRC2**, built on stage 2's provenance.

Stage 2 tagged every fact with the source that produced it and stopped there.
Nothing compared the two accounts, so sipnab merged both into one store and said
nothing when they differed. Dan Jenkins reframed why that matters, after using
the composite stage one shipped:

> "i really didn't want to trust HEP from opensips... the whole point is being
> able to see when opensips is doing something wrong, or ive told it to do the
> wrong thing or whatever. so being able to trace TLS purely from what hit the
> box is fantastic"

HEP reports what the proxy BELIEVES it did. The wire reports what actually left
the box. When the question under investigation is "is OpenSIPS misbehaving, or
did I configure it to", a mirror produced by the suspect cannot answer it — it
is the same witness twice. That makes the two sources complementary rather than
redundant, and it makes their DISAGREEMENT the finding rather than an
inconvenience to reconcile.

### 10.1 The trap: the mirror arrives first

The HEP mirror is usually FIRST. The proxy mirrors as it processes, while the
copy on the wire takes a network hop and a kernel queue to reach the same
process — the same inversion §3.3 F5 describes for media. So any rule shaped
"first one wins" silently makes the proxy's account authoritative, and checking
that account is the entire reason the wire capture exists.

Three properties of `detect_source_disagreement`
([`src/sip/diagnosis.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/diagnosis.rs)) keep that from happening, and none of them is a
convention a later edit can quietly drop:

1. **The pairing key is content, never position.** Two copies pair on
   `(request?, status, method, CSeq, top-`Via` branch)` — [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) §17.1.3 and
   §17.2.3 transaction identity. Which copy the pipeline saw first cannot change
   which copies pair, or whether they pair at all.
2. **Both accounts are reported by name.** `SdpDivergence` carries `mirror` AND
   `wire`. There is no `expected` field for a surface to render as the truth and
   no `actual` field to render as the deviation.
3. **The two gap lists come from ONE expression applied twice with the arguments
   swapped.** A rule favouring either witness would have to be written into that
   single closure, where it is visible, rather than emerging from two
   similar-looking blocks that drifted apart.

`the_mirror_arriving_first_does_not_make_it_the_reference` runs the same ladder
in both arrival orders and demands the same per-source answer from each.

### 10.2 What is reported, per call

Four states, and each reads differently:

- **Agreed** — `agreed`, the count of messages both witnesses carried. The
  denominator: "2 of 14" is diagnostic and "2" is not.
- **Mirror-only** — the proxy believes it sent something this capture never saw
  leave the box.
- **Wire-only** — the box did something its own trace does not admit to.
- **Differing** — both carried the message and each advertised different media
  endpoints. A rewrite: sometimes the SBC doing its job, sometimes the bug, and
  nothing at this layer can tell those apart, which is why both addresses travel.

It is detection 9 on `SignalingDiagnosis`, so it reaches every surface the eight
before it reach — `--call-report` in all three formats, `--json-dialogs`, the
REST dialog routes and MCP's `diagnose_call` — through the machinery those
already share, and it is omitted rather than nulled for the reason
`icmp_unreachable` is: a `null` would claim a comparison that never ran.

### 10.3 The gate, and what it costs a single-source run

The comparison runs only when BOTH witnesses carried at least one message of
THIS call.

Gating on the RUN instead — "the process was started with `-d` and `-L`" — was
rejected, and the reason is the filter this feature's own warning pushes an
operator towards. `composite_filter_warning` exists because the auto-generated
BPF filter is signaling-only and a composite run wants media, so the operator
writes a media-only filter and the wire then carries no signaling at all. Under
a run-level gate every call in that deployment comes out mirror-only, and a
finding on every call is a finding on none.

On a single-source run the gate is one pass of `Copy`-byte comparisons that
stops as soon as both witnesses are known to have spoken, allocating nothing.
The index, the pairing and every `String` are past the early return.

### 10.4 What this deliberately cannot say

**A call ONE witness never saw at all.** From inside such a call there is no way
to tell a proxy that mirrored a phantom from a witness that was not watching
that call's signaling — TLS it cannot decrypt, a BPF filter excluding the port,
a mirror not configured for that traffic. Separating those needs capture-wide
evidence this detection is not given.
`a_whole_call_only_the_mirror_saw_is_not_reported_as_a_disagreement` pins the
limit so a later change to it is visible as a change.

**A dropped packet against a message a source never carried.** They look
identical here. That is the nature of the comparison and the reason this is a
finding to investigate rather than a verdict; the hint says so in the words a
reader sees.

**A uprobe source paired with anything.** `-d` beats `--uprobe-tls` and
`--uprobe-tls` beats `-L`, both with a warning, so uprobe never composes and a
third pairing would be untested code answering a question no run can ask. When
one becomes possible, `detect_source_disagreement`'s gate is where it goes.

**A rank in `--analyze`.** Detection 8 has a `FindingKind`
([`src/analysis.rs`](https://github.com/NormB/sipnab/blob/main/src/analysis.rs)) and this one deliberately does not. All four
severities describe what happened to the CALL, or to sipnab's own reading of
the input: `Blind` means sipnab did not read part of the capture, `Critical`
that nobody could hear, `Major` that the call failed, `Minor` that something
degraded. A disagreement between two witnesses is a statement about the
EVIDENCE, and every one of those tiers would mis-say it — `Blind` most of all,
because it would assert that sipnab missed the message when the whole point is
that the proxy may have reported one it never sent. It belongs in a tier
`--analyze` does not have, and adding one is a larger change than this item.

### 10.5 Tests

Unit tests live beside the detection in [`src/sip/diagnosis.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/diagnosis.rs); the
end-to-end ones drive the real pipeline from
[`tests/composite_source_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/composite_source_test.rs).

- Mirror-only — `a_message_only_the_mirror_reported_is_named_as_mirror_only`,
  and `a_message_only_the_mirror_reported_reaches_the_report_and_the_json` for
  the surfaces.
- Wire-only — `a_message_only_the_wire_carried_is_named_as_wire_only`.
- Differing in SDP — `matched_messages_whose_sdp_differs_report_both_addresses`,
  `an_sdp_rewritten_between_the_two_witnesses_reaches_the_dialog_json`.
- The trap — `the_mirror_arriving_first_does_not_make_it_the_reference`.
- Agreement is not a finding —
  `two_witnesses_that_agree_on_every_message_report_nothing`.
- Single source is silent — `a_single_source_run_reports_no_source_disagreement`,
  `a_single_source_run_carries_no_source_disagreement`,
  `messages_with_no_recorded_origin_report_nothing`,
  `a_uprobe_source_is_not_compared_against_the_wire`.
- The documented limit — `a_whole_call_only_the_mirror_saw_is_not_reported_as_a_disagreement`.
- Retransmissions pair by count — `a_retransmission_the_wire_missed_is_one_gap_not_three`.
- The finding is not silently clean — `a_source_disagreement_alone_makes_the_diagnosis_non_empty`.
- The hint — `the_disagreement_hint_names_both_witnesses`.
- The wire shape matches its schema —
  `the_disagreement_json_validates_against_the_call_report_schema`.
