# Encapsulations

Whether sipnab can read the SIP in your capture when something wraps it: a
VLAN tag, an MPLS label, a tunnel. The first table answers that. The sections
after it give the exact link types, EtherTypes and tunnels, and what sipnab
reports when a frame does not decode.

## Can sipnab read my capture?

| Your SIP travels inside… | From a capture file | From a live capture |
|---|---|---|
| Ethernet, Linux cooked (`any`), raw IP, loopback, PPP or PPPoE | yes | yes |
| VLAN tags: 802.1Q, 802.1ad, QinQ, or legacy `0x9100` | yes | yes |
| MPLS | yes, from an Ethernet capture. Not from a Linux cooked one | name the interface with `-d`, because the default `any` device produces a cooked capture |
| NSH, PBB or MACsec | yes, from an Ethernet capture. MACsec only when it protects integrity without encrypting | name the interface with `-d` and pass your own BPF filter that adds them, such as `portrange 5060-5061 or ether proto 0x88e5` for MACsec |
| IP-in-IP, 6in4, GRE, GRE bridging, MPLS-in-IP or AH | yes | pass your own BPF filter that adds them, such as `portrange 5060-5061 or ip proto 47` for GRE, because the generated one matches UDP and TCP ports only |
| GTP-U, VXLAN or GENEVE | yes | add `--capture-tunnels` |
| Teredo or L2TPv2 | yes (L2TPv2 data messages only) | add `--capture-tunnels=3544` or `--capture-tunnels=1701` |
| ESP | only when NULL-encrypted | pass your own BPF filter that adds it, such as `portrange 5060-5061 or ip proto 50` |
| UDP-encapsulated ESP, or L2TPv3 over UDP | no | no |
| anything else | no | no |

Whenever the answer is no, sipnab says so. It counts the frames it cannot decode
in a `NOT DECODED` line at the end of the run, with the number that identifies
each: the link type, the EtherType or the IP protocol. [What sipnab says when
it cannot read a frame](#what-sipnab-says-when-it-cannot-read-a-frame) shows
that line.

## What sipnab says when it cannot read a frame

sipnab drops nothing on this page silently. A frame it does not decode still
increments a counter keyed by the number it did not recognize, and that count
reaches the run summary, `--report`, `--json`, `/v1/stats`, MCP
`capture_status`, and the Prometheus capture family:

```text
NOT DECODED: 3 of 3 frame(s) (100.0%) produced nothing and are in none of the
counts above. Reasons: unsupported link type 147 (3). NOTHING IN THIS CAPTURE
WAS READ — every frame failed to decode, so the totals above describe no
traffic whatsoever and a zero among them is not evidence of absence.
```

A capture with no SIP *and* no undecodable frames is a finding: the SIP is not
there. One with no SIP and a pile of undecodable frames means sipnab could not
read it, which is a different problem.
[Troubleshooting](troubleshooting.md#start-here-one-pass-over-everything) says
what each reason means and what to do about it.

## The rule that governs decapsulation

Over-eager decapsulation is worse than the silence it replaces.

A silent drop loses a call. A false decapsulation **invents** one — inner
addresses, inner ports, an inner dialog — assembled from bytes that never
described any of it, with nothing marking the flow fictional.

This bites hardest on port-keyed tunnels. A UDP port is not a protocol
identity: 2152, 4789 and 6081 all occur as the *ephemeral source* port of
ordinary RTP media. So every decapsulator validates structurally — reserved
bits, version fields, length self-consistency, the shape of the first inner
header — and declines the moment anything disagrees. Each port-keyed decoder
has a test proving it rejects a realistic RTP packet arriving on its own port.

When the choice is between missing a tunnel and fabricating a flow, sipnab
misses the tunnel. A miss stays visible. A fabrication does not.

## Link types

| DLT | Name | Status |
|---|---|---|
| 1 | Ethernet | decoded |
| 0 | BSD loopback (`DLT_NULL`) | decoded — address family in host byte order |
| 108 | OpenBSD loopback (`DLT_LOOP`) | decoded — address family always big-endian |
| 12 | Raw IP (`DLT_RAW`) | decoded — the version nibble picks v4 or v6 |
| 113 | Linux cooked v1 (`SLL`) | decoded |
| 276 | Linux cooked v2 (`SLL2`) | decoded |
| 9 | PPP (`DLT_PPP`) | decoded — with or without [RFC 1662](https://www.rfc-editor.org/rfc/rfc1662) HDLC-like framing |
| 50 | PPP in HDLC-like framing (`DLT_PPP_SERIAL`) | decoded |
| 51 | PPPoE session (`DLT_PPP_ETHER`) | decoded |
| 228 | bare IPv4 (`DLT_IPV4`) | decoded — sipnab checks the version nibble against the link type and rejects a mismatch |
| 229 | bare IPv6 (`DLT_IPV6`) | decoded — same check, the other way |
| any other | — | **counted and named** as `unsupported link type N` |

Loopback is `DLT_EN10MB` on Linux but `DLT_NULL` on macOS and BSD, which is why
0 and 108 matter for the common "SIP server listening on loopback" case.

The parser dispatches on that closed set rather than on the raw number, and the
cheap `--cores` shard key dispatches on the same one. Adding a link type is a
compile error in both until each has an arm, so the two walks cannot come to
know different sets.

## EtherTypes

| EtherType | Protocol | Reference | Status |
|---|---|---|---|
| `0x0800` | IPv4 | [RFC 894](https://www.rfc-editor.org/rfc/rfc894) | decoded |
| `0x86DD` | IPv6 | [RFC 2464](https://www.rfc-editor.org/rfc/rfc2464) | decoded |
| `0x8100` | C-VLAN tag | IEEE 802.1Q | skipped to reach IP |
| `0x88A8` | S-VLAN tag | IEEE 802.1Q | skipped to reach IP |
| `0x9100` | legacy QinQ | **unregistered** | skipped to reach IP |
| `0x8864` | PPPoE Session | [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516) | decapsulated |
| `0x8863` | PPPoE Discovery | RFC 2516 | never decapsulated — counted and named like any EtherType sipnab does not walk |
| `0x8847` | MPLS unicast | [RFC 5332](https://www.rfc-editor.org/rfc/rfc5332) | decapsulated |
| `0x8848` | MPLS upstream-assigned | RFC 5332 | decapsulated |
| `0x894F` | NSH | [RFC 8300](https://www.rfc-editor.org/rfc/rfc8300) | decapsulated |
| `0x88E7` | PBB I-TAG | IEEE 802.1Q | decapsulated to the customer frame |
| `0x88E5` | MACsec | IEEE 802.1AE | see below |
| any other | — | — | **counted and named** with its hex value |

`0x9100` is genuinely absent from the IEEE RA listing — no assignee, no
protocol text — while every neighbor has both. No standards body ever
registered it: it is legacy vendor usage, still common on older carrier gear.
Supporting it concedes to deployed equipment rather than to any specification.
Do not "correct" it away after checking a registry and finding nothing.

PPPoE Discovery is deliberately never decapsulated: its payload is TLV tags, so
reading it as an IP header would report addresses the wire never carried.

### MACsec is not always encrypted

The SecTAG's `E` and `C` bits distinguish confidentiality from integrity.
sipnab decodes an integrity-protected frame that carries **no** encryption as
the ordinary readable plaintext it is. Only a genuinely encrypted payload gets
reported as encrypted. Treating all of `0x88E5` as opaque would write off
recoverable calls.

IEEE 802.1AE's own Annex C conformance vectors settled those bit positions,
because Figure 9-4 of the 2018 standard is defective — it labels two bits with
names appearing nowhere else in the document.

### A cooked capture reaches fewer of them

The table above describes the **Ethernet** walk. A Linux cooked capture — `SLL`
or `SLL2` — runs a shorter one: VLAN tags, then IPv4, IPv6 or PPPoE Session, and
nothing else. That matters more than it sounds, because `SLL2` is what the `any`
pseudo-device produces, and `any` is what sipnab opens on Linux when no `-d`
names an interface.

| EtherType | Ethernet (`-d eth0`) | Cooked (`any`, `-i any` files) |
|---|---|---|
| `0x8100` / `0x88A8` / `0x9100` VLAN | skipped to reach IP | skipped to reach IP |
| `0x0800` / `0x86DD` IP | decoded | decoded |
| `0x8864` PPPoE Session | decapsulated | decapsulated |
| `0x8847` / `0x8848` MPLS | decapsulated | **not walked** |
| `0x894F` NSH | decapsulated | **not walked** |
| `0x88E7` PBB I-TAG | decapsulated | **not walked** |
| `0x88E5` MACsec | decoded, or named as encrypted | **not walked** |

So SIP inside an MPLS label stack reaches the parser from `-d eth0` and does not
from the default device. A frame the cooked walk declines invents nothing — it
fails to decode and joins the undecodable count with its own reason — but the
remedy is the capture device rather than the filter. **Name the interface when
the link carries any of the bottom four.**

The same asymmetry applies to a saved file: a capture somebody took with
`tcpdump -i any` carries the cooked link type, and no sipnab flag can put back
what the walk does not follow.

## Tunnels above the link layer

| Encapsulation | Key | Reference | Status |
|---|---|---|---|
| IP-in-IP / 6-in-4 | IP proto 4 / 41 | [RFC 2003](https://www.rfc-editor.org/rfc/rfc2003) / [RFC 4213](https://www.rfc-editor.org/rfc/rfc4213) | decoded |
| GRE | IP proto 47 | [RFC 2784](https://www.rfc-editor.org/rfc/rfc2784) | decoded |
| GRE Transparent Ethernet Bridging | GRE proto `0x6558` | [RFC 7637 section 3.2](https://www.rfc-editor.org/rfc/rfc7637#section-3.2) | decoded |
| MPLS-in-IP | IP proto 137 | [RFC 4023](https://www.rfc-editor.org/rfc/rfc4023) | decoded |
| AH | IP proto 51 | [RFC 4302](https://www.rfc-editor.org/rfc/rfc4302) | **traversed** — AH authenticates without encrypting, so the payload is readable |
| ESP | IP proto 50 | [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303) | **decoded when NULL-encrypted** — see below; otherwise named, never guessed |
| GTP-U | UDP 2152 | 3GPP TS 29.281 | decoded |
| VXLAN | UDP 4789 | [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348) | decoded |
| GENEVE | UDP 6081 | [RFC 8926](https://www.rfc-editor.org/rfc/rfc8926) | decoded |
| Teredo | UDP 3544 | [RFC 4380](https://www.rfc-editor.org/rfc/rfc4380) | decoded |
| UDP-encapsulated ESP | UDP 4500 | [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948) | encrypted — sipnab names it, never guesses |
| L2TPv2 | UDP 1701 | [RFC 2661](https://www.rfc-editor.org/rfc/rfc2661) | data messages only |
| L2TPv3 over UDP | UDP 1701 | [RFC 3931](https://www.rfc-editor.org/rfc/rfc3931) | **refused** — see below |

**L2TPv3 over UDP is deliberately not decoded.** [RFC 3931 section 4.1](https://www.rfc-editor.org/rfc/rfc3931#section-4.1) says:

<!-- vale off -->
> The Session ID alone provides the necessary context for all further packet
> processing, including the presence, size, and value of the Cookie.
<!-- vale on -->

The cookie runs to 0, 4 or 8 octets, and only the control channel carries that
length — along with the pseudowire type. Guessing between those is precisely
how a decapsulator invents a flow.

**sipnab reads ESP only when the payload proves NULL encryption.** An IMS core commonly
protects the Gm interface between a phone and its P-CSCF with IPsec ESP, and a
lab or test network often runs it with NULL encryption ([RFC 2410](https://www.rfc-editor.org/rfc/rfc2410)): the
SIP travels in the clear inside an ESP header and trailer.

Nothing in the ESP
header says which, so sipnab reads the payload as NULL-encrypted only when all
of these hold: an integrity check value of 12, 16, 24 or 32 octets, the
default padding of [RFC 4303 section 2.4](https://www.rfc-editor.org/rfc/rfc4303#section-2.4) and 4-octet alignment, a next
header of TCP or UDP, and a TCP or UDP header that fits the recovered segment
and whose checksum verifies. A UDP checksum of zero means "none" and passes
over IPv4 only, as [RFC 768](https://www.rfc-editor.org/rfc/rfc768) and [RFC 8200 section 8.1](https://www.rfc-editor.org/rfc/rfc8200#section-8.1) allow.

A frame that fails any of them joins the
`NOT DECODED` line as `ESP not NULL-encrypted (IP protocol 50)`. sipnab
takes no keys for encrypted ESP, so capture inside the tunnel instead.

**One shared budget bounds nesting.** It covers every layer of a frame, so a
frame combining MACsec, MPLS, GTP-U and IP-in-IP cannot walk further than one
using a single encapsulation repeatedly. sipnab refuses an over-nested frame
rather than following it.

## Live capture needs the tunnel-aware filter

Give sipnab no BPF expression of your own — the trailing argument, or a file
named by `--bpf-file` — and it generates one that matches SIP inside VLAN, QinQ,
PPPoE Session and MPLS as well as untagged traffic. Do not confuse that with
`--filter`, which is sipnab's own matching language over messages sipnab already
decoded, long after the kernel has made its decision.

**UDP-tunneled SIP is not covered by default**: BPF cannot parse a
variable-length GTP-U header to reach the inner port, so covering those means
capturing every packet on those ports. Use `--capture-tunnels` to opt in — see
the [CLI reference](cli-reference.md#capture).

The encapsulated arm compiles on `SLL` and `SLL2` as well as on Ethernet,
because it selects the encapsulation through libpcap's `ether proto`, which
libpcap resolves to the right offset for each link type while compiling. So the
kernel hands those frames up whichever device you opened. What sipnab makes of
them afterwards still depends on the link type — an MPLS frame arrives on the
default device and the cooked walk does not follow it, as the table above says.

Writing your own expression replaces the generated one whole. sipnab never edits
it, so the encapsulated arm goes away and `--capture-tunnels` turns inert. Two
warnings cover that: one when a port-based expression shows no sign of handling
encapsulation, and one naming `--capture-tunnels` as ignored when you passed it
alongside a filter of your own.

One limit worth knowing before you rely on a live capture: on the encapsulated
arm, an IPv4 header carrying **options** stays unmatched, because a BPF index
has to be constant and the arm cannot multiply the IHL nibble. The untagged arm
handles those.

### How the generated filter reaches encapsulated SIP

On a live capture with no filter of your own, sipnab installs one built from
`--portrange`. It is not a bare `portrange 5060-5061`: that one matches the
outer headers only, so on a tagged trunk, a PPPoE access link or an MPLS
core it matches **nothing**, and the kernel discards the frames where no
sipnab counter, metric or report can see them. You get "No SIP traffic
found" on a link carrying calls.

The generated filter adds an encapsulated arm instead, covering one VLAN tag
(802.1Q, 802.1ad or 0x9100), QinQ, PPPoE Session, VLAN over PPPoE, and one or
two MPLS labels, for IPv4 and IPv6, UDP and TCP. The arm still demands a
signaling port, so it matches more of the *same* traffic, not a new class of
it: VLAN-tagged RTP reaches sipnab no more often than untagged RTP did.

**It covers cooked captures too**, so omitting `-d` costs the filter nothing, although the cooked walk still
skips MPLS, as [A cooked capture reaches fewer of them](#a-cooked-capture-reaches-fewer-of-them) says.

The arm asks "does this frame carry an encapsulation?" through libpcap's
`ether proto`, which resolves to the right byte offset for whatever link type
the filter compiles against — offset 12 on Ethernet, 14 on Linux cooked v1,
0 on Linux cooked v2, and a constant false on raw IP and the two loopback
link types, which carry no protocol field at all. Measured on a capture of
each type with `tcpdump -d`.

Asking the same question with a fixed `ether[12:2]` is the trap this avoids.
That offset holds the EtherType on Ethernet and part of the link-layer
address on a cooked capture, so an arm written that way compiles, runs and
matches nothing there: 1 of 11 encapsulated SIP frames on cooked v1 and
cooked v2, against 11 of 11 on Ethernet. Cooked is what Linux gives you when
you name no interface, so that shape would have left the default invocation
blind.

Two limits worth knowing. On the encapsulated arm an IPv4 header carrying
**options** stays unmatched. A BPF byte offset has to be a constant, so the
arm cannot multiply the IHL nibble into the port offset the way libpcap's own
`portrange` does. The untagged `portrange` handles those, so this costs you
only IPv4-options traffic that is *also* encapsulated.

And one filter string serving three link types has to carry all three sets of
inner offsets, because BPF offers no way to ask which link type it compiled
against. Seven offsets get probed on every link type, four of which belong to
a different link header.

Those four can fire only on a frame that already
carries one of the six encapsulating protocols, and only if its bytes at the
wrong offset spell a complete IPv4-or-IPv6 header with a signaling port —
so the worst case is a stray tagged packet reaching userspace, where the
parser rejects it. Ordinary traffic never reaches those probes, because the
outer `ether proto` test is exact.

## STUN and TURN

sipnab reads STUN ([RFC 5389](https://www.rfc-editor.org/rfc/rfc5389)) and TURN
([RFC 5766](https://www.rfc-editor.org/rfc/rfc5766)) because they are the first
link in a one-way-audio chain, not because it is an ICE agent. What it takes
from them is what changes a diagnosis: whether an endpoint asked, whether
anything answered, and which address the answer named.

Three protocols share these ports, and they separate cleanly on the two high
bits of the first byte — STUN `00`, TURN ChannelData `01`, RTP `10` — so
checking STUN before RTP cannot swallow media.

| Read | Why |
|---|---|
| Header: type, length, magic cookie, transaction ID | The parser checks the cookie before believing anything else, which is what makes it safe to offer it every UDP payload |
| Class and method | `Binding` and TURN's `Allocate`, `Refresh`, `Send`, `Data`, `CreatePermission`, `ChannelBind`. An unknown method reports as its number rather than as "unknown", because the number is the thing to look up |
| `XOR-MAPPED-ADDRESS` | The answer the endpoint asked for, and what it then writes into its SDP |
| `XOR-RELAYED-ADDRESS`, `XOR-PEER-ADDRESS`, `LIFETIME` | The TURN equivalents: the address a relay allocated, who a permission is about, and how long it lasts |
| `ERROR-CODE` | So a refusal reads as a refusal. A server that says no is reachable, which is a different fault from silence |
| `SOFTWARE` | Names the stack, which tells one vendor's retransmission pattern from the next |
| `MAPPED-ADDRESS` (legacy) | The pre-RFC5389 form. Servers older than the cookie still answer with it, and without reading it their successful response reads as no answer at all. When both forms arrive the XOR one wins, whatever order they come in |
| `ALTERNATE-SERVER` | So a `300` redirect names where it points instead of reading as a dead end |
| `REALM`, `NONCE` | A `401` with a realm is an authentication challenge, not a blocked path, and each sends you somewhere different. sipnab records the nonce as present only: its value is a server-chosen opaque string that means nothing to an observer |
| `FINGERPRINT` | Verified. A CRC-32 over the message with no key involved, so a passive reader can check it honestly -- and it is what separates a real STUN message from a payload that merely carried the cookie bytes. Reported as verified, present-and-wrong, or absent, which stay distinct |
| ICE `USE-CANDIDATE`, `PRIORITY`, `ICE-CONTROLLING`/`ICE-CONTROLLED` | The nomination is the finding: without it, an ICE exchange that converged and one that never did look alike. Both sides claiming controlling is a role conflict whose only other symptom is media that never starts |
| TURN `CHANNEL-NUMBER`, `REQUESTED-TRANSPORT` | So sipnab can describe a relay path, not merely detect one |
| ChannelData framing | sipnab recognizes **and unwraps** it, so RTP relayed through TURN reaches reconstruction. Without that a relayed call reports as having no media — the same answer sipnab gives for a call that carried none, which are opposite findings |

sipnab tracks transactions, so it reports a request that never came back along
with the number of attempts. A retransmission is one unanswered question, not
several. An error response counts as ANSWERED.

### What is deliberately not read

`MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256` decide whether a message is
**authentic**, and a passive observer has no credentials to check them with.
Reading them and reporting anything about them would be claiming a verification
that did not happen — the same confident-wrong-answer this codebase refuses
elsewhere. sipnab reads `USERNAME`, `REALM` and `NONCE` for what they SAY — an
authentication challenge is a different fault from a blocked path — never as
evidence that authentication succeeded.

sipnab is not an ICE agent and does not evaluate candidate pairs, compute
priorities, or decide nominations. It reports what it saw on the wire.

## How this page stays true

An end-to-end test backs every "decoded" row for a tunnel, in
[`tests/tunnel_integration_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/tunnel_integration_test.rs) that carries a real INVITE through
`parse_packet` into the SIP parser and asserts the method and Call-ID —
MPLS, MPLS-in-IP, NSH, PBB, MACsec (integrity-only), VXLAN, GTP-U, GRE-TEB and
AH each have one. PPPoE and the loopback link types have their own suites.

GENEVE, Teredo and L2TP rely on unit tests over crafted frames rather than an
end-to-end INVITE. That is a weaker proof, and this page says so rather than
letting the table imply otherwise.

No measurement on this page comes from a live NIC.

## Sources

The **IEEE Registration Authority** assigns EtherTypes, not IANA.
[RFC 9542](https://www.rfc-editor.org/rfc/rfc9542.html) states it plainly:

<!-- vale off -->
> Neither EtherTypes nor LSAPs are assigned by IANA; they are assigned by the
> IEEE Registration Authority.
<!-- vale on -->

The EtherType values on this page come from the IEEE RA public
listing at <https://standards-oui.ieee.org/ethertype/eth.txt>, retrieved
2026-08-04, cross-checked against IANA's *informational* mirror at
<https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>,
whose own header reads *"Not assigned by IANA."*

This is the one place the project's "when in doubt, use the RFC" rule does not
resolve on its own: for EtherTypes the RFC hands the question to a different
standards body. Use the IEEE RA listing for the *value* and the current RFC for
the *semantics*.

### Two errors in the IEEE listing

Registries are no more infallible than RFCs, and both of these would mislead
someone implementing from the listing alone.

- **`0x8848` carries the wrong protocol text.** The listing gives it
  `"8847: MPLS (multiprotocol label switching) label stack - unicast"` — the
  `0x8847` entry duplicated, wrong identifier and wrong cast.
  [RFC 5332](https://www.rfc-editor.org/rfc/rfc5332.html) assigns `0x8848` to
  MPLS with an **upstream-assigned** label.
- **`0x894F` cites a superseded draft**, `draft-ietf-sfc-nsh-18`, published as
  [RFC 8300](https://www.rfc-editor.org/rfc/rfc8300.html) in January 2018. That
  one is *stale rather than wrong* — the draft and the RFC define the same
  header — and the two cases do not belong in the same bucket.

<details>
<summary>Why / how we know</summary>

sipnab used to answer a question it had not understood. Given a capture whose
frames it could not decode, it reported:

```text
sipnab: 49 packets captured, 0 SIP messages, 0 RTP packets across 0 streams
No SIP traffic found. Check that the capture contains SIP packets (typically UDP port 5060-5061).
```

That output was identical whether sipnab had read every frame and found no SIP,
or had failed to read a single frame of a capture full of INVITEs. Two such
captures were in this repository's own test corpus.

A missed encapsulation is now **counted and named**, with the number that
identifies it — the link type, the EtherType, the IP protocol. See
[Troubleshooting](troubleshooting.md#start-here-one-pass-over-everything) for what each reason means.

</details>
