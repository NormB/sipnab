# Troubleshooting

> **Under pressure?** Each scenario below is: Problem, Command, What to look for, Next steps. Copy-paste and go.

## Find your symptom

Match the complaint, not what you think is wrong -- the section works back to
the cause from there.

| What the caller says | Section |
|---|---|
| "It just says the number is unavailable" / call never connects | [Failed calls](#failed-calls) |
| "It rings and rings, then nothing" / 408, or no response at all | [Nothing came back](#nothing-came-back-408-or-silence-ask-the-network) |
| "It hangs up after 30 seconds" / after exactly 15 or 30 minutes | [Dropped calls](#dropped-calls-call-answers-then-disconnects-mid-conversation) |
| "Calls to that one carrier fail immediately" / 488 | [488 Not Acceptable Here](#488-not-acceptable-here-codec-mismatch) |
| "They can hear me but I can't hear them" | [One-way audio](#one-way-audio) |
| "It sounds choppy / robotic / underwater" | [Poor call quality](#poor-call-quality) |
| Every call in the capture looks lossy at once | [Poor call quality](#poor-call-quality), then [Tuning capture](tuning-capture.md) -- the loss may be sipnab's, not the network's |
| "There's a long pause before it rings" | [Slow call setup](#slow-call-setup-post-dial-delay) |
| "Audio dies as soon as they answer" / works internally, not externally | [NAT traversal issues](#nat-traversal-issues) |
| "The phones keep dropping off" / no inbound calls arrive | [Registration failures](#registration-failures) |
| "Something is hammering the PBX" / probes across unknown extensions | [SIP scanner detection](#sip-scanner-detection) |
| "No SIP traffic found" on a link you know carries calls | [A live capture that sees nothing](#a-live-capture-that-sees-nothing) |
| Nothing yet -- you have a capture and a complaint | [Start here](#start-here-one-pass-over-everything) |

Whatever the symptom, three things decide whether the answer is in the capture
at all: it covers the right time window, it comes from a point that sees both
directions, and `--portrange` covers the ports in use. The next section deals
with the third.

## Start here: one pass over everything

Don't know which problem you have yet? The `--problems` alias surfaces every
troubled call in a single sweep -- failed calls **plus** one-way audio, high
loss/jitter, NAT mismatches, retransmit storms, slow setup, and media
asymmetries:

```bash
# Every problematic call
sipnab -N -I capture.pcap --problems --json
```

`--problems` is shorthand for the full Filter-DSL expression `state == 'Failed' OR one_way == true OR rtp.loss > 5.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 11.0 OR ...` -- so it is a superset of "failed calls". Once you know the symptom, jump to the matching section below for the precise filter.

> **First, check you are reading the whole capture.** `--portrange` defaults to
> `5060-5061`, and sipnab skips any SIP message whose source and destination
> ports both fall outside it. Skipped messages reach no count, no dialog and no
> output, so a call carried on 5070 or 5080 -- ordinary on carrier trunks and
> SBCs -- is simply not in any answer below. sipnab says so on stderr and again
> at the end of the run:
>
> ```text
> NOT ANALYZED: 1 further SIP message(s) were seen on ports outside --portrange
> and are in none of the totals above. Busiest: 8090 (1).
> ```
>
> If you see that line, or the call you are chasing is missing, add
> `--portrange 1-65535` to every command on this page and start again. On a
> **live** capture the range becomes the kernel BPF filter, so the traffic never
> reaches sipnab and nothing reports it missing -- set the range before you
> capture.

> **Second, check sipnab could read the capture at all.** A frame on a link
> type, EtherType or IP protocol sipnab has no decoder for produces nothing:
> it counts as a packet (it arrived) and contributes to no message, dialog
> or stream. sipnab reports those separately, with the numbers that name them:
>
> ```text
> NOT DECODED: 49 of 49 frame(s) (100.0%) produced nothing and are in none of
> the counts above. Reasons: unsupported link type 0 (49). NOTHING IN THIS
> CAPTURE WAS READ -- every frame failed to decode, so the totals above
> describe no traffic whatsoever and a zero among them is not evidence of
> absence.
> ```
>
> This is the difference between *there is no SIP in this capture* and *I could
> not read one single frame of this*, which the totals alone render identically.
> When the share is high, treat every zero on this page as **unknown**, not as
> a finding, and fix the decode first.
>
> The number in each reason is what you act on:
>
> | Reason | What it means | What to do |
> |---|---|---|
> | `unsupported link type N` | The pcap's DLT has no decoder here. `0` is `DLT_NULL` (BSD loopback), `9` is PPP, `276` is Linux cooked v2. | Convert it: `editcap -T ether in.pcap out.pcap`. If the link type is one sipnab should read, open an issue naming the number. |
> | `not IP (EtherType 0xNNNN)` | The frame decoded and carried no IP. `0x0806` is ARP, `0x8847` MPLS, `0x88CC` LLDP. | ARP and LLDP are ordinary background -- expect a few on any Ethernet capture. A large MPLS or PPPoE share means the mirror is giving you the encapsulated form. |
> | `no transport (IP protocol N)` | IP decoded; its payload is no transport sipnab handles. `50` is ESP, `47` GRE, `89` OSPF. | ESP encrypts the SIP inside it, so the capture cannot yield it; take the capture inside the tunnel instead. |
> | `truncated frame` | The frame is shorter than a header it declares. | Raise `--snaplen` on the capture, or re-take it. |
> | `decode error` | The decoder rejected the bytes outright. | Usually a corrupt or mis-declared file; try `editcap` or `tshark -r` on it. |

---

## Failed calls

Calls rejected with `403 Forbidden`, `404 Not Found`, `486 Busy Here`, `488 Not Acceptable Here`, or timing out with `408 Request Timeout`? Find every call that never established, then triage by response code.

List every failed call, one line per response message, carrying the Call-ID, the response code, and the reason text:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -c 'select(.is_request == false) | {call_id, status_code, reason}'
```

You should see one line per response message of each failed call (minimal example):

```json
{"call_id":"abc123@host","status_code":100,"reason":"Trying"}
{"call_id":"abc123@host","status_code":486,"reason":"Busy Here"}
{"call_id":"def456@host","status_code":408,"reason":"Request Timeout"}
```

Once one of those Call-IDs is worth escalating, write the detailed Markdown report for that single call and attach it to a ticket. Substitute the Call-ID you picked. The redirect overwrites `report.md` in the current directory. `--no-cli-print` is not optional here: without it sipnab dumps every message in the capture ahead of the report, and the file you attach opens with hundreds of lines of raw SIP:

```bash
sipnab -N -I capture.pcap --call-report "abc123@host" --markdown --no-cli-print > report.md
```

**What to look for:** sipnab includes response code intelligence -- the status field tells you why:

| Code | Meaning | Typical fix |
|------|---------|-------------|
| 401/407 | Authentication required | Check credentials, realm mismatch, nonce expiry |
| 403 | Forbidden | ACL/IP allowlist, registration required, call barring |
| 404 | Not found | Bad dial plan, missing route, number not provisioned |
| 408 | Request timeout | Endpoint unreachable, DNS failure, firewall |
| 486 | Busy here | Endpoint occupied, no call waiting |
| 488 | Not acceptable here | Codec mismatch, SDP incompatibility -- full recipe [below](#488-not-acceptable-here-codec-mismatch) |
| 503 | Service unavailable | Upstream overload, trunk down, proxy crash |

**Next steps:** If the response code is 408 or you see high `retransmits`, the problem is network-level -- check connectivity and firewall rules before touching SIP config. The next section turns that "network-level" guess into evidence.

---

## Nothing came back (408, or silence) -- ask the network

A 408 and a call that simply stops both look like "the far end did not answer". Usually that is an inference from silence. Sometimes it is not: if a router or the host itself sent an ICMP error quoting your request, the network stated the cause, and sipnab reads it.

Any run that saw such an error ends with a capture-wide tally on stderr, so you do not have to go looking for it. A run that saw none prints nothing:

```text
ICMP: 4 error(s) quoting a SIP request, naming 2 unreachable endpoint(s).
Busiest: 192.0.2.10:5060 (2, port unreachable), 192.0.2.11:5080 (2, host unreachable).
```

Seeing that line, pull the affected calls out as one object each and read the finding:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.signaling_diagnosis.icmp_unreachable) |
           {call_id, method,
            code: (.final_status_code // .signaling_diagnosis.final_failure.code),
            icmp: .signaling_diagnosis.icmp_unreachable}'
```

Then read one of them in full, which lays the ICMP finding beside the SIP timeline and names the messages it came from:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print
```

```text
Signaling Issues:
  - Final failure: 408 Request Timeout
    evidence: #2 408 Request Timeout
  - ICMP port unreachable: 192.0.2.10:5060 unreachable (2 times), reported by 198.51.100.1
    evidence: #0 OPTIONS, #1 OPTIONS
```

**What to look for:**

| Field | What it tells you |
|-------|-------------------|
| `description` | The network's own words -- `port unreachable`, `host unreachable`, `administratively prohibited`. Each points somewhere different. |
| `unreachable_endpoint` | The socket that did not answer. **This is the machine to go and look at.** |
| `reported_by` | The device that noticed and said so -- usually a working router in the path. Do not send an engineer here. |
| `errors` | Exact count of such errors for this call. Two or three says the peer was consistently unreachable, not momentarily busy. |

**Next steps:**

1. `port unreachable` means the host is up and nothing is listening on that port. Check that the SIP service is running and bound where you think, and that the port in the `Contact`/`Via` matches what it actually listens on. **This is not a network fault.**
2. `host unreachable` or `network unreachable` is a routing problem short of the destination -- the reporter names the hop that gave up. Nothing reached the host, so the capture says nothing about its ports.
3. `administratively prohibited` (v4 codes 9, 10, 13; v6 type 1 code 1) is a **firewall or router ACL, not a dead host**. The peer may be perfectly healthy and answering everyone else. The fix is on the filtering device, and it is a different team from the one you call about an unreachable host. On one real corpus a single capture held 433 host-unreachable and 262 administratively prohibited errors -- treating them the same would have sent an engineer to the wrong device 262 times.
4. No ICMP at all does **not** clear the network: most firewalls drop ICMP errors outright, and the summary can only report what the capture holds.

When a call shows both `retransmissions` and `icmp_unreachable`, read them together rather than as two problems. The retransmission count is how hard the sender tried. The ICMP error is why nothing came back. sipnab annotates the retransmission finding with `icmp_cause` and stops offering its own guess at the reason, but keeps the count -- "11 OPTIONS over 300 s" and "3 INVITEs over 3 s" are the same cause and a very different operational picture.

There is no `icmp` field in the Filter DSL, so select these calls with `jq` on `--json-dialogs` as above rather than with `--filter`.

---

## Dropped Calls (call answers, then disconnects mid-conversation)

The call sets up fine, both sides talk, then it dies partway through -- often after a suspiciously round number of minutes.

Enumerate the calls that established and then ended early -- completed, but far shorter than a real conversation:

```bash
sipnab -N -I capture.pcap --filter "duration < 120.0 AND state == 'Completed'" --json \
  | jq -r '.call_id' | sort -u
```

Then print the timeline for one of those calls -- who sent the BYE, and exactly when. Substitute a Call-ID from the list above for `abc123@host`:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print
```

The call report shows the full SIP message timeline plus per-stream RTP stats (including first/last packet timestamps). Match the signature:

- **BYE at a round interval after answer** (exactly 15 min, 30 min, 1 h -- e.g. 200 OK at `14:00:02`, BYE at `14:30:02`): [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028) **session-timer expiry**. One side never sent (or never received) the session refresh re-INVITE/UPDATE and tore the call down when `Session-Expires` ran out.
- **RTP last packet well before the BYE** (stream `last_seen` minutes earlier than the BYE): a NAT/firewall **idle timeout silently dropped the media path**; the endpoint's RTP-timeout watchdog eventually hung up.
- **BYE from the carrier side, accompanied by SIP retransmits**: trunk-side reset or an upstream element recycling the session.

**Next steps:**

1. Session timer: align `Min-SE` / `Session-Expires` between PBX and trunk, and confirm the negotiated refresher actually sends the refresh before expiry.
2. NAT/firewall: enable RTP keepalives (or comfort noise) on the endpoints, and raise the firewall's UDP session timeout above the keepalive interval.
3. Disable SIP ALG on intermediate NAT devices -- it corrupts dialogs in ways that surface as mid-call drops.

---

<!-- "488 Not Acceptable Here" is the SIP reason phrase verbatim ([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)).
Sentence-casing it would name a response that does not exist. -->
<!-- vale sipnab.Headings = NO -->

## 488 Not Acceptable Here (codec mismatch)

An INVITE comes back `488 Not Acceptable Here`: the callee (or an SBC in the path) found no common codec between the SDP offer and what it supports.

Find every 488 rejection in the capture:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -c 'select(.status_code == 488) | {call_id, status_code, reason}'
```

You should see:

```json
{"call_id":"abc123@host","status_code":488,"reason":"Not Acceptable Here"}
```

Then compare the SDP offer against the answer for one of those calls, substituting its Call-ID for `abc123@host`:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print
```

The call report's **SDP timeline** lists each offer/answer with its codec set. A 488 means there is no overlap: e.g. the offer carries only `G729` while the callee's profile allows only `PCMU, PCMA`. (If the reject comes from an SBC, the offer may never have reached the far end at all.)

**Next steps:** Enable transcoding on the SBC/media server, or add the missing codec to the endpoint/trunk profile so the offer and answer share at least one codec.

---

<!-- vale sipnab.Headings = YES -->

## One-way audio

One direction of RTP has zero packets. The caller can hear the callee (or vice versa) but not both.

The `--one-way` alias finds every call flagged for one-way audio and dumps the matching SIP messages as NDJSON:

```bash
sipnab -N -I capture.pcap --one-way --json
```

You should see one NDJSON record per SIP message of each flagged call (abridged -- real records carry the full field set):

```json
{"is_request":true,"method":"INVITE","call_id":"7f3a9c@192.0.2.5","from":"...","to":"...", "...":"..."}
```

For the same set of calls rendered as the full diagnostic report rather than raw records:

```bash
sipnab -N -I capture.pcap --one-way --report
```

`--one-way` is shorthand for a Filter-DSL condition. Write that condition out when you want to combine it with others:

```bash
sipnab -N -I capture.pcap --filter "one_way == true" --json
```

Get the diagnosis detail (`one_way_audio`, `nat_mismatch`, hints) per call with `--call-report <call-id>`.

### First: check whether the network already answered

Before reasoning about NAT, look at the end of the run. If anything sent an ICMP error about the media itself, the network has already stated the cause and there is nothing to infer:

```text
ICMP: 27 error(s) quoting non-SIP traffic, 27 of them media, across 6 flow(s). Attributed to a stream or SDP endpoint: 27; matched nothing this capture holds: 0.
  ICMP port unreachable: RTP (payload type 0) from 192.0.2.5:42180 to 198.51.100.9:21750 could not be delivered (11 times), reported by 198.51.100.9. This is one of the media streams in this capture (1 call(s) affected). Audio sent that way is discarded before it arrives, which is heard as one-way or missing audio. The host answered, so it is reachable -- nothing was listening on that port. Check the service and the address it binds, not the network.
```

A media ICMP error has no `Call-ID` to file itself under, so sipnab matches the quoted datagram's own 5-tuple against the streams it tracked, then the SSRC inside the quote, then either socket against a tracked stream endpoint, then against an SDP-advertised media address (or the RTCP port one above it, per [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550) Section 11). Each line says which rule matched, because they are not equally strong.

A quote that matches nothing is still counted and still printed -- the endpoint it names is real whether or not this capture holds the stream, and "matched nothing this capture holds" is a prompt to widen the capture, not a reason to hide the evidence.

**What to look for:**

- ICMP errors against the media ports (above) -- a stated cause, not an inference. Read these before anything else in this section.
- `nat_mismatch == true` alongside `one_way` -- RTP reached the capture point from an address no SDP in the dialog advertised, which is what a NAT rewriting the media source looks like. This is the most common cause.
- Codec asymmetry in the SDP offer/answer (one side offers a codec the other doesn't support).
- RTP ports in the SDP that never receive traffic (firewall blocking the return path).

**Next steps:**

1. If the run printed a media ICMP line, act on that first: it names the socket that rejected the audio and the device that reported it. Nothing below can improve on a router's own statement.
2. Check NAT: `sipnab -N -I capture.pcap --filter "one_way == true AND nat_mismatch == true" --json`
3. If NAT is the cause: enable `fix_nated_contact` / `fix_nated_register` on the proxy, or deploy a TURN server.
4. If NAT is clean: verify symmetric RTP, check for SIP ALG on intermediate firewalls (disable it), and confirm both endpoints negotiate a common codec.

---

## Poor call quality

MOS below 3.0 means quality degradation users notice. Below 2.5, calls are unusable.

Find the calls in a capture whose MOS fell below the noticeable-degradation line:

```bash
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0" --json
```

You should see the SIP messages of every matching call as NDJSON (abridged):

```json
{"is_request":true,"method":"INVITE","call_id":"bad-audio@pbx1", "...":"..."}
```

The per-message records identify *which* calls are bad. Pull the per-stream numbers (`jitter_ms`, `loss_pct`, quality intervals) with `--call-report <call-id>`.

To watch a live interface instead, widen the same filter to jitter spikes and let it run -- each matching call prints as it happens. Live capture needs raw-socket access, hence `sudo`:

```bash
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0 OR rtp.jitter > 50" --json
```

**What to look for:**

| Metric | Threshold | Likely cause |
|--------|-----------|--------------|
| `rtp.mos` < 3.0 | Quality degradation | Aggregated impairment -- check jitter and loss |
| `rtp.jitter` > 30ms | Congestion or buffering | Network saturation, Wi-Fi, VPN overhead |
| `rtp.loss` > 2% | Packet drops | Overloaded links, QoS misconfiguration, carrier issue |

**Next steps:** If jitter is high but loss is low, the problem is buffering or path instability (check for Wi-Fi hops, VPN tunnels, or missing QoS marking). If loss is high, first rule out sipnab itself, then run a path MTR/traceroute to find where packets are dropping.

> **Before you chase high loss on the network, check whether *sipnab* dropped the packets.** A capture that lost packets to a full kernel ring buffer reports the missing RTP as network loss — the numbers look identical, and the fix is on the wrong machine. sipnab warns on the first drop and prints a summary at the end of a live capture; if you see that warning, or if loss looks implausibly high across *every* call at once, the figure is measuring your capture rather than the call. [Tuning capture on a busy server](tuning-capture.md) covers how to read the two drop counters, what each one means, and what to change. This applies to live capture only — an offline `-I` read of an existing pcap loses nothing, though the pcap itself may have lost detail in capture by whatever wrote it.

### Deep-dive with stream detail

In the TUI, navigate to a call's flow view and press `Enter` on an RTP bar (or press `r` to jump to the streams list, then `Enter` on a stream) to open the **Stream Detail** view. This shows:

- **MOS and jitter sparklines** -- visual trend graphs across the stream's lifetime, making it easy to spot the exact moment quality degraded.
- **Quality intervals** -- per-interval breakdown of MOS, jitter, and loss so you can correlate degradation with specific time windows.
- **Burst/gap analysis** ([RFC 3611](https://www.rfc-editor.org/rfc/rfc3611)) -- distinguishes between bursty loss (congestion events) and gap loss (steady-state impairment). Bursty loss points to queue overflow; gap loss points to a consistently lossy link.
- **Silence detection** -- identifies periods where no RTP was flowing, which can indicate hold events, codec DTX, or network black holes.

This same data is available in the browser analyzer at [sipnab.com/analyze/](https://sipnab.com/analyze/) under the **Streams** tab.

---

## Slow call setup (post-dial delay)

PDD over 3 seconds is perceptible to users. Over 5 seconds and they'll hang up.

Find the calls whose post-dial delay crossed the 3-second perceptibility line:

```bash
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json
```

The `--slow-setup` alias carries that same threshold. Pair it with `--report` for a summary instead of per-message records:

```bash
sipnab -N -I capture.pcap --slow-setup --report
```

**What to look for:**

- High `retransmits` alongside high PDD -- the caller keeps retransmitting the INVITE because the first one never landed, or the remote side is slow to respond.
- DNS resolution delays (common when the proxy does NAPTR/SRV lookups for every call).
- Deep proxy chains adding latency at each hop.

**Next steps:** Compare `pdd` with `retransmits`. If retransmits > 0, the delay is network loss or an unresponsive next hop. If retransmits == 0 but PDD is still high, the downstream server is slow to route (check its logs, database lookups, or LCR table performance).

---

## NAT traversal issues

The Contact or Via header advertises a private IP that doesn't match the actual packet source.

Find the calls where the address in the SIP headers disagrees with the address the packet came from:

```bash
sipnab -N -I capture.pcap --filter "nat_mismatch == true" --json
```

The `--nat-issues` alias is the same selection without writing the filter out:

```bash
sipnab -N -I capture.pcap --nat-issues
```

**What to look for:** `nat_mismatch == true` means RTP for the call reached the capture point from an address that no SDP in the dialog advertised. The far end therefore sends its media to the address the SDP named, which nothing answers on -- so the return path fails even though signaling completed. sipnab compares addresses only, not ports, because NAT and RTP proxies rewrite the port on healthy calls too.

**Next steps:**

1. **Proxy-side:** Enable `fix_nated_contact` and `fix_nated_register` (OpenSIPS/Kamailio) to rewrite Contact headers with the observed source address.
2. **Endpoint-side:** Configure STUN/TURN on the phone or softclient so it discovers its public address. **Check that it worked** -- see [NAT discovery went unanswered](#nat-discovery-went-unanswered) below. A phone configured with a STUN server it cannot reach behaves exactly like a phone with no STUN at all.
3. **Network-side:** Disable SIP ALG on every NAT device in the path. SIP ALGs almost always make things worse.

### The SDP offered a private address

`private_media_address == true` means the dialog advertised an [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918),
[RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) or link-local address in its `c=` line to a peer that is not itself
private. sipnab raises this as a **warning, not a fault**, because there are
two situations and only one of them fails:

- Something downstream rewrites the SDP -- an SBC, an ALG, or a media proxy --
  and the address the far end finally sees is routable. Correct, common, and
  nothing to do.
- Nothing rewrites it, and the far end sends media to an address the internet
  cannot route. The call still signals cleanly and answers `200`, and the audio
  is one-way.

Without more to go on, sipnab cannot tell those apart from one capture, so it
reports the evidence rather than a verdict. Carrier-grade NAT space ([RFC 6598](https://www.rfc-editor.org/rfc/rfc6598),
`100.64.0.0/10`) is deliberately NOT flagged: it is routable inside the carrier
that assigned it, so flagging it would fire on a large share of working mobile
calls.

**Unless STUN settles it.** When the capture also holds the client's STUN or
TURN exchange, the two situations stop being indistinguishable, and the
`stun_sdp_mismatch` object on the diagnosis carries the proof:

| What STUN shows | What it means |
|---|---|
| A mapped or relayed address in public space, and the SDP named the private one anyway | Nothing rewrote it. The client *knew* its routable address and did not use it. |
| The probe drew no reply, and the STUN server is itself public | The client tried to reach the internet and could not, so it fell back to the private address. |
| The probe drew no reply, but the STUN server is on the LAN | This proves nothing — a LAN-only exchange says nothing about internet reachability, and sipnab stays quiet. |

The first two raise `private_media_address` **on their own**, with no observed
stream needed. That matters for the worst case: a call whose media never
arrived at all has no peer to examine, so the stream-based test could not fire
exactly when the finding was most needed.

The correlation is by the client's IP address, with nothing shared between the
STUN exchange and the dialog. Where the evidence sits well outside the call —
merged captures, or a probe from an earlier registration — the finding says so,
because a persistent NAT-discovery failure is an inference about the client
rather than an observation of this call.

### NAT discovery went unanswered

sipnab reads STUN and TURN, and reports transactions that went out and never
came back:

```
STUN/TURN: 192.0.2.10:5060 sent Binding to 198.51.100.1:3478 2 time(s) and got
no reply. An endpoint that cannot learn its reflexive address falls back to
advertising its PRIVATE address in SDP ...
```

**Why a SIP tool reports this.** It is the first link in the one-way-audio
chain above. The phone asks the network what address the outside world sees it
as, gets nothing, and falls back to the only address it knows -- its private
one -- which it then writes into its SDP. Everything after that looks healthy.

**Read what is MISSING, not just that something is.** A reply that never comes
is a different fault from a reply that says no:

| What you see | What it means |
|---|---|
| No reply at all | Something in the path is discarding the packets. On school, campus and corporate networks that is most often a security appliance -- web filter, secure web gateway, firewall or IPS -- dropping UDP it does not recognize. Check whether one sits in this path and whether it permits UDP to the STUN/TURN port **before** suspecting the server. |
| An error response | The server was reachable and refused. sipnab counts this as ANSWERED, because chasing a blocked path here would waste the effort. Look at the code: `401`/`438` are authentication, not connectivity. |
| A reply arrives, media still one-way | STUN worked. The fault is downstream -- check the SDP the far end actually received, and see the private-address section above. |

A retransmission counts as **one** unanswered question with N attempts, not N
questions: a phone that retries five times has asked once, and nothing answered it
five times.

**A capture holding nothing else is still worth reading.** Two unanswered
Binding Requests and no SIP at all is not an empty capture -- it is the cause
of a one-way-audio complaint, and sipnab says so rather than reporting "no SIP
traffic found".

`sipnab_nat_unanswered_requests` carries the same signal for a dashboard. See
[Prometheus Metrics](prometheus-metrics.md).

`sipnab --stun` prints the whole exchange as a table: one row per transaction,
what came back, and how long it took. `--json-stun` is the same thing as NDJSON.

### A relayed call that went quiet halfway through

A TURN allocation has a lifetime, and the client must Refresh it before that
lifetime runs out. When it does not -- or when its Refresh never reaches the
server -- the relay tears the allocation down and the media stops **mid-call**.

This is the only fault sipnab reports that has no other symptom anywhere. No
SIP message says the audio stopped. The signaling shows a healthy call that
went quiet, and both endpoints are still happily sending into a relay that no
longer exists.

sipnab flags it wherever the run reports anything: on stderr as `TURN: N
allocation(s) were still carrying traffic after the lifetime they were last
granted had run out`, as `LAPSED` in the `--stun` allocations table, as
`lapsed: true` in `--json-stun`, as a `turn_allocation_lapsed` finding in
`--analyze`, and as `sipnab_nat_lapsed_turn_allocations` for a dashboard,
`/v1/stats` and the MCP `capture_status` tool.

Two things it deliberately does **not** claim. It says no Refresh was *seen*,
never that none was *sent* -- a capture that started late or lost a packet
cannot tell those apart. And a Refresh carrying `LIFETIME` 0 is a deliberate
release, which is never reported: the client asked for the teardown.

**And it names the audio that died with the relay.** sipnab unwraps ChannelData
and the RTP inside it reaches the stream list as ordinary media -- but carrying
phone-to-relay addresses, so nothing in the stream list said the relay had
carried it. Every surface now carries the join: the `--stun` allocations section says which
channel carried which SSRC, the lapsed-allocation lines say `media on it:`, the
`--analyze` finding counts `relayed_streams`, `--json-stun` puts a `channels`
array on the allocation, and a relayed call's own diagnosis carries
`media_relay` naming the relay its audio crossed. On a dashboard,
`sipnab_nat_lapsed_turn_allocation_streams` is the scale beside the allocation
count: a relay torn down with nothing on it cost nobody a call.

### Both ICE agents think they are in charge

ICE gives one agent the **controlling** role and the other **controlled**, and
the controlling one picks the candidate pair. When both claim the same role, the
agent that notices answers `487 Role Conflict`
([RFC 8445 §7.3.1.1](https://www.rfc-editor.org/rfc/rfc8445#section-7.3.1.1)),
one side switches role and repeats every check it had already sent.

Often ICE fixes this itself and the call costs a round trip. Where it does not,
nothing is ever nominated and the call has no media path -- with signaling that
looks perfectly healthy. The usual source is two endpoints configured with the
same role, or a B2BUA relaying one side's role attribute straight to the other.

sipnab reports it on stderr as `ICE: N candidate pair(s) show a role conflict`,
as a `ROLE CONFLICT` line in the `--stun` ICE section, as an `ice_role_conflict`
finding in `--analyze`, in the `ice` record of `--json-stun`, and as
`sipnab_nat_ice_role_conflicts` for a dashboard, `/v1/stats` and the MCP
`capture_status` tool. Each report says whether the conflict **resolved** --
the agents nominated a pair between them anyway -- because warning at full weight
about a conflict the agents fixed in one round trip is how a reader learns to
skip the warning that matters.

The same section answers the question ICE otherwise leaves unanswered: which
candidate pair won. `nominated 192.0.2.10:50004 -> 203.0.113.9:16000` is the ICE
analogue of the mapped address -- it names the path the media actually took, and
without it a capture of an exchange that converged and one that never did read
the same. Where **nothing** answered a single check, the ICE section says so
outright: ICE never completed, so the call has no media path. Those individual
transactions also appear in the unanswered list below it, which is where sipnab
reports the silence itself -- one silence, stated once.

---

## SIP scanner detection

Scanners probe for open registrations and try credential stuffing. Detect them early and feed the IPs to fail2ban.

Detect scanners on a live interface and append fail2ban-compatible lines to a log file fail2ban can watch. `--kill-scanner` additionally sends the kill response back to the scanner, so run it only where you mean to:

```bash
sudo sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab/scanners.log
```

After the fact, match the known scanner User-Agents in a capture -- this only reads the file, and sends nothing:

```bash
sipnab -N -I capture.pcap --filter "ua =~ 'friendly-scanner|sipcli|sipvicious'"
```

**What to look for:** known scanner fingerprints (`friendly-scanner`, `sipvicious`, `sipcli`), high REGISTER rates from a single source, sequential extension enumeration (INVITE to 100, 101, 102, and upward).

**Next steps:**

1. Count who the detectors would ban *before* fail2ban sees any of it. On a carrier trunk the enumeration signature and a busy hunt group look alike, and the addresses at the top of this list are routinely your own SBCs:

   ```bash
   sipnab -N -I capture.pcap --kill-scanner --fail2ban \
     | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn
   ```

   Put every address you recognize into the jail's `ignoreip` and raise `maxretry` until the list holds only what you meant. A jail that bans your carrier takes the phone system down more thoroughly than the scanner would have.
2. Then point fail2ban at the log file. `--fail2ban` chooses the **format** and detects nothing on its own: `--kill-scanner` (or `--kill-ua`) produces `scanner_detected` lines, `--reg-flood` produces `reg_flood` lines, and without one of those the log stays empty while looking like an all-clear. sipnab warns on stderr when you ask for the format with no scanner detector armed.
3. For broader detection, combine flags: `sudo sipnab -N -d eth0 --kill-scanner --fraud-detect --reg-flood --alert syslog`
4. Use `--digest-leak` to check if any endpoints are leaking credentials in cleartext.

---

## Registration failures

REGISTER rejected with `401 Unauthorized`, `403 Forbidden`, or `423 Interval Too Brief`? Phones not registering means no inbound calls and potentially no outbound.

```bash
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND state == 'Failed'" --json
```

For one line per registration rather than one per message, read the
`registration_failure` finding. It answers this question directly, and it also
catches the failure that is not a rejection at all -- a registrar that grants
less time than the phone asked for, so the phone re-registers far more often
than it planned:

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet \
  | jq -c 'select(.signaling_diagnosis.registration_failure) |
           {call_id, from} + .signaling_diagnosis.registration_failure'
```

`kind` is `rejected` or `shortened_expiry`. On the second, compare
`requested_expiry_sec` against `granted_expiry_sec`.

> Do **not** reach for `final_status_code` here: it reads INVITE transactions
> only, so on a `REGISTER` dialog it is always `null`, however the registration
> ended. `signaling_diagnosis.final_failure.code` carries the status for any
> dialog.

**What to look for:**

| Code | Meaning | Typical fix |
|------|---------|-------------|
| 401/407 | Auth challenge | Normal first response -- check if the phone retries with credentials. If it doesn't, credentials are misconfigured. |
| 403 | Forbidden | IP not in ACL, registration not allowed for this user, or domain mismatch |
| 423 | Interval too brief | The registrar wants a longer expiry. Increase the registration interval on the phone. |

**Next steps:** A REGISTER that gets 401 followed by a second REGISTER with credentials followed by 200 is healthy. If you see repeated 401s with no successful registration, the password or auth username is wrong. If you see `retransmits > 3` on REGISTERs, the registrar may be unreachable. Three or more challenges with no 200 is exactly what `signaling_diagnosis.auth_loop` reports, and its `kind` separates the two causes: `credential_failure` (the phone answers and is re-challenged -- wrong password) from `silent_drop` (the phone never sends `Authorization` at all -- it has none configured, or does not understand the challenge).

---

## Generating reports

Export call data for tickets, post-mortems, or automated pipelines.

A Markdown report for one call, to attach to a ticket. The redirect overwrites `report.md` in the current directory, and `--no-cli-print` keeps the capture's per-message dump out of it:

```bash
sipnab -N -I capture.pcap --call-report "abc123@host" --markdown --no-cli-print > report.md
```

A JSON export of every failed call, to feed a monitoring system. This one overwrites `failed_calls.json`:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json > failed_calls.json
```

A failure count per response code, written to the terminal rather than a file:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r 'select(.is_request == false) | .status_code' \
  | sort | uniq -c | sort -rn
```

---

## Quick browser analysis

No install, no upload, no data leaves your machine.

Drop a pcap file at [sipnab.com/analyze/](https://sipnab.com/analyze/) -- your browser does all the work via WebAssembly. The analyzer provides two tabs: **Dialogs** (SIP call list with flow diagrams) and **Streams** (full RTP quality data including MOS, jitter, loss, and per-stream detail). Useful for quick triage when you can't install the CLI, or for sharing a link with a colleague who doesn't have sipnab.

---

## Export call audio

When metrics aren't enough — export the actual audio to hear what the caller heard.

In the TUI: select a dialog, press **F2**, Tab to **WAV** format, type a filename, press Enter.

sipnab decodes G.711 audio (mu-law/A-law) from captured RTP streams and writes a standard WAV file. If the dialog has two RTP streams (one per direction), the export produces a **stereo WAV** with caller on the left channel and callee on the right.

- **Supported codecs:** PCMU (PT 0), PCMA (PT 8)
- **Buffer:** Last ~30 seconds of audio per stream (configurable: `[limits] max_audio_frames`)
- **Output:** 16-bit PCM WAV at the stream's sample rate (typically 8000 Hz)

Open the WAV in any audio player or Audacity.

---

## A live capture that sees nothing

`sipnab -d eth0` runs, exits cleanly, and reports **No SIP traffic found** --
but you know the link carries calls, and `tcpdump -i eth0` shows them.

Check what sipnab asked the kernel for. Run with `SIPNAB_LOG=info` and read the
`Auto-generated BPF filter:` line. Then take that exact expression to tcpdump
against the same interface, or against a capture from it:

```
tcpdump -r sample.pcap -nn 'portrange 5060-5061' | wc -l
```

Zero there means the filter never matched, and this is the failure mode with
no other symptom: the **kernel** drops the frames before sipnab sees them, so
no counter, metric, `NOT DECODED` line or report can show them missing. An
empty result reads as "there were no calls".

The usual cause is encapsulation. A port filter matches the outer headers
only, so SIP inside a VLAN tag, QinQ, PPPoE or MPLS never matches one.
Confirm by comparing:

```
tcpdump -r sample.pcap -nn 'portrange 5060-5061'            | wc -l   # 0
tcpdump -r sample.pcap -nn 'pppoes and portrange 5060-5061' | wc -l   # 32
```

**If you passed your own filter (a positional expression or `--bpf-file`),
that is the cause.** sipnab uses your expression exactly as typed and never
edits it. Drop it and let sipnab generate one: the generated filter carries an
arm for VLAN, QinQ, PPPoE, VLAN-over-PPPoE and one or two MPLS labels, and that
arm fires on Ethernet and on both Linux cooked headers alike. Omitting `-d` on
Linux therefore costs no encapsulation coverage. On raw IP from a tun device
and on the two loopback headers the arm compiles away to nothing, which costs
you nothing either: none of those link types carries a tag to begin with.

Two cases the generated filter still does not cover:

- **SIP inside a UDP tunnel** (GTP-U, VXLAN, GENEVE). Off by default, and
  sipnab warns about it at startup. BPF cannot reach the inner port, so the
  only way to cover it is to take the whole port -- add `--capture-tunnels`
  and size the buffer for the extra volume first ([Tuning
  capture](tuning-capture.md)).
- **SIP on a port outside `--portrange`** -- widen it (see [Start
  here](#start-here-one-pass-over-everything)).

One more thing the encapsulated arm cannot reach: an IPv4 header carrying
**options**, because a BPF byte offset has to be a constant and the arm cannot
multiply the IHL nibble into the port offset. The untagged `portrange` handles
those, so the gap needs IPv4 options *and* an encapsulation together.

To confirm which of these you are looking at, run the generated filter and a
plain `portrange` over the same capture and compare the counts. Against the
repository's PPPoE-over-Ethernet sample the plain filter matches 0 of 32 frames
and the generated one matches all 32. Wrap the same SIP in a Linux cooked
header and the numbers hold: 11 encapsulations, 11 matched, on Ethernet,
cooked v1 and cooked v2 alike.

## Still stuck?

Build custom queries with the [Filter DSL](filter-dsl.md) -- 33 fields, regex support, boolean logic. See the [CLI Reference](cli-reference.md) for every flag and more recipes.

If the capture itself is the problem -- drops on a busy link, a full kernel ring buffer, or loss that appears on every call at once -- see [Tuning capture on a busy server](tuning-capture.md).
