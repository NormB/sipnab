+++
title = "A finding is a floor, not a verdict"
date = 2026-09-01
description = "The same problem query answered 0 and then 127 on one capture, thirty seconds apart. Four questions to ask of any finding before you act on it, and the fields that answer each one."

[extra]
kind = "howto"
+++

`find_problems` hands back a list. An agent reads the list, writes a
conclusion, and the conclusion is only as good as four things the list does not
say out loud. Every one of them has a field, and every one of them has a
failure mode where the honest answer and the alarming answer look identical.

## Question 1 — was that the whole answer?

Here are two responses to the same `find_problems` call, on the same capture,
from the same binary. Nothing changed except how long the server had been
reading:

```jsonc
// asked immediately after the handshake
{ "returned": 0, "total_matched": 0, "source_exhausted": false,
  "capture_identity": { "dialog_generation": 37 } }
```

```jsonc
// asked again once the file had been read to its end
{ "returned": 2, "total_matched": 127, "truncated": true,
  "source_exhausted": true,
  "capture_identity": { "dialog_generation": 9015 } }
```

Zero problems became 127. An agent that asked once and reported "no problems
found" would have been wrong about a capture holding 127 of them, and nothing
in the first response says "wrong" — it says `source_exhausted: false`, which
means the same thing and takes a reader who knows to look.

Three fields carry this, and they answer different questions:

- **`source_exhausted`** — has sipnab read the source to its end? Until this
  goes true, every count is a floor. On a live interface it never goes true, by
  design.
- **`total_matched`** — how many matched across the WHOLE store, whatever
  `limit` and `cursor` say. This is the number that answers "how many". Counting
  the returned array answers a different question.
- **`truncated`** — matches remain after this page. Note what it does in the
  first response above: it is not `false`, it is ABSENT. sipnab omits the field
  rather than claiming completeness it cannot support, so a client reading a
  missing key as `false` invents the reassurance.

`capture_identity.dialog_generation` moved from 37 to 9015 between those two
answers, which is the same fact in a different currency. And a changed
`instance` voids every cursor you hold, so a paging client that ignores it pages
through a capture that no longer exists.

## Question 2 — what did the run decline to read?

A finding counts what sipnab understood. Anything it threw away first makes
every count below it a floor, and `--analyze` puts that at the top of its list
under its own severity:

```text
1. [BLIND] SIP discarded by --portrange — 10 message(s)
   sipnab recognized these as SIP and then threw them away because neither port
   was inside --portrange. They are in no dialog and no count.
```

`BLIND` sits above `CRITICAL` on purpose. Over MCP the same facts arrive on
`capture_status` as `unanalysed_sip_messages`, `unanalysed_busiest_ports` and
the `capture_quality` block, which carries `kernel_dropped_packets`,
`undecodable_frames` and `snapped_frames` beside the NAT and relay counters.

Read those before the findings, not after. A capture where
`unanalysed_sip_messages` reads 10 and `dialog_count` reads 0 is not a quiet
network.

## Question 3 — was anything watching?

An empty list has three readings and only one of them is "clean". sipnab keeps
them apart with a flag rather than leaving you to guess:

```jsonc
// security_findings {}
{ "detection_armed": false, "armed_kinds": [], "findings": [], "total_matched": 0,
  "note": "No detection rule is armed on this server, so no finding could have been recorded. An empty findings list here means nothing was watching, NOT that the traffic was clean. Arm a detector with --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and re-run the capture." }
```

`describe_endpoint` carries the same distinction one level further in.
`findings.selectable: false` means nobody COULD ask — the alert engine files
every finding against a source address, so a query keyed on a SIP user has no
key to select with. An empty `armed_kinds` means nothing was watching. Only on a
server with a detector armed does an empty list mean the endpoint stayed clean.

The same instinct guards the arithmetic. `failure_rate_pct` comes back `null`
rather than `0.0` when nothing reached a final status, because a zero there
hands a clean bill of health to an endpoint nobody measured.
`registration.applicable: false` does the same job for REGISTER.

## Question 4 — is this a fault, or a thing to rule out?

Severity in sipnab describes how much the finding constrains the answer, not
how upset to be. Two examples where the text tells you to stand down:

```text
[MINOR] Call failed 4xx
Many 4xx codes are ordinary call outcomes — 486 Busy Here, 404 for a
misdialled number, 480 for a phone that is off — so this is listed to be ruled
out rather than acted on. The codes are named below; a run of 403 or 408 is not
an ordinary outcome.
```

```text
[MAJOR] RTP source no SDP advertised
Frequently benign on its own (symmetric RTP through a NAT looks exactly like
this); read it together with any one-way audio on the same call.
```

Both of those are true findings about real packets, and acting on either alone
wastes a morning. The second one is the sharper lesson: a NAT-mismatch finding
means something rewrote the media source, which is what a NAT is FOR. It earns
attention only when a one-way finding names the same call.

Meanwhile a `[CRITICAL] One-way audio` on a session whose SDP negotiated
`a=recvonly` describes the packets perfectly and describes no fault at all.
[Ruling that out is its own note.](@/notes/rule-out-the-relay-before-the-nat.md)

## Then go and check the packet

Every finding names evidence a reader can go back to. A dialog summary carries
a `frame` pointer, and that pointer is checkable:

```bash
sipnab -N -I capture.pcap --show-frame 'capture.pcap#0@db88659b94678546'
```

With the digest attached, sipnab verifies the bytes and prints `VERIFIED`
before the hex. Against a file that has rotated, truncated or changed since you
made the pointer, it refuses:

```text
refusing: capture.pcap frame 0 is not the frame this pointer was made against.
The capture was rotated, truncated or rewritten since then. Showing you what is
there now would look like an answer and be the wrong one.
```

A pointer typed by hand, without the digest, still prints the frame and marks
it `UNVERIFIED`, because nothing exists to check it against. That word is the
whole difference between quoting evidence and quoting whatever now sits at that
offset.

## The short version

Before acting on any finding: check `source_exhausted`, check the blind
findings and `unanalysed_sip_messages`, check that you armed a detector, and
read the finding's own text for the sentence telling you it is a thing to rule
out. Then pull the frame and look at it.
