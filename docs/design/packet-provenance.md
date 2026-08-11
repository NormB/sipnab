# Packet-level provenance

Every fact sipnab emits should carry a pointer back to the bytes that produced
it, and that pointer should be resolvable — you can follow it and get the frame.

## The problem

sipnab tells you a call failed because the far end never answered, that a stream
lost 4% of its packets, that a message violates [RFC 3261 §20](https://www.rfc-editor.org/rfc/rfc3261#section-20). Each of those is a
conclusion drawn from specific bytes in a specific capture, and none of them says
which bytes.

That is fine while the person reading the output is the person who ran the tool
on the capture sitting in front of them. It stops being fine the moment the
conclusion travels: into a ticket, into an email to a carrier, into an agent's
context window, into a report someone forwards to a customer. At that point the
conclusion is an assertion with nothing behind it, and the reader's only options
are to trust it or to redo the work.

The failure mode is not that sipnab is wrong. It is that sipnab cannot be
*checked*, which over a long enough horizon is the same thing.

## What already exists

[`Packet::interface`](../../src/capture/packet.rs) names the packet's source: the
capture device for live capture, the capture FILE for replay, the listener
address for HEP. It is an `Arc<str>` interned once per source, so stamping it on
every packet costs a refcount bump rather than an allocation.

That landed with the pcapng interface fix, where frames from the second input
file claimed to have come from the first. It is half of a pointer: it says which
haystack, never which needle.

## What is missing

Three things, in order of dependency.

**An ordinal.** Nothing counts frames. The file reader yields packets and
forgets how many it has yielded. Without an ordinal there is no way to name one
frame among the 235,769 in a capture.

**A path from fact to frame.** [`SipMessage`](../../src/sip/message.rs) carries
`raw`, `timestamp`, and the five-tuple, but nothing about where it was read
from. Dialogs are built from messages, findings from dialogs, reports from
findings — so a pointer absent at the message level is absent everywhere
downstream, and adding it at the top would be a fabrication.

**A resolver.** A pointer nobody can follow is decoration. Something has to
accept `capture.pcap#4212` and return those bytes.

## The honesty requirement

This is the part that decides the design.

A pointer that resolves to the *wrong* frame is worse than no pointer, in
exactly the way the pcapng interface bug was worse than writing no interface at
all: it manufactures confidence. If someone follows `capture.pcap#4212` and gets
a frame, they will believe it is the frame the finding was about. They have no
way to tell that the file was rotated, truncated, or recompressed since the run.

So the pointer must carry enough to detect that it no longer resolves. The
cheapest anchor that actually works is a hash of the frame's own bytes, computed
when the frame is read and checked when the pointer is followed:

- Frame present and hash matches → resolved, and say so.
- Frame present and hash differs → **refuse**, and say the capture changed.
- Frame absent (file gone, too short) → refuse, and say which.

Never return bytes that might not be the right bytes. A resolver that guesses is
the pcapng bug again, one layer up.

## Shape

```
FrameRef {
    source:  Arc<str>,   // already on every Packet
    ordinal: u64,        // 0-based, within that source
    digest:  u64,        // hash of the frame bytes as read
}
```

Sixteen bytes plus a refcount bump per packet, and the `Arc<str>` is shared with
`Packet::interface` rather than duplicated. A 14M-packet replay pays 14M
refcount increments and 224 MB it would otherwise not spend, which is the real
cost and the reason retention has to stay opt-in for the message-level copy.

`ordinal` is per source, not per run. A frame is identified by the file it lives
in and its position in that file, so the same frame gets the same `FrameRef`
whether it was read alone, as part of a directory, or as the second of a glob.
A run-global counter would give the same bytes different names depending on how
the run was invoked, which makes the pointer useless for comparing two runs —
and comparing two runs is the whole of `compare_captures`.

## What this unblocks

The reason this is first rather than fifth:

- **`compare_captures`** cannot be built at all without stable identity for a
  frame across two runs. This provides it.
- **The linter** can cite the frame a violation lives in, not only the message,
  which is the difference between "your proxy sends a malformed Contact" and
  "frame 4212 of the capture you sent me, here it is".
- **Redaction** gains a way to state what it redacted without revealing it: the
  pointer survives redaction while the bytes do not.
- **`generate_repro`** can name the frames a repro must contain.
- **Evidence packages** can carry the pointers and the frames together, so the
  caveat travels inside the artifact.

Each of those gets better once provenance exists, and none of them can
retrofit it.

## Staging

1. `FrameRef` and the ordinal, plumbed from the file reader to `Packet`. No
   consumer yet. Provable on its own: the *n*th packet of a file reports
   ordinal *n*.
2. The resolver, with all three outcomes tested — match, changed, absent.
   Independently useful: `sipnab --show-frame capture.pcap#4212`.
3. `SipMessage` carries its `FrameRef`. Behind retention, so a run that does
   not need it does not pay for it.
4. Surfaces emit it: `--json-dialogs`, the report, REST, MCP.
5. Live capture and HEP, where "source" is a device or a listener and the
   ordinal is per session. The pointer is honest about being unresolvable
   after the fact — a live frame has no file to go back to, and the resolver
   must say that rather than pretend.

Stage 5 matters more than its position suggests. Most of sipnab's users run it
on files, but the ones running it live are the ones who will most want to follow
a pointer, and telling them plainly that a live pointer cannot be followed is
better than letting them discover it when it counts.
