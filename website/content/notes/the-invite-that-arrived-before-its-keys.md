+++
title = "The INVITE that arrived before its keys"
date = 2026-08-20
description = "A TLS capture that decrypted everything except the one message that mattered, and reported a NAT problem instead. Three bugs, none of them the race everyone assumed."

[extra]
kind = "postmortem"
+++

Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) reported that sipnab
decrypted his OpenSIPS TLS traffic almost perfectly. Every message came through
except the INVITE. Because the INVITE carries the SDP offer, sipnab then
concluded the media endpoints did not match and reported a NAT problem.

That is the worst possible failure shape. Not "decryption failed", which sends
you to the keys, but a confident and specific diagnosis about something else
entirely.

## The obvious cause, real but not sufficient

Keys arrive late. A keylog producer attaches to a daemon that already runs, a
call arrives, and the first records reach sipnab before the first key does. On
a SIP dialog the first record is the INVITE.

So hold records you cannot open, and retry them once a key turns up. Dan
suggested exactly this, and he was right.

The first implementation worked on a synthetic test and failed on his capture,
reporting:

```text
recovered 0 of 3 buffered record(s)
```

Three records held, keys present, none opened.

## Bug one, a rewind that walked through its own lock-on

Both endpoints keep a sequence counter, and TLS 1.3 numbers every record from
it. A capture that joins mid-stream does not know where in that sequence it
sits, so sipnab searches a window of candidate numbers and *locks on* once one
opens. The lock-on keeps a floor that advances on every failed attempt, and the
window widens as attempts fail.

Replaying held records ran straight through that machinery. Each failed retry
advanced the floor. By the time a real key arrived, the floor had walked past
sequence 0, and sequence 0 is where the INVITE lives. The recovery pass
methodically buried the exact record it existed to find.

The fix treats a replay as something other than a discovery. It retries with a
window of one and leaves the floor alone. That went in as a test reproducing
Dan's failure first, which reported `left: None`, and then passing.

## Bug two, a flag that could never fire

A guard on the floor advance depended on `handshake_seen`. Session setup
computed that value, and sessions come into being at startup, before packet
one, so it always held false. The guard could not fire, by construction.

It now takes its value when the handshake actually *arrives*, and clears the
floor at the same moment, because by then the floor may already sit at 16.

This defect class deserves a name. A flag computed at the wrong point in the
lifecycle stays invisible in review, reads correctly, and does nothing. The
tell was a debug counter reporting `observed=0` on a capture that plainly
contained a handshake.

## Bug three, NewSessionTickets in the plaintext

With records recovering, the `100 Trying` went missing.

In TLS 1.3 the outer content type of a protected record always reads 23,
ApplicationData. The *inner* type, which is the last non-zero byte of the
plaintext, is what separates a handshake message from application data. sipnab
never looked, so post-handshake NewSessionTicket messages joined the SIP byte
stream as though they were SIP. The parser then lost framing alignment and
dropped the next message.

Filtering on the inner content type fixed it.
[RFC 8446 §5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2) says this
plainly. The code simply had not asked.

## The framing fix that mattered more than any of them

Underneath all three sat a wrong assumption. TLS delivers a **byte stream**,
not messages. sipnab ran its SIP detector once per decrypted record, so a
message split across two records never registered, and two messages inside one
record produced one.

Decrypted bytes now pass through the same TCP SIP framing the cleartext path
uses. This is the kind of defect that only shows up on real traffic, because
synthetic fixtures tend to put one tidy message in one tidy record.

## The rethink that mattered most

There is a second and better outcome here. The original framing for running a
HEP mirror alongside a live interface was *redundancy*, a fallback for when key
extraction turns fragile. Dan put it differently after using it:

> the whole point is being able to see when [OpenSIPS] is doing something wrong

That inverts the feature. A mirror the proxy produces reports what the proxy
*believes* it did. The wire reports what actually left the box. When the
question is "does the proxy misbehave, or did I configure it to", those are not
two sources of one truth, and asking the suspect twice cannot answer it.

So the **disagreement** became the finding. Per call: messages both saw,
mirror-only, wire-only, and present on both with differing SDP. The trap is
that the mirror usually arrives first, because the proxy mirrors as it
processes while the wire copy takes a network hop. Any "first one wins" rule
therefore makes the proxy authoritative, which is the one thing the wire
capture exists to check. sipnab pairs copies by transaction identity
([RFC 3261 §17.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.3)),
never by arrival order.

## Bounds

Recovery has limits, because a peer whose keys never arrive would grow the hold
forever. 4 MiB total, 16 records per direction, 4096 directions, and five
seconds of age. It closes a gap measured in packets, not one measured in
minutes. Start the key source before the capture wherever you can.

Shipped in 0.5.120. Reported, diagnosed alongside, and materially improved by
Dan Jenkins ([@danjenkins](https://github.com/danjenkins)).
