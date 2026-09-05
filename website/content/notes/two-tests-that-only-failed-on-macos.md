+++
title = "Two tests that only failed on macOS, and the thing they had in common"
date = 2026-09-05
description = "Both encoded when a kernel reports a peer's disconnect as if it were the behavior under test. Both passed on Linux, and on the one platform the author could not run, both were wrong."

[extra]
kind = "postmortem"
+++

Adding HEP over TCP and TLS produced two test failures on the macOS runner and
nowhere else. They looked unrelated. They were the same mistake.

## The first

A test arranges for a listener to refuse a connection, then reads the peer
socket to prove the connection ended. It asked for a read timeout after writing
to the socket:

```rust
let _ = peer.write_all(&packet);
peer.set_read_timeout(Some(Duration::from_millis(750)))?;
```

macOS returns `EINVAL` from `setsockopt(SO_RCVTIMEO)` once the peer has reset
the connection — and a refusal racing that write is precisely what the test
sets up, so by the time the call ran the socket was often already in an error
state. Linux tolerates it. The fix is ordering: ask for the timeout while the
socket is plainly healthy, before the write.

## The second

A test drops a collector and then checks the sender rebuilds its connection. It
sent three packets and then accepted:

```rust
for body in [b"second", b"third", b"fourth"] {
    let _ = sender.send_payload(body);
}
let mut second = accept_within(&collector, "the rebuilt connection");
```

The sender rebuilds when a write fails. A write fails once the peer's RST is
back. How many writes that takes is the kernel's business — on Linux the RST
beats the second packet, and on macOS it does not. Nobody chose three. It was the
number that happened to work here.

## What they share

Both tests asserted a claim about sipnab and encoded a claim about a kernel.
The claim about sipnab was right: the connection ends, the sender reconnects.
The claim about timing was one platform's, written by someone who could only
run that platform.

The second test now offers packets until the sender reconnects and lets a
deadline be the failure. It says what it means — that the sender rebuilds when
the collector comes back — instead of that it rebuilds on a particular packet.
A sender that never rebuilds still fails, which is the property worth keeping.

## The shape to watch for

Any test whose fixture depends on *when* a kernel reports a peer's disconnect
is testing the kernel. Loss, reset, close and timeout are all in that family.
The fix is nearly always the same: replace the fixed count with a loop and a
deadline, and let the deadline carry the failure message.
