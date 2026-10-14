+++
title = "Two HEP-over-TCP tests failed on macOS because they assumed Linux timing"
date = 2026-09-05
updated = 2026-10-11
description = "Why two tests for the HEP over TCP feature passed on Linux and failed on macOS before the 0.5.150 release, and how each test now checks the behavior without depending on one operating system's timing."

[extra]
kind = "postmortem"
+++

## In short

Version 0.5.150 added the option to send and receive HEP over TCP and TLS
connections, not only UDP. HEP is a format for copying captured SIP traffic to
a collector.

- During that work, two of its automated tests passed on Linux. They failed on
  the macOS build machine.
- In both, the sipnab behavior was correct.
- The tests assumed that macOS reports a closed connection at the same moment
  Linux does.
- The project corrected both tests before the 0.5.150 release.
  - So the failures affected no released version.

## What happened

sipnab's CI is the automated build-and-test jobs that run on each change. It
runs the test suite on Linux and on macOS (`macos-latest` in
`.github/workflows/ci.yml`). Both tests below are in `src/capture/hep.rs`.

**The allowlist test**
(`a_tcp_peer_outside_the_allowlist_is_refused_before_it_can_speak`).

- A HEP listener can start with `--hep-listen-transport tcp` and
  `--hep-allow`.
  - It must close a TCP connection from an address outside the allowed list
    as soon as it arrives.
- The test connects from outside the list. It sends one packet.
- Then it reads from its own end of the connection. This confirms that the
  listener closed it.
- The test set a read time limit on its connection after sending the packet.
- On macOS that step failed with an error.
  - So the test failed before it reached its check.

**The reconnect test**
(`a_tcp_sender_reconnects_after_the_collector_drops_the_connection`).

- With `--hep-send-transport tcp`, sipnab's sender must open a new connection
  after the collector closes the old one.
- The test closed the collector's side.
- It had the sender send exactly three packets.
- Then it waited for a new connection.
- On macOS no new connection arrived within ten seconds. The test failed.

## Why it happened

Both tests depended on when the operating system reports that the other side
has closed a connection. The code comments and the 0.5.150 changelog record
the difference:

- **Allowlist test.**
  - macOS returns the error `EINVAL` when a program sets a read time limit
    (`setsockopt(SO_RCVTIMEO)`) on a connection the other side has already
    reset.
  - Linux accepts the call.
  - The listener's refusal and the test's packet happen at nearly the same
    moment.
  - So on macOS the connection could already be reset when the test set the
    limit.
- **Reconnect test.**
  - The sender opens a new connection only after a send fails.
  - A send fails only after the operating system has received the
    collector's reset.
  - On Linux that reset arrives before the sender writes the second packet.
    So three packets were enough.
  - On macOS it does not. After the three packets, no new connection arrived
    within ten seconds.

In both cases the number or order in the test matched Linux timing. It did not
match the behavior the test exists to check.

## What changed

Both fixes are in 0.5.150 (2026-09-04).

- **Allowlist test.**
  - The test now sets the read time limit before it sends the packet.
  - At that point the connection is still open on every platform.
  - The test then checks that the connection ended. It accepts either an
    end-of-stream or a connection reset.
- **Reconnect test.**
  - The test no longer sends a fixed number of packets.
  - It keeps sending one packet at a time and checking for a new connection.
    It does this for up to ten seconds.
  - A sender that reconnects passes on any platform.
  - A sender that never reconnects still fails when the ten seconds run out,
    with this message:

  ```text
  the rebuilt connection: the sender offered packets for 10s and never reconnected
  ```

The sender's behavior did not change. The CLI reference states this for
`--hep-send-transport`:

- a send that fails drops the connection;
- the next packet opens a new one;
- there is one reconnect attempt per packet.

## What you can check yourself

- Both tests run on every change on the Linux and macOS CI jobs.
- The behavior they protect appears in the CLI reference rows for
  `--hep-send-transport` and `--hep-allow`, linked below.

## Terms used here

- **HEP**: a format for sending copies of captured SIP packets to a collector
  such as Homer.
- **SIP**: the signaling protocol that sets up and ends phone calls.
- **UDP, TCP, TLS**: ways to send data over a network. UDP sends separate
  packets with no connection. TCP keeps a connection open. TLS is TCP with
  encryption.
- **Collector**: the program that receives HEP packets.
- **Allowlist**: the list of addresses a HEP listener accepts connections from
  (`--hep-allow`).
- **Reset**: the signal a computer sends to end a TCP connection at once.
- **CI**: continuous integration, the automated jobs that build and test
  sipnab on every change.
- **Test**: an automated check that fails when the behavior it describes is
  broken.

## Related guides

- [Network listeners, including `--hep-send-transport` and `--hep-allow`](@/docs/cli.md#network-listeners)
- [What `--hep-send` sends](@/docs/cli.md#what-hep-send-sends)
- [How `--hep-listen` reads the transport](@/docs/cli.md#how-hep-listen-reads-the-transport)
