+++
title = "Send SIP to a HEP collector over TCP and accept only known senders"
date = 2026-09-05
updated = 2026-10-16
description = "Start a sipnab HEP listener on TCP that accepts one sender address, forward a capture to it from a second sipnab, and read the counts on both sides to confirm what arrived."

[extra]
kind = "howto"
+++

## In short

sipnab can forward the SIP it reads to a collector as HEP, and it can act as
that collector. By default both sides use UDP. This page sets up both sides on
TCP:

- the collector accepts connections only from addresses you list with
  `--hep-allow`;
- the sender connects with `--hep-send-transport tcp`;
- each side prints a count when it stops, and the collector's count is the
  one that says what arrived.

Every command runs on one machine against `127.0.0.1`, with a capture from the
sipnab repository.

## Who this is for

Anyone who forwards SIP from one sipnab to another sipnab or to a Homer
collector, and wants TCP instead of UDP, or wants the collector to refuse
unknown senders.

## Before you start

- A sipnab built with the `hep` feature. `sipnab --version` lists the
  features of a build.
- Two terminals on the same machine.
- A free TCP port. This page uses 9060.

## Start a collector that accepts one sender

In the first terminal, start a HEP listener on TCP. It accepts connections
only from `127.0.0.1`:

```bash
sipnab -N -L 127.0.0.1:9060 --hep-listen-transport tcp --hep-allow 127.0.0.1 --no-cli-print
```

It reports that it is ready:

```text
INFO sipnab::capture::hep: HEP allowlist active: 1 CIDR range(s)
INFO sipnab::capture::hep: HEP rate limiting: global 50000/s, per-peer disabled
INFO sipnab::capture::hep: HEP listener started on 127.0.0.1:9060 (tcp)
```

Each log line also starts with a timestamp, left out here.

- sipnab refuses `--hep-listen-transport` and `--hep-allow` without `-L`
  (`--hep-listen`).
- `--hep-allow` is repeatable. Give it once per address or CIDR range.
- Leave the listener running.

## Forward a capture to it

In the second terminal, read a capture and forward its SIP over TCP:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap -H 127.0.0.1:9060 --hep-send-transport tcp --no-cli-print
```

The sender first warns that the capture's signaling leaves the machine. When
it finishes, it reports what it sent. Its whole log, with the timestamps left
out as above:

```text
WARN sipnab::app::bootstrap: --hep-send 127.0.0.1:9060 forwards every SIP message and every RTCP report this run reads to that address, and this run is reading a capture FILE (sip-rtp-g711.pcap). The signaling in those captures leaves this machine: request lines, headers, URIs, and any message bodies they hold. The RTCP carries the media quality summary alongside it — SSRCs, loss, jitter and the endpoints reporting them — but not the audio, which is never forwarded. sipnab forwards what it does send as it was recorded and redacts nothing. Point --hep-send at a collector you control, or drop it to analyze the captures without forwarding them.
INFO sipnab::capture::file: Reading from 'tests/pcap-samples/sip-rtp-g711.pcap'
INFO sipnab::app::batch: HEP sender targeting 127.0.0.1:9060 over tcp (capture id 1)
INFO sipnab::capture::file: File reader finished: 852 packets total, through 'tests/pcap-samples/sip-rtp-g711.pcap'
INFO sipnab::capture::file: Read 852 packets: 1 of 1 file(s) read in full
INFO sipnab::app::batch: HEP export to 127.0.0.1:9060 over tcp: 10 packet(s) sent, none failed, 0 reconnect(s); sent means written to the connection: a write that fails is counted, and the next packet dials again
INFO sipnab::app::batch: sipnab: 852 packets captured, 10 SIP messages, 839 RTP packets across 2 streams
```

sipnab forwards SIP messages and RTCP reports. It never forwards the audio.

## Read what the collector received

Stop the listener in the first terminal with Ctrl+C. It prints its count:

```text
INFO sipnab::capture::hep: HEP listener on 127.0.0.1:9060 finished: 10 packets received
INFO sipnab::app::batch: sipnab: 10 packets captured, 10 SIP messages, 0 RTP packets across 0 streams
```

The ten SIP messages the sender sent are the ten the collector received.

## Confirm that the collector refuses an unlisted sender

Start the listener again with an allowlist that does not include the sender:

```bash
sipnab -N -L 127.0.0.1:9060 --hep-listen-transport tcp --hep-allow 192.0.2.1 --no-cli-print
```

Run the same sender command as before. The sender still reports
`10 packet(s) sent, none failed`, because "sent" means written to the
connection. Stop the listener with Ctrl+C:

```text
INFO sipnab::capture::hep: HEP listener on 127.0.0.1:9060 finished: 0 packets received
INFO sipnab::app::batch: sipnab: 0 packets captured, 0 SIP messages, 0 RTP packets across 0 streams
```

The listener closed the connection and kept nothing. It writes no log line
for a refused connection at the default log level. To confirm that a sender is
reaching a collector, read the collector's count, not the sender's.

## If the collector goes away

With `--hep-send-transport tcp`, a write that fails drops the connection, and
the next packet opens a new one. There is one reconnect attempt per packet.
Each connect attempt gives up after 3 seconds. The sender's closing line
reports the number of failed writes and reconnects.

## Terms used here

- **HEP**: the Homer Encapsulation Protocol, a format for sending copies of
  captured SIP packets to a collector such as Homer.
- **Collector**: the program that receives HEP packets. Here it is a second
  sipnab started with `-L`.
- **SIP**: the signaling protocol that sets up and ends phone calls.
- **RTCP**: the control protocol that carries a call's media quality reports.
- **UDP, TCP**: ways to send data over a network. UDP sends separate packets
  with no connection. TCP keeps a connection open.
- **Allowlist**: the addresses a HEP listener accepts connections from,
  given with `--hep-allow`.
- **CIDR range**: a block of addresses written as an address and a prefix
  length, such as `192.0.2.0/24`.

## Related guides

- [Network listeners, including `--hep-send-transport` and `--hep-allow`](@/docs/cli.md#network-listeners)
- [What `--hep-send` sends](@/docs/cli.md#what-hep-send-sends)
- [How `--hep-listen` reads the transport](@/docs/cli.md#how-hep-listen-reads-the-transport)
