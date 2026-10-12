+++
title = "Decrypt SIP over TLS when the keys arrive after the call starts"
date = 2026-08-21
updated = 2026-10-11
description = "Run sipnab so that it holds encrypted SIP records captured before their keys and decrypts them when the keys arrive, read what it reports about them, and recover the rest from a saved capture."

[extra]
kind = "howto"
+++

## In short

To read SIP that TLS encrypts, sipnab needs the session keys, often
from a key log that another program writes while the capture runs. That
program writes a session's keys only after the session setup completes, so the
first encrypted records of a call, starting with the INVITE that opens it,
can reach sipnab before their key. Without the INVITE, sipnab does not see the
call's original audio offer and can report a media or NAT problem that is not
there. sipnab holds such records for a few seconds and decrypts them when the
key arrives, and it reports how many it recovered and how many it could not.

## Who this is for

Operators who decrypt SIP over TLS with a key log that its writer is still
adding to during the capture: eCapture attached to a running SIP server, or an endpoint
started with `SSLKEYLOGFILE`.

## Before you start

No TLS capture with late keys ships in the sipnab repository, so this page
shows the commands without output. The messages quoted in step 3 come
from the sipnab source. The number in each is a count that depends on the
run.
[Capture SIP over TLS](@/docs/tls-capture.md#which-method-can-you-use)
covers choosing a key source.

## Steps

### 1. Start the key source before the capture

Start eCapture, or the endpoint that writes `SSLKEYLOGFILE`, first, and start
sipnab after it. A key-log writer emits a session's keys only after the TLS
handshake completes, so the first application record is on the network before
any key for it exists. sipnab's 0.5.120 release notes record a gap of 56 ms
measured in the field. Holding records (step 2) covers a gap of that size. It
does not cover traffic that passed before the capture started, or keys the
writer never produced.

For a long-lived connection set up before the capture started,
restart that connection while capturing, so that the capture holds its
handshake and its first records.

### 2. Run sipnab so that it can hold records until their keys arrive

```bash
sudo sipnab -N -d eth0 --keylog /tmp/keys.log --keylog-watch -O encrypted.pcap
```

- `--keylog-watch` re-reads the key log as it grows. sipnab holds records it
  cannot open only when more keys can still arrive: with `--keylog-watch`, or
  with `--keylog-fd`, which reads keys from an open file descriptor and implies
  `--keylog-watch`. A plain `--keylog` reads the file once, and then a record
  that does not open is not held.
- `-O encrypted.pcap` saves the original encrypted packets (the default
  `--pcap-export-mode` is `raw`), so that step 4 can read them again.
- `-N` runs without the interactive interface and prints the end-of-run
  report that step 3 describes.
- If the SIP server uses a TLS port outside 5060 to 5061, add a
  `--portrange` that covers it.

The hold has fixed limits: 4 MiB in total across every session, 16 records
per direction, 4096 directions, and 5 seconds per record. A direction is one
side of one TCP connection.
[Capture SIP over TLS](@/docs/tls-capture.md#when-the-keys-arrive-after-the-call-starts)
lists the limits.

### 3. Read what the run reports about held records

When held records open after their key arrives, sipnab logs this line (`N` is
the count):

```text
TLS late decrypt: recovered N record(s) that arrived before their keys
```

It is an informational log line, so `--quiet` hides it. At the end of a run
with `-N`, sipnab prints these lines when they apply. The last one is a
warning log line and carries a timestamp:

```text
sipnab discarded N TLS record(s) held from before a key arrived: the late-decrypt hold is bounded (4 MiB total, 16 record(s) per direction, 5s), and it filled before any key matched them. Start the key source before the capture, or expect the first message of a call to be missing.
```

```text
N TLS record(s) were still waiting when the run ended: no key ever arrived for them. Nothing was discarded and starting the capture earlier would not have helped -- the key source never produced those secrets.
```

```text
TLS late decrypt: N record(s) opened only after the capture ended -- their keys arrived too late to place the messages in this run. Re-read the saved capture with the same keylog to see them.
```

What each one means:

| Line | Meaning | What to do |
|---|---|---|
| `recovered N record(s)` | sipnab decrypted records held before their key and placed them in the run. | Nothing. |
| `discarded N TLS record(s)` | The hold reached one of its limits (size, count, or the 5-second age) before a key matched these records. | Start the key source earlier, then capture again; or read the saved capture as in step 4. |
| `still waiting when the run ended` | No key for these records ever arrived. | Check the key source. eCapture attached to a TLS library the server does not use writes no keys; see [Capture SIP over TLS, method 5](@/docs/tls-capture.md#5-lift-keys-from-a-daemon-you-cannot-restart). |
| `opened only after the capture ended` | The keys arrived after the last packet. | Read the saved capture as in step 4. |

If a call's INVITE is missing and sipnab reports a media or NAT problem for
that call, look for these lines first.

### 4. Read the saved capture again with the complete key log

```bash
sipnab -N -I encrypted.pcap --keylog /tmp/keys.log --portrange 1-65535 --report
```

In this read sipnab loads every key before the first packet, so no record has
to wait for its key and sipnab holds nothing. `--portrange 1-65535` makes sure
that sipnab reads SIP on any port.

## What changed in sipnab 0.5.120 and 0.5.121

Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) reported that
sipnab decrypted his SIP over TLS traffic except for the INVITE, and then
reported a NAT problem on a trunk that did not have one. The 0.5.120 release
(2026-08-21) fixed three causes:

- **Records that arrived before their keys**: sipnab dropped them. It now
  holds and retries them as described above. A retry tries the record sequence number
  sipnab already has and never advances its search for the number; that rule
  is Dan Jenkins's. Without it, failed retries moved the search past sequence
  0, where the INVITE is. sipnab computed a related flag, which marks a
  session's handshake as seen, when it created the session. With a complete
  key log, sipnab creates sessions before it reads the first packet, so the
  flag was always false. sipnab now sets it when the handshake arrives.
- **A SIP message split across two TLS records** lost everything after the
  first record. Decrypted bytes now go through the same stream framing as
  SIP over plain TCP.
- **TLS 1.3 session tickets** (`NewSessionTicket` messages): sipnab passed them
  to the SIP parser, which cost the next message. sipnab now checks each record's
  inner content type ([RFC 8446 section 5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2)).

The release notes record the result on the reproduction capture Dan Jenkins
supplied:

- Before: 0 of 17 application-data records decrypted in 32.9 seconds.
- After: all 8 messages of the call, the INVITE with its SDP offer, in 0.55
  seconds.

The 0.5.121 release (2026-08-21) added a report for a run that takes SIP from
a HEP mirror and from the network at the same time: per call, messages both
sources saw, messages only one of them saw, and messages present in both with
different SDP. Dan Jenkins proposed, after using the two sources together,
that the two sources count as complementary rather than as copies of each other. See
[cookbook recipe 6d](@/docs/cookbook.md#6d-take-signaling-from-hep-and-media-off-the-wire-in-one-process).

## Terms used here

- **SIP**: the signaling protocol that sets up and ends calls.
- **INVITE**: the SIP request that starts a call; it carries the caller's SDP
  offer.
- **SDP offer**: the part of the INVITE that says where to send the caller's
  audio.
- **NAT**: address translation between a private network and the internet; a
  mismatch between signaled and actual media addresses can indicate it.
- **TLS**: the encryption protocol that protects SIP on port 5061.
- **Record**: one encrypted unit of TLS data on a connection.
- **Key log**: a text file of TLS session secrets in the `SSLKEYLOGFILE`
  format, written by a TLS library or by eCapture.
- **eCapture**: a third-party tool that reads TLS keys out of a running
  process.
- **Handshake**: the start of a TLS connection, where the two sides agree on
  keys.
- **HEP**: a protocol that SIP servers use to send copies of their messages to
  a collector.
- **pcap**: the standard packet capture file format.
- **MiB**: mebibyte, 1,048,576 bytes.

## Related guides

- [Capture SIP over TLS: When the keys arrive after the call starts](@/docs/tls-capture.md#when-the-keys-arrive-after-the-call-starts)
- [Capture SIP over TLS: 1. The endpoint writes a key log](@/docs/tls-capture.md#1-the-endpoint-writes-a-key-log)
- [Capture SIP over TLS: 5. Lift keys from a daemon you cannot restart](@/docs/tls-capture.md#5-lift-keys-from-a-daemon-you-cannot-restart)
- [Cookbook: 7e. Decrypt traffic from a daemon you cannot restart](@/docs/cookbook.md#7e-decrypt-traffic-from-a-daemon-you-cannot-restart)
- [Cookbook: 7f. Decrypt without writing the keys to disk](@/docs/cookbook.md#7f-decrypt-without-writing-the-keys-to-disk)
- [Troubleshooting: Encrypted SIP that does not decrypt](@/docs/troubleshooting.md#encrypted-sip-that-does-not-decrypt)
- [CLI reference: TLS / decryption](@/docs/cli.md#tls-decryption)
