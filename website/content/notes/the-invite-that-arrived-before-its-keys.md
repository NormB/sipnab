+++
title = "Decrypt SIP over TLS when the keys arrive after the call starts"
date = 2026-08-21
updated = 2026-10-16
description = "Run sipnab so that it holds encrypted SIP records captured before their keys and decrypts them when the keys arrive, read what it reports about them, and recover the rest from a saved capture."

[extra]
kind = "howto"
+++

## In short

To read SIP that TLS encrypts, sipnab needs the session keys. They often come
from a key log that another program writes while the capture runs.

- That program writes a session's keys only after the session setup
  completes.
- So the first encrypted records of a call can reach sipnab before their key.
  - These start with the INVITE that opens the call.
- Without the INVITE, sipnab does not see the call's original audio offer.
  - It can then report a media or NAT problem that is not there.
- sipnab holds such records for a few seconds. It decrypts them when the key
  arrives.
- It reports how many it recovered and how many it could not.

## Who this is for

Operators who decrypt SIP over TLS with a key log that its writer is still
adding to during the capture. Examples:

- eCapture attached to a running SIP server,
- an endpoint started with `SSLKEYLOGFILE`.

## Before you start

- Holding records until their keys arrive needs sipnab 0.5.120 or later, built
  with the `tls` feature. `sipnab --version` lists the features of your build.
- No TLS capture with late keys ships with sipnab. So this page shows the
  commands without output.
  - The messages quoted in the step about held records show `N` where sipnab
    prints a count for the run.
- [Capture SIP over TLS](@/docs/tls-capture.md#which-method-can-you-use)
  covers choosing a key source.

## Steps

### Start the key source before the capture

Start eCapture, or the endpoint that writes `SSLKEYLOGFILE`, first. Start
sipnab after it.

- A key-log writer emits a session's keys only after the TLS handshake
  completes.
- So the first application record is on the network before any key for it
  exists.
- Holding records (the next step) covers a gap of up to 5 seconds per record.
- It does not cover:
  - traffic that passed before the capture started,
  - keys the writer never produced.

A long-lived connection may have started before the capture started.
Restart that connection while capturing. Then the capture holds its handshake
and its first records.

### Run sipnab so that it can hold records until their keys arrive

```bash
sudo sipnab -N -d eth0 --keylog /tmp/keys.log --keylog-watch -O encrypted.pcap
```

- `--keylog-watch` re-reads the key log as it grows.
  - sipnab holds records it cannot open only when more keys can still arrive.
  - That is the case with `--keylog-watch`.
  - It is also the case with `--keylog-fd`. That option reads keys from an
    open file descriptor and implies `--keylog-watch`.
  - A plain `--keylog` reads the file once. Then a record that does not open
    is not held.
- `-O encrypted.pcap` saves the original encrypted packets.
  - The default `--pcap-export-mode` is `raw`.
  - So the last step can read them again.
- `-N` runs without the interactive interface.
  - It prints the end-of-run report that the next step describes.
- The SIP server may use a TLS port outside 5060 to 5061. Then add a
  `--portrange` that covers it.

The hold has fixed limits:

- 4 MiB in total across every session,
- 16 records per direction,
- 4096 directions,
- 5 seconds per record.

A direction is one side of one TCP connection.
[Capture SIP over TLS](@/docs/tls-capture.md#when-the-keys-arrive-after-the-call-starts)
lists the limits.

### Read what the run reports about held records

Held records may open after their key arrives. Then sipnab logs this line
(`N` is the count):

```text
TLS late decrypt: recovered N record(s) that arrived before their keys
```

It is an informational log line. So `--quiet` hides it.

At the end of a run with `-N`, sipnab prints these lines when they apply. The
last one is a warning log line and carries a timestamp:

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
| `discarded N TLS record(s)` | The hold reached one of its limits (size, count, or the 5-second age) before a key matched these records. | Start the key source earlier, then capture again; or read the saved capture as in "Read the saved capture again with the complete key log". |
| `still waiting when the run ended` | No key for these records ever arrived. | Check the key source. eCapture attached to a TLS library the server does not use writes no keys; see [Capture SIP over TLS: Lift keys from a daemon you cannot restart](@/docs/tls-capture.md#lift-keys-from-a-daemon-you-cannot-restart). |
| `opened only after the capture ended` | The keys arrived after the last packet. | Read the saved capture as in "Read the saved capture again with the complete key log". |

A call's INVITE may be missing, and sipnab may report a media or NAT problem
for that call. Then look for these lines first.

### Read the saved capture again with the complete key log

```bash
sipnab -N -I encrypted.pcap --keylog /tmp/keys.log --portrange 1-65535 --report
```

In this read sipnab loads every key before the first packet.

- So no record has to wait for its key.
- sipnab holds nothing.
- `--portrange 1-65535` makes sure that sipnab reads SIP on any port.

### Check the call in the decrypted result

After the run, or after the re-read, check that the call starts with its
INVITE and that its audio offer is present.

- sipnab reassembles a SIP message that spans two TLS records, as it does for
  SIP over plain TCP.
- sipnab skips TLS 1.3 session tickets (`NewSessionTicket` messages). They do
  not take the place of the next SIP message.
- A call still reported with a media or NAT problem after the re-read has
  that problem in the capture. The cause is not a missing INVITE.

## Use a HEP feed and the network together

A SIP server can send copies of its messages to sipnab over HEP while sipnab
also captures the network. sipnab then reports, per call:

- messages both sources saw,
- messages only one of them saw,
- messages present in both with different SDP.

This needs sipnab 0.5.121 or later. See
[cookbook recipe "Take signaling from HEP and media off the wire, in one process"](@/docs/cookbook.md#take-signaling-from-hep-and-media-off-the-wire-in-one-process).

## Terms used here

- **SIP**: the signaling protocol that sets up and ends calls.
- **INVITE**: the SIP request that starts a call. It carries the caller's SDP
  offer.
- **SDP offer**: the part of the INVITE that says where to send the caller's
  audio.
- **NAT**: address translation between a private network and the internet. A
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
- [Capture SIP over TLS: The endpoint writes a key log](@/docs/tls-capture.md#the-endpoint-writes-a-key-log)
- [Capture SIP over TLS: Lift keys from a daemon you cannot restart](@/docs/tls-capture.md#lift-keys-from-a-daemon-you-cannot-restart)
- [Cookbook: 7e. Decrypt traffic from a daemon you cannot restart](@/docs/cookbook.md#decrypt-traffic-from-a-daemon-you-cannot-restart)
- [Cookbook: 7f. Decrypt without writing the keys to disk](@/docs/cookbook.md#decrypt-without-writing-the-keys-to-disk)
- [Troubleshooting: Encrypted SIP that does not decrypt](@/docs/troubleshooting.md#encrypted-sip-that-does-not-decrypt)
- [CLI reference: TLS / decryption](@/docs/cli.md#tls-decryption)
