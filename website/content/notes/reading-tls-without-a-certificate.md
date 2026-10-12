+++
title = "Decrypting SIP over TLS from session key logs"
date = 2026-09-01
updated = 2026-10-11
description = "How sipnab decrypts encrypted SIP signaling from TLS session keys, where those keys can come from, and which traffic it cannot decrypt."

[extra]
kind = "feature"
+++

## In short

Many phone systems encrypt their call signaling with TLS, so a recording of
the network traffic shows only scrambled bytes. The server's certificate and
private key are not enough to unscramble a recording made with current TLS
settings. sipnab decrypts the traffic when it has the per-connection
session keys, which a program on the machine that runs the connection can
write out. This note explains where those keys come from, how sipnab reads
them, and what it cannot decrypt.

## Who this is for

Engineers who need to read SIP over TLS (port 5061 by default) and can get
session keys from an endpoint or from the SIP server's host. If you cannot get
keys but have root on the SIP host, the how-to
[Read SIP over TLS on a server you cannot restart, using eBPF uprobes](@/notes/read-tls-without-a-key-or-a-restart.md)
reads the unencrypted text from the process instead.

## What it does

TLS (Transport Layer Security) encrypts each connection with session keys that
the two endpoints agree on during the handshake, the exchange that opens the
connection. With forward secrecy, which every ECDHE or DHE key exchange
provides and TLS 1.3 requires, the endpoints never send those keys, and nothing
can derive them from the server's private key. sipnab therefore needs the session keys
themselves, written in the NSS key log format (the `SSLKEYLOGFILE` format, one
line per secret).

sipnab reads that key material from four kinds of input:

| Input | Option | Notes |
|---|---|---|
| A key log file | `--keylog <FILE>` | Read once at startup. Add `--keylog-watch` to keep reading lines appended later. |
| A named pipe (FIFO) | `--keylog <PATH>` | Read as a live stream. |
| An open file descriptor | `--keylog-fd <N>` | For a privileged program that hands keys over a pipe, so they never reach disk. Implies `--keylog-watch`. |
| A pcapng file with an embedded Decryption Secrets Block | none | sipnab reads the keys from the capture file itself. |

A run cannot combine `--keylog` and `--keylog-fd`. A run given both exits with
code 2 and the message `--keylog and --keylog-fd name different sources of the
same secrets; pass one, not both`.

The keys can come from two places:

- **An endpoint started with `SSLKEYLOGFILE` set.** The endpoint (a software
  phone, a test client or a server) writes its keys to that file. This needs a restart
  of the endpoint.
- **A key extractor on the SIP server's host.** eCapture, an open-source tool
  that uses eBPF (a Linux kernel facility for attaching small programs to
  running code), reads the keys out of a running process with no restart.
  sipnab cannot start eCapture itself: sipnab sets `PR_SET_NO_NEW_PRIVS` at
  startup, every program it starts inherits that setting, and so a child of
  sipnab can never gain the `CAP_BPF` privilege eBPF needs. Start eCapture from
  a shell or a service manager and pass its output to sipnab.

The same decryption applies to a live capture (`-d <interface>`) and to a
recorded file (`-I <file>`).

## How to turn it on

Decryption is part of the `tls` build feature. The `full` feature set includes
it. The default build (`native`, `tui`, `audio`, `metrics`) does not. Check
what your binary carries:

```bash
sipnab --version
```

```text
sipnab 0.5.211 (15e5e7bd) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,archive
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

`tls` must appear in the feature list.

## Example runs

No TLS capture with matching keys ships in the repository, and eCapture needs
root and eBPF, so these runs were not repeated for this note. The commands come
from the guides. This note shows output only where a guide records it.

1. Decrypt a recorded capture with a key log file written by an endpoint
   (from the TLS capture guide, method 1; no output recorded there):

```bash
sipnab -I tls-capture.pcap --keylog /tmp/sip-keys.log
```

2. Pass keys from eCapture to a live capture through a pipe, so they are never
   written to disk (cookbook recipe 7f; no output recorded there). Name the
   TLS library the SIP daemon uses with eCapture's `--libssl` option, because
   eCapture otherwise chooses the library `curl` uses, which can differ.
   Replace the path below with the one your daemon maps; the TLS capture
   guide, method 5, shows how to read it from `/proc/<pid>/maps`, and
   `sipnab --uprobe-list` prints it after a `/proc/<pid>/root` prefix:

```bash
sudo sh -c 'ecapture tls -m keylog --libssl=/usr/lib/x86_64-linux-gnu/libssl.so.3 --keylogfile=/dev/stdout | sipnab -N -d eth0 --keylog-fd 0'
```

3. Read a pcapng file that eCapture wrote with its `-m pcap` mode, which embeds
   the keys in the file. This read needs no key option:

```bash
sipnab -N -I sip-tls.pcapng --portrange 1-65535 --report
```

   Cookbook recipe 7i records this run (2026-09-09, eCapture v2.5.2, a TLS 1.3
   session using `TLS_AES_256_GCM_SHA384`). Its first output line was:

```text
TLS decryption active: 6 secret(s) from embedded DSB in sip-tls.pcapng
```

   and the report listed one completed dialog, `tls-split-invite-1@127.0.0.1`,
   with 7 messages. The line format matches `src/app/batch.rs` line 3338.

## Starting a capture on a connection that is already open

A capture that starts after the handshake has two problems, one per TLS
version:

- **TLS 1.3** numbers each record with a counter that is not sent on the wire.
  sipnab searches for the counter, up to `--tls-lockon-window` records into the
  connection. The default is 1,048,576 records (`TLS_SEQ_LOCKON_WINDOW` in
  `src/capture/mod.rs`), which is about 29 hours of a connection carrying ten
  records a second. Past that point the keys are correct and the records still
  do not decrypt. The search grows only while records fail to decrypt, so a
  larger window costs nothing on a connection captured from its handshake.
  This command from the CLI reference raises the window to 8,388,608 records,
  about 9.7 days at ten records a second:

```bash
sudo sipnab -N -d eth0 --keylog /run/sip.keys --keylog-watch --tls-lockon-window 8388608
```

- **TLS 1.2** keys (`CLIENT_RANDOM` lines in the key log) become record keys
  only with values sent in the handshake. If the capture missed the
  handshake, sipnab cannot decrypt those sessions.

In both cases the fix is to restart the connection, or the far end, while the
capture is running.

## When a key arrives after the traffic

When eCapture attaches to a server that is already running, the first
encrypted records of a new call can reach sipnab before their key does. The
first record of a new SIP call is the INVITE (the request that starts the
call), so without it sipnab would see a call with no offer and report it as a
media or NAT problem.

sipnab holds records it cannot decrypt yet and retries them when a key for
that session arrives. This needs no option. A run that recovered records logs
a line such as this one, recorded in the TLS capture guide and matching
`src/capture/decrypt.rs` line 1574:

```text
TLS late decrypt: recovered 3 record(s) that arrived before their keys
```

The hold has limits of 4 MiB in total, 16 records per direction, 4096
directions and 5 seconds per record. At the end of the run, sipnab reports the
records it discarded at those limits, with their count and the limits
(`src/app/batch.rs` line 2042). sipnab reports records whose keys never arrived
separately, as records "still waiting when the run ended"
(`src/app/batch.rs` line 2054). Start the key source before the capture wherever possible.

## Limits

- **sipnab cannot decrypt a capture without keys.** With forward secrecy the
  information needed is not in the capture.
- **The server's private key decrypts only TLS 1.2 RSA key exchange.**
  `--tls-key` works for those handshakes and no others.
- **A mirror port or network tap gives the same encrypted bytes** as a local
  capture. Keys are still needed.
- **Traffic sent before the capture started is not in the capture**, and keys
  obtained later do not recover it.
- **Key extraction works only on a machine you control.** eCapture reads
  process memory on the host it runs on. Anyone who can run it can read every
  SIP session on that host, credentials included. Treat key logs as secrets.
- **sipnab decrypts only AES-GCM cipher suites.** sipnab recognizes CBC suites and
  refuses to output their plaintext, because it does not verify the CBC record
  MAC (message authentication code) and so could not detect forged records.
  ChaCha20-Poly1305 suites are not supported (`src/capture/decrypt.rs`).

## Terms used here

- **SIP**: the protocol that sets up, changes and ends phone calls over IP.
- **TLS**: the protocol that encrypts a network connection.
- **Session key**: the per-connection secret that encrypts the traffic.
- **Private key**: the server's long-term secret that matches its
  certificate.
- **Handshake**: the messages that open a TLS connection and agree its keys.
- **Forward secrecy**: a property of a key exchange (ECDHE, DHE) under which
  the server's long-term private key cannot decrypt recorded sessions.
- **Record**: one encrypted unit of TLS data.
- **Key log (`SSLKEYLOGFILE` format)**: a text file with one session secret
  per line, defined by the NSS library and read by Wireshark and sipnab.
- **FIFO / named pipe**: a file-system entry that passes data from one program
  to another without storing it.
- **File descriptor**: a number a program uses to refer to an open file or
  pipe.
- **pcap / pcapng**: file formats for recorded network traffic; pcapng can also
  hold decryption secrets.
- **eBPF**: a Linux kernel facility that runs small programs attached to
  running code.
- **eCapture**: an open-source eBPF tool that extracts TLS keys or plaintext
  from running programs.
- **Dialog**: one SIP conversation, such as one call.
- **NAT**: network address translation, which rewrites addresses between
  private and public networks.
- **Cipher suite**: the set of algorithms a TLS connection uses; AES-GCM, CBC
  and ChaCha20-Poly1305 are families of them.

## Related guides

- [Capture SIP over TLS: which method can you use?](@/docs/tls-capture.md#which-method-can-you-use)
- [Method 1: the endpoint writes a key log](@/docs/tls-capture.md#1-the-endpoint-writes-a-key-log)
- [Method 5: lift keys from a daemon you cannot restart](@/docs/tls-capture.md#5-lift-keys-from-a-daemon-you-cannot-restart)
- [When the keys arrive after the call starts](@/docs/tls-capture.md#when-the-keys-arrive-after-the-call-starts)
- [What does not work, and why](@/docs/tls-capture.md#what-does-not-work-and-why)
- [Read TLS without keys (eBPF)](@/docs/uprobe-walkthrough.md)
- Cookbook [7e](@/docs/cookbook.md#7e-decrypt-traffic-from-a-daemon-you-cannot-restart),
  [7f](@/docs/cookbook.md#7f-decrypt-without-writing-the-keys-to-disk) and
  [7i](@/docs/cookbook.md#7i-one-file-taken-off-the-host-that-decrypts-itself)
- [CLI reference: TLS / decryption](@/docs/cli.md#tls-decryption)
