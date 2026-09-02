+++
title = "Reading SIP over TLS without a certificate"
date = 2026-09-01
description = "The wire never yields encrypted SIP on its own. sipnab takes session keys from wherever you can get them — a key log, a pipe, an eCapture probe on a daemon you cannot restart — and states plainly what none of that recovers."

[extra]
kind = "feature"
+++

A hardened SIP server often does not listen on 5060 at all. Every call is TLS,
and a capture that reads only plaintext reads nothing. For those deployments
this is not an advanced topic — it is the only topic.

The wire alone never yields it. Modern TLS uses forward secrecy, so even the
server's private key does not open a captured session. Something on a machine
you control has to hand over the session keys or hand over the plaintext, and
this capability is about the first of those. It lives behind the `tls` Cargo
feature, which `full` carries and the default build does not.

## The key log, and three ways to feed it

`--keylog` reads the NSS `SSLKEYLOGFILE` format that every TLS library built on
OpenSSL, NSS or GnuTLS writes. It works the same against a live device and
against a pcap you already recorded:

```bash
sipnab -I tls-capture.pcap --keylog /tmp/sip-keys.log
```

`--keylog-watch` re-reads the file as it grows, so keys minted after sipnab
starts still decrypt. Without it you get only the sessions whose keys were
already on disk when the run began.

Keys are credential material, so the flag takes more than a path. `--keylog`
accepts a **FIFO** and reads it as a live stream. `--keylog-fd` takes an
already-open descriptor and implies `--keylog-watch`, which lets a privileged
producer hand secrets over a pipe that never touches disk:

```bash
sudo sh -c 'ecapture tls -m keylog --keylogfile=/dev/stdout | sipnab -N -d eth0 --keylog-fd 0'
```

That line is the whole feature in one place: an eBPF extractor lifts session
secrets out of a running SIP daemon's OpenSSL and pipes them straight in. **No
certificate, no private key, and no restart of the daemon.**

sipnab cannot start that extractor itself, and the reason is structural rather
than a missing convenience. sipnab sets `PR_SET_NO_NEW_PRIVS` at startup and
every child inherits it, so a child can never acquire the `CAP_BPF` an eBPF
extractor needs. Start it from a supervisor, or from a shell as above, and hand
sipnab the read end.

One trap accounts for most empty key logs: eCapture picks the TLS library to
instrument by looking at `curl`. A SIP daemon commonly maps a different one, so
name the daemon's own path with `--libssl` and check the path eCapture chose in
its startup line before trusting the run. [The TLS capture
page](@/docs/tls-capture.md) has the full sequence, including reading the path
out of `/proc`.

## Start the key source before the connections

This is the biggest trap on a long-lived trunk, and it bites differently per
TLS version.

**TLS 1.3** numbers each record with a counter both endpoints keep privately.
Nothing on the wire carries it, so sipnab searches for it — around a million
records, roughly a day of a trunk ticking over at ten records a second. The
search costs one AEAD tag check per candidate and runs once per direction per
session, so it is a one-off of about a second rather than a per-record cost.
Past that ceiling, the keys are right and the records still do not open.
`--tls-lockon-window` raises it.

**TLS 1.2** is worse. A `CLIENT_RANDOM` line gives the master secret, and the
server random and cipher suite that expand it into record keys live in the
ServerHello. Miss the handshake and the secret is unusable, now or later.

sipnab says which of these happened, with counts. The fix is at capture time
either way: bounce the connection, or the far end, while capturing.

## The race it does close

Attach a key source to a daemon that is already running, and a call can arrive
before the first key does. On a SIP session the first record is the INVITE, so
the symptom is not "a few records are unreadable" — it is a call with no offer
in it, which sipnab then reports as a media mismatch or a NAT problem, because
from the dialog's point of view that is exactly what it looks like.

sipnab holds application data it cannot open yet and retries it as soon as a
key for that session turns up. No flag switches this on. A run that recovered
records says so:

```text
TLS late decrypt: recovered 3 record(s) that arrived before their keys
```

The hold has bounds — 4 MiB in total, 16 records per direction, 4096
directions, 5 seconds — because a peer whose keys never arrive would otherwise
grow it without end. A run that hit a bound says that too, in different words,
because "we never had the keys for those records" and "we had them and had
already discarded the ciphertext" are different problems with different fixes.
Recovery closes a gap measured in packets, not one measured in minutes.

## What this cannot do

Stated here rather than discovered later.

- **A packet capture alone.** No flag decrypts a pcap with no keys. If the
  handshake had forward secrecy, the information required is not in the capture
  and never was.
- **The server's private key, on modern TLS.** `--tls-key` works only for TLS
  1.2 handshakes that used RSA key exchange. Every ECDHE/DHE configuration —
  which is every modern one, and mandatory in TLS 1.3 — has forward secrecy,
  and the private key does not decrypt a recorded session.
- **A mirror port or tap by itself.** It gives you the same ciphertext as a
  local capture.
- **The back catalog.** Keys extracted from a running process decrypt records
  captured from that point on. Traffic that went past before the capture
  started is not in the capture, and nothing recovers it.
- **A machine you do not control.** The key sources here read process memory on
  the host they run on. That is the whole boundary, and anyone who can run them
  can read every SIP session on that machine, credentials included.
- **CBC cipher suites.** sipnab refuses to emit record plaintext it cannot
  MAC-verify, so a forged capture cannot inject "decrypted" SIP. Configure an
  AES-GCM suite.

If you cannot get keys at all, the other half of the story is reading the
plaintext instead: `--uprobe-tls` attaches to the TLS library's write function
and reads the bytes before the library encrypts them, recovering no key and
decrypting nothing. Run `sudo sipnab --uprobe-list` first — it installs nothing
and prints which TLS libraries this host runs.
