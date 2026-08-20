# Capture SIP over TLS

You have SIP on port 5061, sipnab shows you nothing useful, and you want to
see the signaling. This page picks the method for you.

**For many production deployments this is not an advanced topic — it is the
only topic.** A hardened SIP server often does not listen on 5060 at all, so
every call is TLS and a capture that reads only plaintext reads nothing. If
that is your situation, start at the table below rather than with the
plaintext quick-start elsewhere in these docs.

**The short version.** The wire alone never yields encrypted traffic —
modern TLS uses forward secrecy, so even the server's private key does not
open a captured session. Something on a machine you control has to hand over
the session keys, or hand over the plaintext. Every method below is one of
those two, and they differ only in what access each demands.

## Which method can you use?

Read down the first column and stop at the first row you can satisfy.

| If you can… | Use | Needs | Gets you |
|---|---|---|---|
| Set `SSLKEYLOGFILE` on the endpoint (a soft client, test UA, or a daemon you can restart) | [`--keylog`](#1-the-endpoint-writes-a-key-log) | Nothing special | Full decryption, live or from a pcap |
| Get root on the SIP host, but **not** restart the daemon | [`--uprobe-tls`](#3-no-keys-at-all-read-the-plaintext-in-the-process) | Linux, root | Plaintext, no peer addresses |
| Get root **and** the kernel has BTF | [`--uprobe-tls --uprobe-backend bpf`](#4-plaintext-and-the-peer-address) | Linux, root, BTF, a `bpf` build | Plaintext **with** the real 5‑tuple |
| Run a helper on the SIP host but prefer keys to plaintext | [eCapture → `--keylog`](#5-lift-keys-from-a-daemon-you-cannot-restart) | Linux, root | Full decryption, daemon untouched |
| Only reach an old TLS 1.2 server using RSA key exchange | [`--tls-key`](#6-the-old-rsa-case) | The server's private key | Decryption, **non-PFS handshakes only** |
| None of the above | — | — | Nothing. See [what does not work](#what-does-not-work-and-why) |

**Most people want row 1 or row 3.** Row 1 if you are testing and control an
endpoint. Row 3 if you are on a production box and cannot restart anything —
that is the case sipnab exists for, and the one people assume is impossible.

---

## 1. The endpoint writes a key log

The ordinary case, and the cheapest. Any TLS library built on OpenSSL, NSS or
GnuTLS writes session keys to the file named by `SSLKEYLOGFILE`.

```sh
# Run all of these, in order.
export SSLKEYLOGFILE=/tmp/sip-keys.log
# start your softphone or daemon from this shell, then:
sudo sipnab -d eth0 --keylog /tmp/sip-keys.log --keylog-watch
```

`--keylog-watch` re-reads the file as it grows, so keys minted after sipnab
starts still decrypt. Without it you get only the sessions whose keys were
already written.

Same flag reads a capture you already recorded:

```sh
sipnab -I tls-capture.pcap --keylog /tmp/sip-keys.log
```

The full recipes, including exporting a decrypted pcap for Wireshark and
keeping keys off disk entirely, are cookbook
[§7a–7f](examples.md#7-decrypt-siptls-via-sslkeylogfile).

## 2. Check what you have before going further

```sh
sudo sipnab --uprobe-list
```

Installs nothing. It prints the TLS libraries running on this host and which
processes use them — which tells you whether rows 3 and 4 are even available
before you spend time on them.

## 3. No keys at all: read the plaintext in the process

This is the method the [sngrep feature request](https://github.com/irontec/sngrep/issues/447)
asks for — TLS visibility with no recompile and no certificate — and it is
what sipnab does here.

```sh
sudo sipnab -N --uprobe-tls
```

sipnab attaches a uprobe to the TLS library's write function and reads the
bytes **before** the library encrypts them. It recovers no key, decrypts
nothing, and touches no other machine.

Dialogs carry **no addresses and port 0**, labelled `uprobe:<process>/<pid>`.
A uprobe sees the bytes an application handed its TLS library and nothing
about the socket underneath, so sipnab names the process rather than inventing
a peer. If you need the addresses, use method 4.

**If it attaches and reports zero messages**, the symbol is almost certainly
wrong — OpenSSL 3 applications increasingly call `SSL_write_ex` rather than
`SSL_write`:

```sh
# Run all of these, in order.
nm -D --undefined-only /usr/sbin/opensips | grep -i ssl_write
sudo sipnab -N --uprobe-tls --uprobe-symbol SSL_write_ex
```

Read [the security implications](uprobe-walkthrough.md) before using this on a
production host. It reads process memory, so anyone who can run it can read
every SIP session on that machine, credentials included.

## 4. Plaintext **and** the peer address

```sh
sudo sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535
```

Adds a kernel probe on `tcp_sendmsg` and pairs it with the write by thread, so
dialogs carry the real 5-tuple. Needs a kernel with `CONFIG_DEBUG_INFO_BTF=y`
and a sipnab built with `--features bpf`. sipnab **refuses** rather than
falling back in silence, because a silent downgrade would leave you with no
peers and no reason given.

Widen `--portrange`. The port a uprobe reports is whatever the socket used,
which is usually ephemeral rather than 5061.

## 5. Lift keys from a daemon you cannot restart

If you would rather have keys than plaintext — keys decrypt a pcap you keep,
and plaintext does not — [eCapture](https://github.com/gojue/ecapture) reads
them out of a running process and sipnab consumes them unchanged:

```sh
# Run all of these, in order.
# eCapture picks the TLS library to instrument by looking at curl. Your SIP
# daemon may well map a different one, so name the daemon's explicitly — this
# is the single most common reason a keylog stays empty.
LIBSSL=$(sudo awk '/libssl/ {print $6; exit}' /proc/"$(pgrep -o opensips)"/maps)
sudo ecapture tls -m keylog --libssl="$LIBSSL" --keylogfile=/tmp/keys.log &
sudo sipnab -d eth0 --keylog /tmp/keys.log --keylog-watch
```

The uprobe attaches to the library, not to one process, so a forking daemon
needs no `--pid` — it covers every worker that maps that path, and `--pid`
would restrict you to one of them. Check the path it chose in eCapture's own
startup line (`openssl_path=`) before trusting the run.

**Start the capture before the connections you want to read.** This is the
single biggest trap on long-lived trunks, and it bites differently in each TLS
version:

- **TLS 1.3** numbers each record with a counter both endpoints keep privately.
  Nothing on the wire carries it, so sipnab searches for it — about a million
  records, roughly a day of a trunk ticking over at ten records a second. The
  search costs one AEAD tag check per candidate and runs once per direction per
  session, so it is a one-off of about a second, not a per-record cost. Past
  that, the keys are right and the records still do not open.
- **TLS 1.2** is worse: a `CLIENT_RANDOM` line gives the master secret, and the
  server random and cipher suite that expand it into record keys are in the
  ServerHello. Miss the handshake and there is no way to use the secret at all,
  now or later.

sipnab says which of these happened, with counts. The fix is at capture time
either way: bounce the connection, or the far end, while capturing, so the
capture catches the stream from its handshake and its first record.

Cookbook [§7e](examples.md#7-decrypt-siptls-via-sslkeylogfile) has the full
sequence, and [§7f](examples.md#7-decrypt-siptls-via-sslkeylogfile) shows
feeding keys through a pipe so they never reach disk.

## 6. The old RSA case

```sh
sipnab -I capture.pcap --tls-key server.key
```

Works **only** for TLS 1.2 handshakes that used RSA key exchange. Any
ECDHE/DHE handshake — which is every modern configuration, and mandatory in
TLS 1.3 — has forward secrecy, and the private key does not decrypt a recorded
session. If this produces nothing, your traffic is almost certainly PFS and
you need method 1, 3, 4 or 5.

## Media as well as signaling

SRTP keys arrive two ways, and sipnab reads both:

- **SDES** — keys travel in the SDP, so decrypting the signaling decrypts the
  media with it. Nothing extra to do.
- **DTLS-SRTP** — a DTLS handshake carries the keys, so supply the keylog
  the same way, cookbook [§7d](examples.md#7-decrypt-siptls-via-sslkeylogfile).

## What does not work, and why

Stated plainly, because time spent here is time people lose:

- **A packet capture alone.** No amount of sipnab flags decrypts a pcap with
  no keys. If the handshake had forward secrecy, the information required is
  not in the capture and never was.
- **The server's private key, on modern TLS.** See method 6.
- **A mirror port or tap, by itself.** It gives you the same ciphertext as a
  local capture. You still need keys or plaintext from an endpoint.
- **Any of methods 3–5 against a machine you do not control.** They read
  process memory on the host they run on. That is the whole boundary.
- **Attaching to a long-lived connection and expecting the back catalogue.**
  Keys extracted from a running process decrypt records captured from that
  point on, provided the capture catches the stream early enough. They never
  recover traffic that went past before you started.

## Still stuck?

| Symptom | Likely cause |
|---|---|
| `--uprobe-list` prints nothing | Not root — it can only read your own processes. Re-run with `sudo` |
| Attaches, reports 0 messages | Wrong symbol — try `--uprobe-symbol SSL_write_ex` (see method 3) |
| `needs this kernel's BTF` | No `CONFIG_DEBUG_INFO_BTF`; use `--uprobe-backend tracefs` |
| `no kernel programs` | Binary lacks the `bpf` feature; use `tracefs`, or rebuild |
| Keylog present, still encrypted | Keys minted after start — add `--keylog-watch` |
| Keylog stays empty | eCapture attached to a TLS library the daemon never calls — pass `--libssl` with the path from `/proc/<daemon-pid>/maps` |
| Keys load, sessions listed, nothing decrypts | The capture joined TLS 1.3 connections already running, past the record numbers sipnab searches. Restart the connection while capturing |
| Keys load, no sessions listed | TLS 1.2 without the handshake — the ServerHello never got captured, and the master secret alone cannot make record keys. Restart the connection while capturing |
| TLS 1.2, right keys, still nothing | A CBC suite. sipnab refuses to emit record plaintext it cannot MAC-verify, so a forged capture cannot inject "decrypted" SIP. Configure an AES-GCM suite |
| Addresses show `0.0.0.0:0` | Expected on the tracefs backend; use method 4 for peers |

More in [Troubleshooting](troubleshooting.md) and the
[uprobe walkthrough](uprobe-walkthrough.md).
