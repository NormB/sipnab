+++
title = "Read SIP over TLS on a box you cannot restart"
date = 2026-09-01
description = "No private key, no maintenance window, and the proxy has to keep serving calls. Three methods survive those constraints, they cost different things, and one command tells you which of them your host can actually run."

[extra]
kind = "howto"
+++

The production constraint is always the same. SIP runs on 5061, sipnab shows
you nothing useful, you hold no private key, and nobody is restarting the proxy
at two in the afternoon to set an environment variable. That is not a corner
case — a hardened SIP server frequently does not listen on 5060 at all, so
every call is TLS and a plaintext capture reads nothing.

Start by throwing two methods away, because the constraint already excluded
them.

## Two methods the constraint removes

**Setting `SSLKEYLOGFILE` on the endpoint.** The cheapest method by a wide
margin, and it needs a restart of whatever writes the log. If you can restart a
soft client or a test UA, stop reading and use `--keylog`. If the thing you
care about is the production proxy, you cannot.

**The server's private key.** `--tls-key` opens TLS 1.2 handshakes that used
RSA key exchange, and nothing else. Modern TLS uses forward secrecy, so the
private key opens no captured session at all. Holding the key feels like it
should be enough. It is not, and this is the single most common wasted hour on
this problem.

The methods that survive read the plaintext or the keys out of the running
process, on the host, with root. Three shapes, and one command picks between them.

## Run the list first

```bash
sudo sipnab --uprobe-list
```

This is the question that decides whether the capture is worth starting: is the
process you care about actually mapping a TLS library sipnab can read? The
answer is a table.

```text
FLAVOR        INODE  PIDS  LIBRARY
OpenSSL    146539451     1  /proc/<pid>/root/usr/lib/aarch64-linux-gnu/libssl.so.3
OpenSSL        35057     5  /proc/<pid>/root/usr/lib/aarch64-linux-gnu/libssl.so.3
```

Two rows and two inodes means two DIFFERENT copies of the library, which is
what a containerized daemon beside a host one looks like. The path runs through
`/proc/<pid>/root` for exactly that reason: sipnab names the library through the
observed process's own mount namespace, because that is where the bytes it
probes actually live. Give the same form to `--uprobe-library` when you want to
bypass discovery, including for a library nothing has mapped yet.

An empty table is an answer too. A daemon statically linked against its TLS
stack maps no shared library, and no uprobe on `libssl` reaches it.

sipnab probes every mapped TLS library rather than one, because a host commonly
runs OpenSSL and wolfSSL together. `--uprobe-flavor` narrows that, and
`--uprobe-symbol` overrides the write symbol when a daemon calls something other
than the flavor's default.

## Read the plaintext, or lift the keys

The list gives you two ways forward, and the difference is not convenience.

**Plaintext, straight out of the process:**

```bash
sudo sipnab -N --uprobe-tls --analyze
```

Nothing restarts, no key material touches the disk, and you see the SIP as the
library saw it. What you do not get is a pcap anyone can re-read. The
plaintext exists in this run and ends with it.

**Keys, lifted from the daemon by a helper, then handed to sipnab:**

Run a keylog extractor on the SIP host and point `--keylog` at what it writes.
The daemon stays untouched and the pcap stays readable afterwards, by you and
by Wireshark and by whoever you send it to. That last property is usually worth
more than it looks: a keylog turns a one-shot investigation into evidence.

The extractor picks the TLS library to instrument by looking at whatever it
finds first, which need not be the one your SIP daemon maps. Name the library
explicitly, using the path `--uprobe-list` printed. An empty keylog is almost
always this, and the exact invocation lives on the
[TLS capture page](@/docs/tls-capture.md).

Secrets on disk are a real cost. `--keylog-fd` reads NSS keylog lines from an
already-open file descriptor, so a privileged producer hands over session keys
without writing them anywhere:

```bash
sipnab -N -d eth0 --keylog-fd 3 --portrange 5061-5061
```

sipnab cannot start that producer for you, and the reason is worth knowing
rather than working around. sipnab sets `PR_SET_NO_NEW_PRIVS` at startup and
every child inherits it, so a child can never acquire the `CAP_BPF` an eBPF
extractor needs. Start the extractor from a supervisor and pass the read end in.

## What the tracefs backend cannot tell you

`--uprobe-tls` defaults to `--uprobe-backend tracefs`, which works on any Linux
with tracefs mounted and sees no socket. Its dialogs therefore name a PROCESS
rather than a peer. For "what did this proxy say", that is enough. For "which
of these forty trunks said it", it is not.

The `bpf` backend pairs each write with its `tcp_sendmsg` and recovers the real
5-tuple. It needs two things, and it refuses rather than quietly falling back
when either is missing:

```text
--uprobe-backend bpf needs a sipnab built with the `bpf` feature; this binary
does not carry it
```

Check what you have before you plan around it:

```bash
sipnab --version
```

The feature list comes back on that line. The refusal is deliberate — the
addresses are the only reason to ask for that backend, so silently giving you
the address-free one would answer a question you did not ask. The other
requirement is a kernel with `CONFIG_DEBUG_INFO_BTF`.

## When the keys arrive after the call

A capture that joined an established TLS connection has a problem no version of
TLS solves for it: no record number appears on the wire, so sipnab has to
search for where in the key stream it landed. The AEAD tag makes searching safe,
and `--tls-lockon-window` is the ceiling that search may reach:

```bash
sipnab -N -I capture.pcap --keylog keys.log --tls-lockon-window 8192
```

Raising it costs nothing on a connection captured from its handshake, because
the search widens only as records fail to open. Raise it for a carrier trunk
held open for days. Lower it on a host where key material for other connections
is common and the search wastes effort.

## Choosing, in one paragraph

If the pcap has to outlive the investigation, lift keys and use `--keylog`. If
you need an answer in the next ten minutes and nobody has to re-read it, use
`--uprobe-tls`. If the question is which peer said what, you need the `bpf`
backend, and `sipnab --version` plus your kernel config decide that before you
start rather than after. Run `--uprobe-list` first in all three cases, because
every one of them fails the same way when the daemon maps a library you were
not expecting.
