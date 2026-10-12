+++
title = "Read SIP over TLS on a server you cannot restart, using eBPF uprobes"
date = 2026-09-01
updated = 2026-10-11
description = "Steps to read the unencrypted SIP inside a running TLS server process with sipnab's uprobe capture, with no key, no certificate and no restart, and what each backend can and cannot show."

[extra]
kind = "howto"
+++

## In short

When a phone system encrypts its call signaling with TLS, a network recording
shows only scrambled bytes. If you have administrator (root) access to the
server but cannot restart it or obtain its keys, sipnab can read the signaling
inside the running server program, just before the program encrypts it. This
how-to walks through checking that the server is readable, running the
capture, and getting the network addresses of the other side when you need
them.

## Who this is for

Engineers with root on a Linux host running a SIP server over TLS who cannot
restart it. If you can restart an endpoint with `SSLKEYLOGFILE` set, or you
want keys that decrypt a recording later, read
[Decrypting SIP over TLS from session key logs](@/notes/reading-tls-without-a-certificate.md)
instead.

## What this method does and does not do

A uprobe is a Linux kernel hook on a function in a program or shared library.
`--uprobe-tls` places one on the TLS library's write function (`SSL_write` for
OpenSSL, `wolfSSL_write` for wolfSSL) and reads the bytes the server hands to
that function, before the library encrypts them. It recovers no key and decrypts no
recording. The plaintext exists only in the sipnab run that read it. To keep a
recording that others can decrypt later, use the key log method in the note
linked above.

It reads process memory, so anyone who can run it can read every SIP session
on that host, credentials included. Read the security section of the uprobe
walkthrough before using it on a production host.

## Steps

The commands below need root and a TLS server, which were not available for
this note. Their output comes from the guides where they record it, with
the source named. This note invents nothing below.

1. Confirm that the host is Linux with tracefs (the kernel's tracing file
   system) mounted:

```bash
ls -d /sys/kernel/tracing
```

```text
/sys/kernel/tracing
```

   If the directory is missing, the uprobe walkthrough shows how to mount it.

2. List the TLS libraries sipnab would probe. This installs nothing:

```bash
sudo sipnab --uprobe-list
```

   The uprobe walkthrough records this output from one host:

```text
FLAVOR        INODE  PIDS  LIBRARY
OpenSSL        21143    12  /proc/954/root/usr/lib/x86_64-linux-gnu/libssl.so.3
wolfSSL     17433084     1  /proc/982702/root/usr/lib/libwolfssl.so.42.2.0
```

   Each row is one library file, the number of processes (PIDS) that map it,
   and its path as seen through one of those processes (`/proc/<pid>/root`),
   which also works for a server running in a container. Two rows with the
   same path and different inodes are two different copies of the library. If
   your SIP server's library is not listed, the capture cannot read it: for
   example, a server statically linked with its TLS library maps no `libssl`
   file. `--uprobe-library <PATH>` names a library directly instead.

   When sipnab finds nothing, it prints this (recorded in the uprobe
   walkthrough and in `src/app/bootstrap.rs`) and exits with code 1:

```text
No TLS library is mapped by any process sipnab can see.
Either nothing here uses OpenSSL or wolfSSL, or sipnab cannot read
/proc/<pid>/maps — try again as root.
```

   A run without root sees only its own processes, so run this as root before
   concluding the host uses no TLS.

3. Start the capture with the default `tracefs` backend:

```bash
sudo sipnab -N --uprobe-tls
```

   The uprobe walkthrough records this line from such a run:

```text
12:57:47.360 0.0.0.0:0 -> 0.0.0.0:0 REGISTER TCP origin=uprobe
```

   This backend sees no network connection, so messages carry no addresses
   (`0.0.0.0:0`), dialogs carry the label `uprobe:<process>/<pid>`, and
   `origin=uprobe` marks the line as uprobe input. sipnab probes every TLS
   library it found. `--uprobe-flavor openssl` or `--uprobe-flavor wolfssl`
   narrows that.

4. If the capture attaches but reports no messages, the server may call a
   different write function. Some OpenSSL 3 programs call `SSL_write_ex`
   instead of `SSL_write`. Step 4 of the uprobe walkthrough's tracefs section
   shows how to list the write functions the server binary imports. Then probe
   the function it names (the guides record no output for this command):

```bash
sudo sipnab -N --uprobe-tls --uprobe-symbol SSL_write_ex
```

5. To get the other side's address and port, use the `bpf` backend. It pairs
   each write with the kernel's `tcp_sendmsg` call on the same thread and
   recovers the connection's addresses. It needs three things: a sipnab built
   with the `bpf` feature, a build that also produced the kernel programs (this
   needs `bpf-linker` and a nightly Rust toolchain on the build host), and a kernel with BTF
   (`CONFIG_DEBUG_INFO_BTF`), which provides `/sys/kernel/btf/vmlinux`. Check
   the build first:

```bash
sipnab --version
```

   On the binary used for this note, the output was:

```text
sipnab 0.5.211 (15e5e7bd) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,archive
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

   `bpf` is not in that list, so this binary refuses the backend. Running
   `sipnab -N --uprobe-tls --uprobe-backend bpf` with it logged this error and
   exited with code 1 (message text from `src/capture/native.rs` line 47):

```text
--uprobe-backend bpf needs a sipnab built with the `bpf` feature; this binary does not carry it
```

   A binary that lists `bpf` but came from a build without `bpf-linker` refuses with
   the "no kernel programs" message quoted in the uprobe walkthrough. sipnab
   never falls back to `tracefs` on its own. With all three in place, widen
   `--portrange`, because the ports a uprobe reports are the connection's
   actual ports, often not 5061:

```bash
sudo sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535
```

   The uprobe walkthrough records this output:

```text
200 OK     127.0.0.1:15061 -> 127.0.0.1:36160  TCP  uprobe:python3/349147#0
REGISTER   127.0.0.1:36160 -> 127.0.0.1:15061  TCP  uprobe:python3/349147#1
```

   A write the library buffered instead of sending at once does not pair with
   a send, and sipnab reports that message with no addresses rather than
   guessing one.

6. After the capture, confirm that sipnab removed its probes (the tracefs
   backend only — the kernel frees the programs of the `bpf` backend on exit). The
   walkthrough states that this prints nothing:

```bash
sudo grep sipnab_ /sys/kernel/tracing/uprobe_events
```

## Choosing between this and a key log

| You need | Use |
|---|---|
| The SIP text now, with no keys and no restart | `--uprobe-tls` (steps 1 to 4) |
| The same, plus the other side's address and port | `--uprobe-tls --uprobe-backend bpf` (step 5) |
| A recording that you or others can decrypt later | Keys from the endpoint or from eCapture, read with `--keylog` or `--keylog-fd`; see [Decrypting SIP over TLS from session key logs](@/notes/reading-tls-without-a-certificate.md) |

The server's private key (`--tls-key`) decrypts only TLS 1.2 sessions that
used RSA key exchange. Sessions using ECDHE, DHE or TLS 1.3 have forward
secrecy, and the private key does not decrypt them.

## Terms used here

- **SIP**: the protocol that sets up, changes and ends phone calls over IP.
- **TLS**: the protocol that encrypts a network connection.
- **Plaintext**: the unencrypted content.
- **Root**: the Linux administrator account.
- **uprobe**: a Linux kernel hook placed on a function in a user program or
  library.
- **tracefs**: the kernel file system, under `/sys/kernel/tracing`, through
  which programs manage tracing hooks.
- **eBPF / `bpf` backend**: a Linux facility that runs small verified programs
  in the kernel; sipnab's `bpf` backend uses it to read the connection
  addresses.
- **BTF**: BPF Type Format, the kernel's description of its own data
  structures, at `/sys/kernel/btf/vmlinux`.
- **Inode**: the file system's number for one file; two paths with the same
  inode are the same file.
- **Shared library / statically linked**: code loaded from a separate file at
  run time, versus code built into the program itself.
- **Dialog**: one SIP conversation, such as one call.
- **Forward secrecy**: a key-exchange property under which the server's
  private key cannot decrypt recorded sessions.
- **eCapture**: an open-source eBPF tool that extracts TLS keys from running
  programs.

## Related guides

- [Read TLS without keys (eBPF): can your system run this at all?](@/docs/uprobe-walkthrough.md#can-your-system-run-this-at-all)
- [The quickest answer to all three](@/docs/uprobe-walkthrough.md#the-quickest-answer-to-all-three)
- [Security implications, stated plainly](@/docs/uprobe-walkthrough.md#security-implications-stated-plainly)
- [Walkthrough: the tracefs backend](@/docs/uprobe-walkthrough.md#walkthrough-the-tracefs-backend)
- [Walkthrough: the eBPF backend](@/docs/uprobe-walkthrough.md#walkthrough-the-ebpf-backend)
- [Cleaning up](@/docs/uprobe-walkthrough.md#cleaning-up)
- [Capture SIP over TLS: which method can you use?](@/docs/tls-capture.md#which-method-can-you-use)
- [Method 3: no keys at all](@/docs/tls-capture.md#3-no-keys-at-all-read-the-plaintext-in-the-process)
  and [method 4: plaintext and the peer address](@/docs/tls-capture.md#4-plaintext-and-the-peer-address)
- Cookbook [7g](@/docs/cookbook.md#7g-read-tls-with-no-keys-at-all) and
  [7h](@/docs/cookbook.md#7h-read-tls-and-who-the-peer-was)
- [CLI reference: TLS / decryption](@/docs/cli.md#tls-decryption)
